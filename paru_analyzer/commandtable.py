"""The command table (docs/COMMANDS.md): what each command does, as data.

An entry says what a command reads, writes, deletes, executes, fetches, uploads or changes on the system,
depending on its arguments, in a fixed vocabulary (no code in the table). Whether an effect is a concern is a
policy decision made elsewhere; the table only states the facts. Every entry carries examples (`ex:`) that are
run as tests, and options the entry does not list (`covers:`) are reported as an unknown effect rather than
ignored, so an incomplete table fails towards "not understood".

    python -m paru_analyzer.commandtable --check        # validate the table and run every example
    python -m paru_analyzer.commandtable --show sed     # print what the table says about one command
"""
from __future__ import annotations

import re
import shlex
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, NamedTuple

EFFECTS = ("read", "write", "delete", "perm", "exec", "fetch", "upload", "system", "spawn")
CONTEXTS = ("build", "hook")
FIELDS = ("covers", "valued", "subs", "like", "where", "single-dash-long", "mode-first", "bundled-first", "effects", "ex", "note")
REMOTE_OPERAND = re.compile(r"^(?:rsync|ssh)://|^(?:[\w.-]+@)?[\w.-]+:(?!//)")
URL = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|git@)")
MODE = re.compile(r"^-[rwxXstugo]+$")
BUNDLED = re.compile(r"^[A-Za-z]+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
TARGET = re.compile(
    r"^@(?P<kind>none|args|opt|url|script|cmd|stdin|tree|deps|system|find-paths|find-exec)"
    r"(?:\((?P<opts>[^)]*)\)|\[(?P<slice>-?\d*(?::-?\d*)?)\])?$")
LITERAL = re.compile(r"^[a-z][a-z0-9-]*$")
EXECUTABLE_TARGETS = frozenset({"script", "cmd", "stdin", "tree", "args", "opt", "find-exec", "none"})
FILE_TARGETS = frozenset({"args", "opt", "tree", "stdin", "none", "find-paths"})
READ_TARGETS = FILE_TARGETS | {"system"}          # @system: system state outside the build tree, only for read
NETWORK_TARGETS = frozenset({"url", "deps", "args", "opt", "none"})


class TableError(ValueError):
    pass


class Effect(NamedTuple):
    kind: str          # one of EFFECTS, or "unknown"
    target: str = ""

    def __str__(self) -> str:
        return f"{self.kind} {self.target}".strip()


# ---- what the table is made of ----

def _describe_target(t: "Target") -> str:
    if t.kind == "literal":
        return t.word
    if t.kind == "opt":
        return "@opt(" + "|".join(t.opts) + ")"
    if t.kind == "args" and (t.index or t.start is not None or t.stop is not None):
        if t.index:
            return f"@args[{t.start}]"
        return f"@args[{'' if t.start is None else t.start}:{'' if t.stop is None else t.stop}]"
    return "@" + t.kind


def _describe_condition(c: "Condition") -> str:
    bang = "!" if c.negated else ""
    if c.kind == "predicate":
        return f"[{bang}?{c.names[0]}]"
    if c.kind == "sub":
        return f"[{bang}sub:{'|'.join(c.names)}]"
    return f"[{bang}{'|'.join(c.names)}]"


@dataclass(frozen=True)
class Target:
    kind: str                    # none args opt url script cmd stdin tree deps system find-paths find-exec, or "literal"
    opts: tuple = ()             # for @opt(...)
    start: int | None = None     # for @args[a:b] / @args[n]
    stop: int | None = None
    index: bool = False
    word: str = ""               # for a literal target (system=users)


@dataclass(frozen=True)
class Condition:
    kind: str                    # flag, predicate, sub
    names: tuple
    negated: bool = False


@dataclass(frozen=True)
class EffectRule:
    kind: str
    target: Target
    conditions: tuple = ()
    line: int = 0


@dataclass
class Entry:
    names: tuple
    line: int
    template: bool = False
    like: str = ""
    covers: tuple | None = None          # None: not stated, ("*",): every option is understood
    valued: set = field(default_factory=set)
    subs: tuple | None = None
    where: tuple | None = None
    single_dash_long: bool = False
    mode_first: bool = False       # the first word may be a mode that starts with "-" (chmod -x f)
    bundled_first: bool = False    # old-style letters without a dash (tar xf a, ar rcs lib.a)
    pure: bool = False
    rules: list = field(default_factory=list)
    examples: list = field(default_factory=list)   # (line, command line, expected)
    note: str = ""

    @property
    def name(self) -> str:
        return self.names[0]


class Parsed(NamedTuple):
    flags: set
    options: dict
    positional: list


class Context(NamedTuple):
    args: list
    parsed: Parsed
    piped: bool
    entry: Entry


# ---- predicates: the few questions about arguments that a flag test cannot answer ----

def _sed_active(ctx: Context) -> bool:
    from .strict import _sed_script_is_active
    return _sed_script_is_active(ctx.args)


def _awk_active(ctx: Context) -> bool:
    from .strict import _awk_script_is_active
    return _awk_script_is_active(ctx.args)


def _tar_exec(ctx: Context) -> bool:
    from .strict import TAR_EXEC_OPTIONS
    return any(TAR_EXEC_OPTIONS.match(a) or a == "-I" for a in ctx.args)


def _git_config_exec(ctx: Context) -> bool:
    from .strict import RISKY_GIT_CONFIG
    return any(RISKY_GIT_CONFIG.search(a) for a in ctx.args)


def _inline_code(ctx: Context) -> bool:
    from .strict import inline_flag
    return inline_flag(ctx.args) is not None


def _find_writes(ctx: Context) -> bool:
    return any(a in ("-fprint", "-fprint0", "-fprintf", "-fls") for a in ctx.args)


def _pacman_write(ctx: Context) -> bool:
    from .strict import PACMAN_READ_ONLY
    first = next((a for a in ctx.args if a.startswith("-")), "")
    return not PACMAN_READ_ONLY.match(first)


PREDICATES: dict[str, Callable[[Context], bool]] = {
    "sed-active": _sed_active,
    "awk-active": _awk_active,
    "tar-exec": _tar_exec,
    "git-config-exec": _git_config_exec,
    "inline-code": _inline_code,
    "find-writes": _find_writes,
    "piped": lambda ctx: ctx.piped,
    "pacman-write": _pacman_write,
    "remote-argument": lambda ctx: any(REMOTE_OPERAND.match(a) for a in ctx.parsed.positional),
    "has-operand": lambda ctx: bool(ctx.parsed.positional),
    "shopt-expand-aliases": lambda ctx: "expand_aliases" in ctx.args,
}


# ---- reading the text ----

def _split_names(text: str, line: int) -> tuple:
    names = tuple(n.strip() for n in text.split(",") if n.strip())
    if not names:
        raise TableError(f"line {line}: an entry needs at least one name")
    return names


def _parse_target(text: str, kind: str, line: int) -> Target:
    match = TARGET.match(text)
    if match:
        which = match.group("kind")
        opts = tuple(o for o in (match.group("opts") or "").split("|") if o)
        if which == "opt" and not opts:
            raise TableError(f"line {line}: @opt needs option names, like @opt(-o|--output)")
        piece = match.group("slice")
        start = stop = None
        index = False
        if piece is not None:
            if which != "args":
                raise TableError(f"line {line}: only @args can be sliced")
            if ":" in piece:
                a, b = piece.split(":")
                start = int(a) if a else None
                stop = int(b) if b else None
            else:
                start, index = int(piece), True
        if which == "opt" or which in ("args",):
            pass
        allowed = {"read": READ_TARGETS, "write": FILE_TARGETS, "delete": FILE_TARGETS, "perm": FILE_TARGETS,
                   "exec": EXECUTABLE_TARGETS, "fetch": NETWORK_TARGETS, "upload": NETWORK_TARGETS}.get(kind)
        if allowed is not None and which not in allowed:
            raise TableError(f"line {line}: {kind} cannot take the target @{which}")
        if kind in ("system", "spawn") and which != "none":
            raise TableError(f"line {line}: {kind} takes a word (system=users) or @none")
        return Target(which, opts, start, stop, index)
    if kind in ("system", "spawn") and LITERAL.match(text):
        return Target("literal", word=text)
    raise TableError(f"line {line}: cannot read the target {text!r}")


def _parse_conditions(text: str, line: int) -> tuple:
    conditions = []
    for group in re.findall(r"\[([^\]]*)\]", text):
        for token in group.split():
            negated = token.startswith("!")
            body = token[1:] if negated else token
            if body.startswith("?"):
                if body[1:] not in PREDICATES:
                    raise TableError(f"line {line}: unknown predicate {body[1:]!r}")
                conditions.append(Condition("predicate", (body[1:],), negated))
            elif body.startswith("sub:"):
                conditions.append(Condition("sub", tuple(body[4:].split("|")), negated))
            elif body.startswith("-"):
                conditions.append(Condition("flag", tuple(body.split("|")), negated))
            else:
                raise TableError(f"line {line}: cannot read the condition {token!r}")
    return tuple(conditions)


def _parse_effect_line(kind: str, text: str, line: int) -> EffectRule:
    match = re.match(r"^(?P<target>@\S+|\S+)\s*(?P<rest>(?:\[[^\]]*\]\s*)*)$", text.strip())
    if not match:
        raise TableError(f"line {line}: cannot read {kind} = {text!r}")
    return EffectRule(kind, _parse_target(match.group("target"), kind, line), _parse_conditions(match.group("rest"), line), line)


def parse(text: str) -> list[Entry]:
    entries: list[Entry] = []
    current: Entry | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            if not raw.strip():
                current = None
            continue
        if not raw[0].isspace():
            template = raw.startswith("@")
            current = Entry(_split_names(raw.lstrip("@") if template else raw, number), number, template)
            entries.append(current)
            continue
        if current is None:
            raise TableError(f"line {number}: a field outside an entry")
        body = raw.strip()
        effect = re.match(r"^(" + "|".join(EFFECTS) + r")\s*=\s*(.+)$", body)
        if effect:
            current.rules.append(_parse_effect_line(effect.group(1), effect.group(2), number))
            continue
        key, sep, value = body.partition(":")
        key, value = key.strip(), value.strip()
        if not sep or key not in FIELDS:
            raise TableError(f"line {number}: unknown field {body.split()[0]!r}")
        if key == "covers":
            current.covers = tuple(value.split())
        elif key == "valued":
            current.valued |= set(value.split())
        elif key == "subs":
            current.subs = tuple(value.split())
        elif key == "like":
            current.like = value
        elif key == "where":
            current.where = tuple(value.split())
        elif key == "single-dash-long":
            current.single_dash_long = value == "yes"
        elif key == "mode-first":
            current.mode_first = value == "yes"
        elif key == "bundled-first":
            current.bundled_first = value == "yes"
        elif key == "effects":
            if value != "none":
                raise TableError(f"line {number}: 'effects:' only says 'none'; write the others as kind = target")
            current.pure = True
        elif key == "ex":
            command, arrow, expected = value.partition("=>")
            if not arrow:
                raise TableError(f"line {number}: an example is 'command => effects'")
            current.examples.append((number, command.strip(), expected.strip()))
        elif key == "note":
            current.note = value
    return entries


# ---- the table ----

class Table:
    def __init__(self, entries: list[Entry]):
        self.entries = entries
        self.by_name: dict[str, Entry] = {}
        self.templates: dict[str, Entry] = {}
        self.problems: list[str] = []
        for entry in entries:
            target = self.templates if entry.template else self.by_name
            for name in entry.names:
                if name in target or name in self.by_name or name in self.templates:
                    self.problems.append(f"line {entry.line}: {name!r} is defined twice")
                target[name] = entry
        for entry in entries:
            self._resolve(entry, set())

    def _resolve(self, entry: Entry, seen: set) -> None:
        """Copy what the entry inherits with `like:`, once."""
        if not entry.like or getattr(entry, "_resolved", False):
            return
        parent = self.templates.get(entry.like) or self.by_name.get(entry.like)
        if parent is None or id(entry) in seen:
            self.problems.append(f"line {entry.line}: {entry.name}: like {entry.like!r} is not an entry")
            return
        self._resolve(parent, seen | {id(entry)})
        entry.rules = list(parent.rules) + entry.rules
        entry.valued = set(parent.valued) | entry.valued
        entry.pure = entry.pure or parent.pure
        entry.single_dash_long = entry.single_dash_long or parent.single_dash_long
        entry.mode_first = entry.mode_first or parent.mode_first
        entry.bundled_first = entry.bundled_first or parent.bundled_first
        if entry.covers is None:
            entry.covers = parent.covers
        if entry.subs is None:
            entry.subs = parent.subs
        if entry.where is None:
            entry.where = parent.where
        entry._resolved = True                       # type: ignore[attr-defined]

    def lookup(self, name: str) -> Entry | None:
        return self.by_name.get(name)

    def known(self, name: str, where: str = "build") -> bool:
        entry = self.by_name.get(name)
        return entry is not None and where in (entry.where or ("build",))

    def names(self, where: str) -> frozenset:
        return frozenset(n for n, e in self.by_name.items() if where in (e.where or ("build",)))

    # ---- what a command line does ----

    def effects_of(self, name: str, args: list[str], piped: bool = False) -> list[Effect] | None:
        """None when the command is not in the table; otherwise its effects, with `unknown` for anything the
        entry does not cover."""
        entry = self.by_name.get(name)
        if entry is None:
            return None
        found = self._unknown_effects(entry, args)
        for _, targets, kind in self.fired(name, args, piped):
            for target in targets:
                effect = Effect(kind, target)
                if effect not in found:
                    found.append(effect)
        return found

    def _unknown_effects(self, entry: Entry, args: list[str]) -> list[Effect]:
        args, mode = self._prepare(entry, args)
        parsed = self._parse(entry, args, mode)
        found: list[Effect] = []
        covers = entry.covers or ()
        if covers != ("*",):
            for flag in sorted(parsed.flags):
                if not _covered(flag, covers):
                    found.append(Effect("unknown", flag))
        if entry.subs is not None:
            sub = parsed.positional[0] if parsed.positional else ""
            if sub not in entry.subs:
                found.append(Effect("unknown", f"subcommand {sub}".strip()))
        return found

    @staticmethod
    def _prepare(entry: Entry, args: list[str]):
        args = list(args)
        mode = None
        if entry.mode_first and args and MODE.match(args[0]):
            mode = args.pop(0)
        elif entry.bundled_first and args and BUNDLED.match(args[0]):
            args[0] = "-" + args[0]
        return args, mode

    @staticmethod
    def _parse(entry: Entry, args: list[str], mode: str | None = None) -> Parsed:
        valued = set(entry.valued)
        for rule in entry.rules:
            valued |= set(rule.target.opts)
        parsed = split_args(args, valued, entry.single_dash_long)
        if mode is not None:
            parsed.positional.insert(0, mode)
        return parsed

    def fired(self, name: str, args: list[str], piped: bool = False) -> list:
        """The rules of the entry whose conditions hold for this command line, as (rule, targets, kind).
        strict.py reads the predicate conditions of these to decide what it reports."""
        entry = self.by_name.get(name)
        if entry is None:
            return []
        args, mode = self._prepare(entry, args)
        parsed = self._parse(entry, args, mode)
        ctx = Context(args, parsed, piped, entry)
        return [(rule, _resolve_target(rule.target, ctx), rule.kind)
                for rule in entry.rules if all(_holds(c, ctx) for c in rule.conditions)]


def _covered(flag: str, covers: tuple) -> bool:
    for item in covers:
        if item == flag:
            return True
        if item.endswith("*") and flag.startswith(item[:-1]):
            return True
        if item == "-#" and re.fullmatch(r"-\d", flag):
            return True
    return False


def split_args(args: list[str], valued: set, single_dash_long: bool = False) -> Parsed:
    flags: set = set()
    options: dict = {}
    positional: list = []
    rest = False
    i = 0
    while i < len(args):
        arg = args[i]
        if rest or not arg.startswith("-") or arg == "-":
            positional.append(arg)
        elif arg == "--":
            rest = True
        elif arg.startswith("--") or single_dash_long:
            name, equals, value = arg.partition("=")
            flags.add(name)
            if name in valued:
                if equals:
                    options.setdefault(name, []).append(value)
                elif i + 1 < len(args):
                    options.setdefault(name, []).append(args[i + 1])
                    i += 1
        else:
            letters = arg[1:]
            for j, letter in enumerate(letters):
                flag = "-" + letter
                flags.add(flag)
                if flag in valued:
                    value = letters[j + 1:]
                    if not value and i + 1 < len(args):
                        value = args[i + 1]
                        i += 1
                    if value:
                        options.setdefault(flag, []).append(value)
                    break
        i += 1
    return Parsed(flags, options, positional)


def _holds(condition: Condition, ctx: Context) -> bool:
    if condition.kind == "predicate":
        result = PREDICATES[condition.names[0]](ctx)
    elif condition.kind == "sub":
        result = bool(ctx.parsed.positional) and ctx.parsed.positional[0] in condition.names
    else:
        result = any(
            (name[:-1] and any(f.startswith(name[:-1]) for f in ctx.parsed.flags)) if name.endswith("*") else name in ctx.parsed.flags
            for name in condition.names)
    return not result if condition.negated else result


def _resolve_target(target: Target, ctx: Context) -> list[str]:
    parsed = ctx.parsed
    kind = target.kind
    if kind == "none":
        return [""]
    if kind == "literal":
        return [target.word]
    if kind == "args":
        if target.index:
            try:
                return [parsed.positional[target.start]]
            except IndexError:
                return []
        return parsed.positional[target.start:target.stop]
    if kind == "opt":
        return [value for name in target.opts for value in parsed.options.get(name, [])]
    if kind == "url":
        return [a for a in parsed.positional if URL.match(a)]
    if kind == "script":
        scripts = parsed.options.get("-e", []) + parsed.options.get("--expression", [])
        return scripts or parsed.positional[:1]
    if kind == "cmd":
        rest = [a for a in parsed.positional if not (ASSIGNMENT.match(a) or DURATION.match(a))]
        return rest[:1]
    if kind in ("stdin", "tree", "deps", "system"):
        return [kind]
    if kind == "find-paths":
        paths = []
        for word in ctx.args:
            if word.startswith(("-", "(", "!")):
                break
            paths.append(word)
        return paths or ["."]
    if kind == "find-exec":
        words = ctx.args
        for i, word in enumerate(words):
            if word in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(words):
                return [words[i + 1]]
        return []
    return []


@lru_cache(maxsize=1)
def load() -> Table:
    from .commandtable_data import TABLE
    return Table(parse(TABLE))


# ---- checking ----

def _expected(text: str) -> list[str]:
    return [] if text in ("", "none") else sorted(piece.strip() for piece in text.split(";") if piece.strip())


def check(table: Table | None = None) -> list[str]:
    """Everything wrong with the table: structure, missing parts, and every example that does not hold."""
    table = table or load()
    problems = list(table.problems)
    for entry in table.entries:
        label = f"line {entry.line} ({entry.name})"
        if not entry.note:
            problems.append(f"{label}: no note")
        if entry.template:
            continue
        if entry.covers is None:
            problems.append(f"{label}: no 'covers:' (a list of options, or * when options cannot change the effect)")
        if not entry.rules and not entry.pure:
            problems.append(f"{label}: no effects (write 'effects: none' if it really has none)")
        if entry.pure and entry.rules and not entry.like:
            problems.append(f"{label}: 'effects: none' together with effects")
        if not entry.examples:
            problems.append(f"{label}: no example")
        for context in entry.where or ():
            if context not in CONTEXTS:
                problems.append(f"{label}: unknown context {context!r}")
        for number, command, expected in entry.examples:
            piped = command.startswith("|")
            try:
                words = shlex.split(command.lstrip("|").strip())
            except ValueError as exc:
                problems.append(f"line {number}: cannot read the example {command!r}: {exc}")
                continue
            if not words or words[0] not in entry.names:
                problems.append(f"line {number}: the example {command!r} does not start with one of {', '.join(entry.names)}")
                continue
            got = table.effects_of(words[0], words[1:], piped)
            actual = sorted(str(e) for e in got or [])
            if actual != _expected(expected):
                problems.append(f"line {number}: {command!r} gives {'; '.join(actual) or 'none'}, the example says {expected or 'none'}")
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    table = load()
    if argv[:1] == ["--show"] and len(argv) == 2:
        entry = table.lookup(argv[1])
        if entry is None:
            print(f"{argv[1]}: not in the table")
            return 1
        print(f"{', '.join(entry.names)}  (where: {' '.join(entry.where or ('build',))}; covers: {' '.join(entry.covers or ())})")
        for rule in entry.rules:
            print(f"  {rule.kind} = {_describe_target(rule.target)} {' '.join(_describe_condition(c) for c in rule.conditions)}".rstrip())
        for _, command, expected in entry.examples:
            print(f"  ex: {command} => {expected}")
        print(f"  note: {entry.note}")
        return 0
    if argv[:1] == ["--check"]:
        problems = check(table)
        for problem in problems:
            print(problem)
        count = len([e for e in table.entries if not e.template])
        print(f"{count} entries, {len(table.by_name)} commands, {len(problems)} problem(s)")
        return 1 if problems else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
