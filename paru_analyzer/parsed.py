"""One parse per file, shared by every checker.

The rule engines used to receive the file's text and each parse it again in its own way (a regex
over lines here, `shlex` over a command there, `text.find(item)` to recover a line number). They now
receive a `ParsedFile`: the preprocessed command lines, the commands split into words with quotes
removed, the variables and arrays the script assigns, and the line every array item sits on.

The raw text is deliberately not an attribute. `raw_text()` exists for the few checks that are about
the bytes themselves (invisible characters, the cross-check against bash, the truncation marker), so
that `grep raw_text` lists every place a checker looks past the parse.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple

from . import astadapt, shast
from .invocation import payload, views
from .preprocess import Line, Preprocessed, preprocess
from .strict import Command, extract_commands, strip_substitutions

ARRAY_LINE = re.compile(r"^[A-Za-z_]\w*(?:\[[^\]]*\])?(\+?)=\((.*)\)\s*$", re.S)
ARRAY_NAME = re.compile(r"^([A-Za-z_]\w*)")
OPENS_PIPED_GROUP = re.compile(r"\|&?\s*[({][^)}]*$")
CLOSES_GROUP = re.compile(r"[)}]\s*(?:[|&;<>].*)?$")
HEREDOC_OPEN = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_]\w*)\1")


class Unit(NamedTuple):
    """One logical line a pattern rule reads."""
    number: int
    text: str
    comment: bool
    heredoc: bool = False           # the body of a here-document: text written somewhere, not a command


class Group:
    """The commands found so far on one source line, in order. A pipe that follows a closing `)` or `}`
    (`{ curl x; echo; } | sh`) is fed by all of them, so a command after such a pipe points at its group
    and the number of commands the group held at that moment, instead of copying them."""

    def __init__(self) -> None:
        self.commands: list[Command] = []
        self._prefix: list[frozenset] = []          # _prefix[i]: tags of commands[:i + 1], filled on demand

    def tags(self, tagger, upto: int) -> frozenset:
        while len(self._prefix) < min(upto, len(self.commands)):
            index = len(self._prefix)
            previous = self._prefix[-1] if self._prefix else frozenset()
            self._prefix.append(previous | tagger(self.commands[index]))
        return self._prefix[min(upto, len(self.commands)) - 1] if upto and self.commands else frozenset()


class ParsedCommand(NamedTuple):
    """A simple command plus where it is and what surrounds it."""
    command: Command
    line: int
    text: str                       # the whole preprocessed command line it came from
    top: bool                       # outside every function: runs when the file is merely parsed
    siblings: tuple                 # every Command extracted from the same line, in order
    stage_map: dict | None = None   # segment -> commands, built once per line and shared by its commands
    fed_by: tuple | None = None     # (Group, count): the commands before this line that feed its leading pipe

    def upstream(self) -> list[Command]:
        """Commands of the earlier stages of the pipeline this command receives its input from."""
        by_stage = self._stages()
        found: list[Command] = []
        stage = self.command.segment
        while stage in by_stage and by_stage[stage][0].piped and stage - 1 in by_stage:
            stage -= 1
            found.extend(by_stage[stage])
        if self.fed_by and stage in by_stage and by_stage[stage][0].piped:
            group, count = self.fed_by
            found.extend(reversed(group.commands[:count]))
        return found

    def _stages(self) -> dict:
        if self.stage_map is not None:
            return self.stage_map
        by_stage: dict = {}
        for other in self.siblings:
            by_stage.setdefault(other.segment, []).append(other)
        return by_stage

    def upstream_tags(self, tagger) -> frozenset:
        """The union of `tagger(command)` over everything `upstream()` would return, without building that
        list. Each stage's answer is computed once and kept, so a pipeline of n stages costs n, not n squared.
        `tagger` must be the same function on every call (the kept answers do not record which one made them)."""
        by_stage = self._stages()
        memo = by_stage.setdefault("memo", {})

        def feeds(stage):
            return stage in by_stage and by_stage[stage][0].piped and stage - 1 in by_stage

        chain, stage = [], self.command.segment
        while feeds(stage) and stage not in memo:
            chain.append(stage)
            stage -= 1
        if stage in memo:
            before = memo[stage]
        elif self.fed_by and stage in by_stage and by_stage[stage][0].piped:
            before = self.fed_by[0].tags(tagger, self.fed_by[1])     # the pipe at the bottom is fed by a group
        else:
            before = frozenset()
        for stage in reversed(chain):
            tags = frozenset().union(*(tagger(c) for c in by_stage[stage - 1]), before)
            memo[stage] = before = tags
        return before

    def substitution_tags(self, tagger) -> frozenset:
        """Tags of the commands of every substitution on this line (`$(...)`, `<(...)`)."""
        memo = self._stages().setdefault("memo", {})
        if "sub" not in memo:
            memo["sub"] = frozenset().union(*(tagger(c) for c in self.siblings if c.inside))
        return memo["sub"]


class Array(NamedTuple):
    items: list
    line: int
    item_lines: list                # the line each item sits on, for reporting


class Definition(NamedTuple):
    name: str
    appends: bool
    items: list
    line: int
    item_lines: list


def array_items(body: str) -> list[str]:
    try:
        return shlex.split(body)
    except ValueError:
        return [t.strip("'\"") for t in re.findall(r"'[^']*'|\"[^\"]*\"|\S+", body)]


def literal_variables(pre: Preprocessed) -> dict[str, str]:
    """Literal assignments (`url="https://..."`), used to expand $url in source arrays."""
    found: dict[str, str] = {}
    for line in pre.lines:
        if line.kind != "assignment" or "$(" in line.text or "`" in line.text:
            continue
        try:
            words = shlex.split(line.text)
        except ValueError:
            continue
        for word in words:
            match = re.match(r"^(\w+)=(.*)$", word, re.S)
            if match:
                found.setdefault(match.group(1), match.group(2))
    return found


def _assignments(tree) -> list:
    """Every statement that only assigns (`a=1 b=2`, `x=(..)`), in file order, outside substitutions and pipelines (an assignment in a pipe runs in a subshell and is lost). A
    `local`/`declare` line is a command, not an assignment, as in the text route."""
    return [c.node for c in shast.simple_commands(tree.script) if not c.substitution and c.stages == 1 and c.node.assigns and not c.node.words]


def definitions_from_tree(tree) -> list[Definition]:
    found = []
    for node in _assignments(tree):
        for a in node.assigns:
            if a.array is not None and a.index is None:
                found.append(Definition(a.name, a.append, [w.value for w in a.array], a.line, [w.line for w in a.array]))
    return found


def variables_from_tree(tree) -> dict[str, str]:
    """The first plain literal assignment of each name; a value that runs a command is left out."""
    found: dict[str, str] = {}
    for node in _assignments(tree):
        for a in node.assigns:
            if a.value is None or a.append or a.index is not None:
                continue
            if "$(" in a.value.raw or "`" in a.value.raw:
                continue
            found.setdefault(a.name, a.value.value)
    return found


def assignment_counts(tree) -> dict[str, int]:
    """How many times each name is assigned, `local`/`declare`/`export` included (either value may apply)."""
    counts: dict[str, int] = {}
    for node in _assignments(tree):
        for a in node.assigns:
            counts[a.name] = counts.get(a.name, 0) + 1
    for c in shast.simple_commands(tree.script):
        words = c.node.words
        if words and words[0].value in ("local", "declare", "typeset", "export", "readonly"):
            for w in words[1:]:
                m = re.match(r"([A-Za-z_]\w*)\+?=", w.value)
                if m:
                    counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def expand(value: str, variables: dict[str, str]) -> str:
    for _ in range(5):
        expanded = re.sub(
            r"\$(?:\{(\w+)\}|(\w+))",
            lambda m: variables.get(m.group(1) or m.group(2), m.group(0)),
            value,
        )
        if expanded == value:
            break
        value = expanded
    return value


def _item_lines(pre: Preprocessed, line: Line, items: list[str]) -> list[int]:
    """Line of each array item, searched inside the statement that defines the array, in order. The
    search resumes after the previous item, so two identical items get their own lines."""
    numbers: list[int] = []
    number, column = line.number, 0
    last = max(line.end, line.number)
    for item in items:
        found = None
        probe, start = number, column
        while probe <= last:
            text = pre.source_lines[probe - 1] if 0 < probe <= len(pre.source_lines) else ""
            index = text.find(item, start)
            if index >= 0:
                found = (probe, index + len(item))
                break
            probe, start = probe + 1, 0
        if found:
            number, column = found
        numbers.append(found[0] if found else line.number)
    return numbers


def definitions(pre: Preprocessed):
    """Every array assignment, in file order, nothing merged."""
    for line in pre.lines:
        if line.kind != "array":
            continue
        match, name = ARRAY_LINE.match(line.text), ARRAY_NAME.match(line.text)
        if match and name:
            items = array_items(match.group(2))
            yield Definition(name.group(1), bool(match.group(1)), items, line.number, _item_lines(pre, line, items))


def collect_arrays(pre: Preprocessed, overridden: list | None = None, defs=None) -> dict[str, Array]:
    """name -> Array as makepkg would see it: `+=` appends, a later `=` replaces. The values that were
    replaced are appended to `overridden` as (name, Array), because a replaced source is still
    something the author wrote and must not escape review."""
    arrays: dict[str, Array] = {}
    for d in (definitions(pre) if defs is None else defs):
        if d.appends and d.name in arrays:
            old = arrays[d.name]
            merged = Array(old.items + d.items, old.line, old.item_lines + d.item_lines)
        else:
            if d.name in arrays and overridden is not None:
                overridden.append((d.name, arrays[d.name]))
            merged = Array(d.items, d.line, d.item_lines)
        arrays[d.name] = merged
    return arrays


def _commands_of(line: Line) -> tuple[list[Command], bool]:
    """Commands a preprocessed line runs. At the top level only substitutions run (a declaration
    is not a command), except for real commands, which run when the file is parsed."""
    top = line.region == "top"
    if line.kind == "heredoc":
        # An unquoted here-document is expanded by the shell: $(...) and `...` in it run.
        if line.expands and ("$(" in line.text or "`" in line.text):
            return _substitutions(line.text), True
        return [], False
    if top and line.kind not in ("command", "control"):
        return _substitutions(line.text), True
    return extract_commands(line.text)[0], True


MAX_PAYLOAD_DEPTH = 4
USE_AST = True                  # False: the older text-based route (kept to compare the two)


def _collect(found: list[Command], line: Line, out: list, depth: int, fed_by: tuple | None = None) -> None:
    """Add a line's commands, then the commands inside any `sh -c STR` / `eval STR` they start."""
    siblings = tuple(found)
    stage_map: dict[int, list[Command]] = {}
    for other in siblings:
        stage_map.setdefault(other.segment, []).append(other)
    out.extend(ParsedCommand(c, line.number, line.text, line.region == "top", siblings, stage_map, fed_by) for c in found)
    if depth >= MAX_PAYLOAD_DEPTH:
        return
    for command in found:
        for view in views(command):
            text = payload(view.name, view.args)
            if text and text.strip("_SUB ").strip():
                inner, _ = extract_commands(text)
                if inner:
                    _collect(inner, line, out, depth + 1)


def _substitutions(text: str) -> list[Command]:
    _, subs = strip_substitutions(text)
    found: list[Command] = []
    stages = [0]
    for inner in subs:
        found.extend(extract_commands(inner, 0, stages)[0])
    return found


def _emit(commands: tuple, text: str, top: bool, out: list, depth: int) -> None:
    """Add the commands of one unit as ParsedCommands, then the commands inside any `sh -c STR` /
    `eval STR` they start. `commands` is ((Command, line), ...)."""
    plain = tuple(command for command, _ in commands)
    stage_map: dict[int, list[Command]] = {}
    for command in plain:
        stage_map.setdefault(command.segment, []).append(command)
    for command, line in commands:
        out.append(ParsedCommand(command, line, text, top, plain, stage_map))
    if depth >= MAX_PAYLOAD_DEPTH:
        return
    for command, line in commands:
        for view in views(command):
            payload_text = payload(view.name, view.args)
            if payload_text and payload_text.strip("_SUB ").strip():
                inner, ok = astadapt.flatten(payload_text)
                if not ok:                           # not valid shell: read it as loosely as before
                    inner = tuple(extract_commands(payload_text)[0]) or inner
                if inner:
                    _emit(tuple((c, line) for c in inner), text, top, out, depth + 1)


class ParsedFile:
    def __init__(self, name: str, text: str):
        self.name = name
        self._text = text
        self.base = name.rsplit("/", 1)[-1]
        self.is_install = name.endswith(".install")
        self.is_pkgbuild = name == "PKGBUILD"
        self.is_shell = self.is_pkgbuild or self.is_install
        self.is_patch = name.endswith((".patch", ".diff"))
        self.pre: Preprocessed | None = preprocess(text) if self.is_shell else None

    def raw_text(self) -> str:
        """The file exactly as fetched. Only for checks about the bytes themselves."""
        return self._text

    @cached_property
    def units(self) -> tuple[Unit, ...]:
        """What the pattern rules read: every command on its own line, plus the original statements
        (comments removed, continuations joined) for patterns that span `;`. Files that are not shell
        are read line by line with continuations joined."""
        if self.pre is not None:
            units = [Unit(l.number, l.text, l.kind == "heredoc" and l.text.lstrip().startswith("#"), l.kind == "heredoc")
                     for l in self.pre.lines if l.kind not in ("heredoc-end", "case-pattern")]
            bodies = {l.number for l in self.pre.lines if l.kind in ("heredoc", "heredoc-end")}
            units += [Unit(n, t, t.lstrip().startswith("#"), n in bodies) for n, t in self.pre.statements]
            return tuple(units)
        out, buf, start = [], "", 0
        for number, line in enumerate(self._text.split("\n"), 1):
            if not buf:
                start = number
            if line.endswith("\\"):
                buf += line[:-1] + " "
                continue
            joined = buf + line
            out.append(Unit(start, joined, joined.lstrip().startswith("#")))
            buf = ""
        if buf:
            out.append(Unit(start, buf, buf.lstrip().startswith("#")))
        return tuple(out)

    @cached_property
    def removed_comments(self) -> tuple:
        """((line, text), ...) of comments the shell parse discarded."""
        return self.pre.comments if self.pre is not None else ()

    @cached_property
    def commands(self) -> tuple[ParsedCommand, ...]:
        return self._analysis[0]

    @cached_property
    def unparsed_lines(self) -> frozenset:
        """Lines whose commands could not be extracted. Every line, when the whole shell did not parse:
        the structured rules saw nothing there, so the pattern rules stand in for them."""
        return self._analysis[1]

    def understood(self, line: int) -> bool:
        """True when the commands of this line were extracted, so structured rules covered it."""
        return self.pre is not None and self.pre.ok and line not in self.unparsed_lines

    @cached_property
    def ast(self) -> "shast.ParseResult | None":
        """The syntax tree of a shell file (see shast.py)."""
        return shast.parse(self._text) if self.is_shell else None

    @cached_property
    def _analysis(self) -> tuple:
        if self.pre is None:
            return (), frozenset()
        if USE_AST:
            return self._analysis_from_tree()
        return self._analysis_from_text()

    def _analysis_from_tree(self) -> tuple:
        if not self.pre.ok:                          # the tokenizer failed: nothing was read
            return (), frozenset()
        units, bad = astadapt.units(self.ast.script)
        out: list[ParsedCommand] = []
        for unit in units:
            _emit(unit.commands, unit.text, unit.top, out, 0)
        return tuple(out), frozenset(bad)

    def _analysis_from_text(self) -> tuple:
        out: list[ParsedCommand] = []
        bad: set[int] = set()
        group, group_line = Group(), 0          # the commands of the current source line, for pipes after `)` / `}`
        feeding = False                         # inside a `( ... )` / `{ ... }` that a pipe feeds
        for line in self.pre.lines:
            if line.kind in ("heredoc-end", "case-pattern", "function"):
                continue
            continues = line.text.lstrip().startswith("|")
            if not feeding and not continues and line.number != group_line:
                group, group_line = Group(), line.number
            closing = feeding and line.text.rstrip().endswith(")")
            found, ok = _commands_of(line._replace(text=line.text.rstrip()[:-1]) if closing else line)
            if not ok:
                bad.add(line.number)
            fed_by = None
            if (feeding or continues) and found and group.commands:
                # `(curl x) | sh` reaches us as `curl x` and `| sh`; `curl x | (cd /tmp; sh)` as
                # `curl x | (cd /tmp` and `sh)`. Those lines read a pipe the earlier ones feed.
                fed_by = (group, len(group.commands))
                found = [found[0]._replace(piped=True)] + found[1:]
            _collect(found, line, out, 0, fed_by)
            group.commands.extend(found)
            if feeding and found:
                feeding = not CLOSES_GROUP.search(line.text)
            elif not feeding and found and OPENS_PIPED_GROUP.search(line.text):
                feeding = True
        return tuple(out), frozenset(bad)

    @cached_property
    def _tree(self):
        """The syntax tree when it covers the whole file (no statement was left unread), else None and the
        text route answers: an unread statement could hide an assignment."""
        if not USE_AST or self.pre is None or self.ast is None or self.ast.errors:
            return None
        return self.ast

    def assignment_line(self, name: str) -> int | None:
        """Line of the first plain assignment or array definition of `name`."""
        if self.pre is None:
            return None
        if self._tree is not None:
            for node in _assignments(self._tree):
                if any(a.name == name and a.index is None for a in node.assigns):
                    return node.line
            return None
        for line in self.pre.lines:
            if line.kind in ("assignment", "array") and re.match(rf"{re.escape(name)}\+?=", line.text):
                return line.number
        return None

    @cached_property
    def variables(self) -> dict[str, str]:
        if self._tree is not None:
            return variables_from_tree(self._tree)
        return literal_variables(self.pre) if self.pre is not None else {}

    @cached_property
    def stable_variables(self) -> dict[str, str]:
        """Literal variables assigned exactly once in the file, so `$d` means the same thing wherever it is
        used. A name assigned twice (`dir=/etc` then `dir=$pkgdir/etc`) is left out: either value may apply."""
        if self.pre is None:
            return {}
        counts: dict[str, int] = {}
        if self._tree is not None:
            counts = assignment_counts(self._tree)
        for line in () if self._tree is not None else self.pre.lines:
            if line.kind in ("assignment", "array"):
                for name in re.findall(r"(?:^|\s)(?:local\s+|declare\s+(?:-\w+\s+)?|export\s+|readonly\s+)?([A-Za-z_]\w*)\+?=", line.text):
                    counts[name] = counts.get(name, 0) + 1
        return {k: v for k, v in self.variables.items() if counts.get(k, 0) == 1 and k not in ("pkgdir", "srcdir", "startdir")}

    @cached_property
    def arrays(self) -> dict[str, Array]:
        return self.replaced_arrays[0]

    @cached_property
    def replaced_arrays(self) -> tuple[dict[str, Array], list]:
        replaced: list = []
        arrays = collect_arrays(self.pre, replaced, self.definitions) if self.pre is not None else {}
        return arrays, replaced

    @cached_property
    def definitions(self) -> tuple[Definition, ...]:
        if self._tree is not None:
            return tuple(definitions_from_tree(self._tree))
        return tuple(definitions(self.pre)) if self.pre is not None else ()


def parse(name: str, source) -> ParsedFile:
    """A ParsedFile from text, or the ParsedFile itself (so callers may pass either)."""
    return source if isinstance(source, ParsedFile) else ParsedFile(name, source)
