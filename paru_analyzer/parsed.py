"""One parse per file, shared by every checker.

The rule engines used to receive the file's text and each parse it again in its own way (a regex
over lines here, `shlex` over a command there, `text.find(item)` to recover a line number). They now
receive a `ParsedFile`: the syntax tree (shast.py), the commands and steps made from it (astadapt.py),
the variables and arrays the script assigns, and the line every array item sits on. The only text view
left is `units`, the lines the pattern rules match (the lexer's output, see preprocess.py).

The raw text is deliberately not an attribute. `raw_text()` exists for the few checks that are about
the bytes themselves (invisible characters, the cross-check against bash, the truncation marker), so
that `grep raw_text` lists every place a checker looks past the parse.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property
from typing import NamedTuple

from . import astadapt, shast
from .invocation import payload, views
from .preprocess import Preprocessed, preprocess
from .strict import Command


class Unit(NamedTuple):
    """One logical line a pattern rule reads."""
    number: int
    text: str
    comment: bool
    heredoc: bool = False           # the body of a here-document: text written somewhere, not a command


class ParsedCommand(NamedTuple):
    """A simple command plus where it is and what surrounds it."""
    command: Command
    line: int
    text: str                       # the whole preprocessed command line it came from
    top: bool                       # outside every function: runs when the file is merely parsed
    siblings: tuple                 # every Command extracted from the same line, in order
    stage_map: dict | None = None   # segment -> commands, built once per line and shared by its commands
    end: int = 0                    # last line of the statement
    parent: Command | None = None   # the command whose `sh -c` / `eval` string this one came from

    def upstream(self) -> list[Command]:
        """Commands of the earlier stages of the pipeline this command receives its input from."""
        by_stage = self._stages()
        found: list[Command] = []
        stage = self.command.segment
        while stage in by_stage and by_stage[stage][0].piped and stage - 1 in by_stage:
            stage -= 1
            found.extend(by_stage[stage])
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


def collect_arrays(defs, overridden: list | None = None) -> dict[str, Array]:
    """name -> Array as makepkg would see it: `+=` appends, a later `=` replaces. The values that were
    replaced are appended to `overridden` as (name, Array), because a replaced source is still
    something the author wrote and must not escape review."""
    arrays: dict[str, Array] = {}
    for d in defs:
        if d.appends and d.name in arrays:
            old = arrays[d.name]
            merged = Array(old.items + d.items, old.line, old.item_lines + d.item_lines)
        else:
            if d.name in arrays and overridden is not None:
                overridden.append((d.name, arrays[d.name]))
            merged = Array(d.items, d.line, d.item_lines)
        arrays[d.name] = merged
    return arrays


MAX_PAYLOAD_DEPTH = 4


def _emit(commands: tuple, text: str, top: bool, out: list, depth: int, end: int = 0, parent: Command | None = None) -> None:
    """Add the commands of one unit as ParsedCommands, then the commands inside any `sh -c STR` /
    `eval STR` they start. `commands` is ((Command, line), ...)."""
    plain = tuple(command for command, _ in commands)
    stage_map: dict[int, list[Command]] = {}
    for command in plain:
        stage_map.setdefault(command.segment, []).append(command)
    for command, line in commands:
        out.append(ParsedCommand(command, line, text, top, plain, stage_map, end, parent))
    if depth >= MAX_PAYLOAD_DEPTH:
        return
    for command, line in commands:
        for view in views(command):
            payload_text = payload(view.name, view.args)
            if payload_text and payload_text.strip("_SUB ").strip():
                inner, ok = astadapt.flatten(payload_text)
                if not ok:                           # not valid shell: read what can be read, loosely
                    inner = astadapt.loose(payload_text) or inner
                if inner:
                    _emit(tuple((c, line) for c in inner), text, top, out, depth + 1, end, command)


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
    def _units(self) -> tuple:
        """(units, lines of unreadable statements) of the syntax tree; nothing when the tokenizer failed."""
        if self.pre is None or not self.pre.ok:
            return (), frozenset()
        units, bad = astadapt.units(self.ast.script)
        return tuple(units), frozenset(bad)

    @cached_property
    def _analysis(self) -> tuple:
        out: list[ParsedCommand] = []
        for unit in self._units[0]:
            _emit(unit.commands, unit.text, unit.top, out, 0, unit.end)
        return tuple(out), self._units[1]

    @cached_property
    def code_units(self) -> tuple:
        """Every statement of a shell file as astadapt.Unit (commands, lines, where it runs), in source order."""
        return self._units[0]

    @cached_property
    def steps(self) -> tuple:
        """What the default-deny check and the activity inventory read (see astadapt.Step)."""
        if self.pre is not None and not self.pre.ok:       # the tokenizer failed: no unit exists, say so once
            return (astadapt.Step(1, self._text.strip()[:100], True, False, False, False, [], False, [], False, False),)
        return tuple(astadapt.steps(list(self._units[0])))

    @cached_property
    def function_names(self) -> frozenset:
        """Functions the file defines: calling one is not running an unknown program."""
        if self.pre is None or not self.pre.ok:
            return frozenset()
        return frozenset(n.name for n in shast.walk(self.ast.script) if isinstance(n, shast.FunctionDef))

    @cached_property
    def toplevel_commands(self) -> tuple:
        """The units outside every function that run something (a command, not a plain declaration)."""
        return tuple(u for u in self._units[0] if u.top and u.code and u.ok)

    @cached_property
    def _tree(self):
        """The syntax tree of a shell file, None for other files. A statement it could not read is in
        `unparsed_lines` and is read by the pattern rules; an assignment hidden in one is not seen."""
        return self.ast if self.pre is not None else None

    def assignment_line(self, name: str) -> int | None:
        """Line of the first plain assignment or array definition of `name`."""
        if self._tree is None:
            return None
        for node in _assignments(self._tree):
            if any(a.name == name and a.index is None for a in node.assigns):
                return node.line
        return None

    @cached_property
    def variables(self) -> dict[str, str]:
        return variables_from_tree(self._tree) if self._tree is not None else {}

    @cached_property
    def stable_variables(self) -> dict[str, str]:
        """Literal variables assigned exactly once in the file, so `$d` means the same thing wherever it is
        used. A name assigned twice (`dir=/etc` then `dir=$pkgdir/etc`) is left out: either value may apply."""
        if self._tree is None:
            return {}
        counts = assignment_counts(self._tree)
        return {k: v for k, v in self.variables.items() if counts.get(k, 0) == 1 and k not in ("pkgdir", "srcdir", "startdir")}

    @cached_property
    def arrays(self) -> dict[str, Array]:
        return self.replaced_arrays[0]

    @cached_property
    def replaced_arrays(self) -> tuple[dict[str, Array], list]:
        replaced: list = []
        return collect_arrays(self.definitions, replaced), replaced

    @cached_property
    def definitions(self) -> tuple[Definition, ...]:
        return tuple(definitions_from_tree(self._tree)) if self._tree is not None else ()


def parse(name: str, source) -> ParsedFile:
    """A ParsedFile from text, or the ParsedFile itself (so callers may pass either)."""
    return source if isinstance(source, ParsedFile) else ParsedFile(name, source)
