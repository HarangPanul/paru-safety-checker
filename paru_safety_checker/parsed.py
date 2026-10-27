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

from .invocation import payload, views
from .preprocess import Line, Preprocessed, preprocess
from .strict import Command, extract_commands, strip_substitutions

ARRAY_LINE = re.compile(r"^[A-Za-z_]\w*(?:\[[^\]]*\])?(\+?)=\((.*)\)\s*$", re.S)
ARRAY_NAME = re.compile(r"^([A-Za-z_]\w*)")
HEREDOC_OPEN = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_]\w*)\1")


class Unit(NamedTuple):
    """One logical line a pattern rule reads."""
    number: int
    text: str
    comment: bool


class ParsedCommand(NamedTuple):
    """A simple command plus where it is and what surrounds it."""
    command: Command
    line: int
    text: str                       # the whole preprocessed command line it came from
    top: bool                       # outside every function: runs when the file is merely parsed
    siblings: tuple                 # every Command extracted from the same line, in order

    def upstream(self) -> list[Command]:
        """Commands of the earlier stages of the pipeline this command receives its input from."""
        by_stage: dict[int, list[Command]] = {}
        for other in self.siblings:
            by_stage.setdefault(other.segment, []).append(other)
        found: list[Command] = []
        stage = self.command.segment
        while stage in by_stage and by_stage[stage][0].piped and stage - 1 in by_stage:
            stage -= 1
            found.extend(by_stage[stage])
        return found


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


def collect_arrays(pre: Preprocessed, overridden: list | None = None) -> dict[str, Array]:
    """name -> Array as makepkg would see it: `+=` appends, a later `=` replaces. The values that were
    replaced are appended to `overridden` as (name, Array), because a replaced source is still
    something the author wrote and must not escape review."""
    arrays: dict[str, Array] = {}
    for d in definitions(pre):
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


def _collect(found: list[Command], line: Line, out: list, depth: int) -> None:
    """Add a line's commands, then the commands inside any `sh -c STR` / `eval STR` they start."""
    siblings = tuple(found)
    out.extend(ParsedCommand(c, line.number, line.text, line.region == "top", siblings) for c in found)
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
            units = [Unit(l.number, l.text, l.kind == "heredoc" and l.text.lstrip().startswith("#"))
                     for l in self.pre.lines if l.kind not in ("heredoc-end", "case-pattern")]
            units += [Unit(n, t, t.lstrip().startswith("#")) for n, t in self.pre.statements]
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
    def _analysis(self) -> tuple:
        if self.pre is None:
            return (), frozenset()
        out: list[ParsedCommand] = []
        bad: set[int] = set()
        for line in self.pre.lines:
            if line.kind in ("heredoc-end", "case-pattern", "function"):
                continue
            found, ok = _commands_of(line)
            if not ok:
                bad.add(line.number)
            _collect(found, line, out, 0)
        return tuple(out), frozenset(bad)

    def assignment_line(self, name: str) -> int | None:
        """Line of the first plain assignment or array definition of `name`."""
        if self.pre is None:
            return None
        for line in self.pre.lines:
            if line.kind in ("assignment", "array") and re.match(rf"{re.escape(name)}\+?=", line.text):
                return line.number
        return None

    @cached_property
    def variables(self) -> dict[str, str]:
        return literal_variables(self.pre) if self.pre is not None else {}

    @cached_property
    def arrays(self) -> dict[str, Array]:
        return self.replaced_arrays[0]

    @cached_property
    def replaced_arrays(self) -> tuple[dict[str, Array], list]:
        replaced: list = []
        arrays = collect_arrays(self.pre, replaced) if self.pre is not None else {}
        return arrays, replaced

    @cached_property
    def definitions(self) -> tuple[Definition, ...]:
        return tuple(definitions(self.pre)) if self.pre is not None else ()


def parse(name: str, source) -> ParsedFile:
    """A ParsedFile from text, or the ParsedFile itself (so callers may pass either)."""
    return source if isinstance(source, ParsedFile) else ParsedFile(name, source)
