"""From the syntax tree to the commands the checkers read.

The rules in cmdrules.py and the inventory in activity.py consume `Command` objects (a name, its
arguments with quotes removed, whether it receives a pipe, its redirections, the pipeline stage it
sits in). Until now those came from cutting the preprocessed text into words with `shlex`. Here they
come from the tree in shast.py, so a pipe into a group, a `$(...)` in a word or a here-document no
longer needs a repair after the fact.

What stays the same as before, on purpose, so that the rules see the same shapes:
- the classification of a command (wrappers such as `sudo`/`env`, the program behind `xargs` and
  `find -exec`, words that are not commands such as `[[` and `test`) is `strict._segment`;
- a command substitution is the placeholder `__SUB__` in the word that holds it, an arithmetic
  expansion is `0`, and the commands inside a substitution follow the main ones with `inside=True`;
- the stages of a pipeline are numbered one after the other, so `upstream()` can walk back from a stage.

What is better: every stage of `{ a; b; } | c` and `x | (cd d; c)` is one pipeline stage, so what feeds
`c` is exactly the group before it; a statement the grammar could not read is reported with its lines.
"""
from __future__ import annotations

from typing import NamedTuple

from . import shast
from .shast import (AndOr, ArithCommand, Case, CmdSub, Conditional, For, FunctionDef, Group, HereDoc, If, Pipeline,
                    ProcSub, Script, Simple, Statement, Subshell, Unparsed, While, Word)
from .strict import Command, _segment


class Unit(NamedTuple):
    """The commands of one statement (a command or a whole pipeline), where it is and what it looks like."""
    line: int
    text: str
    top: bool                   # outside every function: runs when the file is merely parsed
    commands: tuple             # ((Command, line), ...)
    heredoc: bool = False       # a command of the unit opens a here-document
    code: bool = False          # a command that is not a plain declaration (`x=1`, `export`, `declare`, ...)
    substituted: bool = False   # a substitution is run by the unit (its commands follow the main ones, `inside=True`)
    ok: bool = True             # False for a statement the grammar could not read; `text` is then its source
    function: str | None = None # the function it is defined in


class Step(NamedTuple):
    """One command of a PKGBUILD / install script, already understood (what strict.py and activity.py read)."""
    line: int
    text: str
    top: bool                    # outside every function: runs when the file is merely parsed
    in_function: bool
    in_array: bool
    toplevel_code: bool          # a top-level command that is not a plain declaration
    commands: list               # commands inside functions
    ok: bool                     # False for a statement the shell grammar could not read
    parse_time: list             # commands inside substitutions that run at parse time
    parse_time_substitution: bool
    heredoc: bool                # the command opens a here-document


def steps(units_: list) -> list[Step]:
    """The steps of a file from its units. At the top level a command is not run by makepkg's parse (only
    its substitutions are), so the commands of a top-level step are those inside substitutions."""
    out = []
    for unit in units_:
        commands = [c for c, _ in unit.commands]
        if unit.top:
            inside = [c for c in commands if c.inside]
            out.append(Step(unit.line, unit.text, True, False, False, unit.code and unit.ok, [], unit.ok, inside,
                            unit.substituted, unit.heredoc))
        else:
            out.append(Step(unit.line, unit.text, False, True, False, False, commands, unit.ok, [], False, unit.heredoc))
    return out


class _Counter:
    def __init__(self) -> None:
        self.value = 0

    def take(self, n: int = 1) -> int:
        first = self.value
        self.value += n
        return first


# ---- text of a node (for messages) ----

def render(node) -> str:
    """The node as one line of shell, the words as they were written. For messages, not for parsing."""
    if isinstance(node, Statement):
        return render(node.node) + (" &" if node.background else "")
    if isinstance(node, Simple):
        bits = [_assign_text(a) for a in node.assigns] + [w.raw for w in node.words] + [_redirect_text(r) for r in node.redirects]
        return " ".join(bits)
    if isinstance(node, Pipeline):
        joiner = " | "
        return ("! " if node.negated else "") + joiner.join(render(c) for c in node.commands)
    if isinstance(node, AndOr):
        return render(node.first) + "".join(f" {op} {render(n)}" for op, n in node.rest)
    if isinstance(node, Group):
        return "{ " + "; ".join(render(s) for s in node.body.items) + "; }"
    if isinstance(node, Subshell):
        return "( " + "; ".join(render(s) for s in node.body.items) + " )"
    if isinstance(node, If):
        text = "; ".join(f"{'if' if i == 0 else 'elif'} {'; '.join(render(s) for s in c.items)}; then {'; '.join(render(s) for s in b.items)}"
                         for i, (c, b) in enumerate(node.branches))
        if node.orelse is not None:
            text += "; else " + "; ".join(render(s) for s in node.orelse.items)
        return text + "; fi"
    if isinstance(node, While):
        return f"{'until' if node.until else 'while'} {'; '.join(render(s) for s in node.condition.items)}; do {'; '.join(render(s) for s in node.body.items)}; done"
    if isinstance(node, For):
        head = f"(({node.arith}))" if node.arith is not None else node.variable + ("" if node.items is None else " in " + " ".join(w.raw for w in node.items))
        return f"{'select' if node.select else 'for'} {head}; do {'; '.join(render(s) for s in node.body.items)}; done"
    if isinstance(node, Case):
        return f"case {node.word.raw} in " + " ".join(f"{'|'.join(p.raw for p in c.patterns)}) ...;;" for c in node.clauses) + " esac"
    if isinstance(node, FunctionDef):
        return f"{node.name}() {render(node.body)}"
    if isinstance(node, Conditional):
        return "[[ " + " ".join(w.raw for w in node.words) + " ]]"
    if isinstance(node, ArithCommand):
        return f"(({node.expression}))"
    if isinstance(node, Unparsed):
        return node.text
    return ""


def _assign_text(assign) -> str:
    index = f"[{assign.index}]" if assign.index is not None else ""
    value = "(" + " ".join(w.raw for w in assign.array) + ")" if assign.array is not None else assign.value.raw
    return f"{assign.name}{index}{'+' if assign.append else ''}={value}"


def _redirect_text(redirect) -> str:
    target = redirect.target
    shown = f"{target.delimiter}" if isinstance(target, HereDoc) else target.raw
    return f"{redirect.fd or ''}{redirect.op}{shown}"


# ---- words ----

def word_text(word: Word) -> str:
    """A word the way the command checkers read it. `\\;` (the end of a `find -exec`) is `__SEMI__`."""
    if word.raw == "\\;":
        return "__SEMI__"
    return word.text()


def _word_holders(node: Simple):
    """Every word of a simple command that can hold a substitution."""
    yield from node.words
    for assign in node.assigns:
        if assign.value is not None:
            yield assign.value
        if assign.array:
            yield from assign.array
    for redirect in node.redirects:
        if isinstance(redirect.target, Word):
            yield redirect.target


def _redirect_pairs(node: Simple) -> tuple:
    """(operator, target) as the checkers always had them: a descriptor on either side of a duplication
    (`2>&1`, `>&-`) is not a file and a here-document is not a path."""
    pairs = []
    for redirect in node.redirects:
        if isinstance(redirect.target, HereDoc):
            continue
        text = word_text(redirect.target)
        if text == "-" or text.isdigit():
            continue
        pairs.append((redirect.op, text))
    return tuple(pairs)


def _commands(node: Simple, segment: int, piped: bool, inside: bool) -> list[Command]:
    found = _segment([word_text(w) for w in node.words], piped)
    pairs = _redirect_pairs(node)
    if pairs:
        if found:
            found[0] = found[0]._replace(redirects=pairs)
        else:
            found = [Command(":", [], piped, pairs)]
    return [c._replace(segment=segment, inside=inside) for c in found]


# ---- walking a statement ----

class _Collector:
    """The commands of one unit, and the substitutions still to be read after the main ones."""

    def __init__(self, counter: _Counter, inside: bool):
        self.counter = counter
        self.inside = inside
        self.found: list[tuple[Command, int]] = []
        self.subs: list = []

    def note(self, words) -> None:
        for word in words:
            self.subs.extend(word.substitutions)

    def node(self, node, segment: int, piped: bool) -> None:
        """Add every command in `node` as part of one pipeline stage."""
        if isinstance(node, Simple):
            self.note(_word_holders(node))
            for redirect in node.redirects:
                if isinstance(redirect.target, HereDoc):
                    self.subs.extend(redirect.target.expansions)
            for command in _commands(node, segment, piped, self.inside):
                self.found.append((command, node.line))
        elif isinstance(node, Statement):
            self.node(node.node, segment, piped)
        elif isinstance(node, Script):
            for item in node.items:
                self.node(item, segment, piped)
        elif isinstance(node, Pipeline):
            base = self.counter.take(len(node.commands))
            for index, command in enumerate(node.commands):
                self.node(command, base + index, index > 0)
        elif isinstance(node, AndOr):
            self.node(node.first, segment, piped)
            for _, operand in node.rest:
                self.node(operand, segment, piped)
        elif isinstance(node, (Group, Subshell)):
            self.node(node.body, segment, piped)
            self._redirects(node)
        elif isinstance(node, If):
            for condition, body in node.branches:
                self.node(condition, segment, piped)
                self.node(body, segment, piped)
            if node.orelse is not None:
                self.node(node.orelse, segment, piped)
            self._redirects(node)
        elif isinstance(node, While):
            self.node(node.condition, segment, piped)
            self.node(node.body, segment, piped)
            self._redirects(node)
        elif isinstance(node, For):
            self.note(node.items or ())
            self.node(node.body, segment, piped)
            self._redirects(node)
        elif isinstance(node, Case):
            self.note([node.word])
            for clause in node.clauses:
                self.note(clause.patterns)
                self.node(clause.body, segment, piped)
            self._redirects(node)
        elif isinstance(node, FunctionDef):
            self.node(node.body, segment, piped)
        elif isinstance(node, Conditional):
            self.note(node.words)
            self._redirects(node)
        elif isinstance(node, ArithCommand):
            self._redirects(node)

    def _redirects(self, node) -> None:
        for redirect in getattr(node, "redirects", ()):
            if isinstance(redirect.target, Word):
                self.note([redirect.target])
            elif isinstance(redirect.target, HereDoc):
                self.subs.extend(redirect.target.expansions)

    def statement(self, node) -> None:
        """One pipeline or command as its own stages, numbered one after the other."""
        if isinstance(node, Pipeline):
            self.node(node, 0, False)
        elif isinstance(node, (Simple,)):
            self.node(node, self.counter.take(), False)
        else:
            self.node(node, self.counter.take(), False)

    def drain(self) -> None:
        """Read the substitutions found so far, and those inside them, after the main commands."""
        inner = _Collector(self.counter, True)
        index = 0
        queue = self.subs
        while index < len(queue):
            sub = queue[index]
            index += 1
            inner.subs = queue
            inner.found = self.found
            for item in sub.script.items:
                inner.statement(item.node if isinstance(item, Statement) else item)
        self.subs = []


DECLARATIONS = frozenset({"export", "declare", "readonly", "unset", "typeset"})


def _has_heredoc(node) -> bool:
    return any(isinstance(r.target, HereDoc) for s in shast.walk(node) if isinstance(s, Simple) for r in s.redirects)


def _is_declaration(node) -> bool:
    """A command that only declares: `x=1`, `x=(..)`, `export X`, `declare -a y`, `unset z`."""
    if isinstance(node, Statement):
        node = node.node
    if not isinstance(node, Simple):
        return False
    return not node.words or node.words[0].value in DECLARATIONS


def _unit(node, line: int, top: bool, function: str | None = None) -> Unit:
    collector = _Collector(_Counter(), False)
    collector.statement(node)
    substituted = bool(collector.subs)
    collector.drain()
    return Unit(line, render(node), top, tuple((command, line) for command, _ in collector.found),
                _has_heredoc(node), not _is_declaration(node), substituted, True, function)


def _header(words, redirects, text: str, line: int, top: bool, function: str | None = None) -> Unit | None:
    """The substitutions in the part of a compound command that is not a statement (a `for` list, a
    `case` word, the target of a redirection): they run, so their commands are reported."""
    collector = _Collector(_Counter(), False)
    collector.note(words)
    for redirect in redirects:
        if isinstance(redirect.target, Word):
            collector.note([redirect.target])
        elif isinstance(redirect.target, HereDoc):
            collector.subs.extend(redirect.target.expansions)
    if not collector.subs:
        return None
    collector.drain()
    return Unit(line, text, top, tuple((command, line) for command, _ in collector.found), substituted=True, function=function)


def units(script: Script) -> tuple[list[Unit], set[int]]:
    """The units of a script in source order, and the lines of the statements that could not be read."""
    found: list[Unit] = []
    bad: set[int] = set()

    def visit(node, function: str | None) -> None:
        top = function is None
        if isinstance(node, Statement):
            visit(node.node, function)
        elif isinstance(node, Script):
            for item in node.items:
                visit(item, function)
        elif isinstance(node, (Simple, Pipeline)):
            found.append(_unit(node, node.line, top, function))
        elif isinstance(node, AndOr):
            visit(node.first, function)
            for _, operand in node.rest:
                visit(operand, function)
        elif isinstance(node, (Group, Subshell)):
            visit(node.body, function)
            _add(_header((), node.redirects, render(node), node.line, top, function))
        elif isinstance(node, If):
            for condition, body in node.branches:
                visit(condition, function)
                visit(body, function)
            if node.orelse is not None:
                visit(node.orelse, function)
            _add(_header((), node.redirects, render(node), node.line, top, function))
        elif isinstance(node, While):
            visit(node.condition, function)
            visit(node.body, function)
            _add(_header((), node.redirects, render(node), node.line, top, function))
        elif isinstance(node, For):
            _add(_header(node.items or (), node.redirects, render(node), node.line, top, function))
            visit(node.body, function)
        elif isinstance(node, Case):
            _add(_header([node.word, *(p for c in node.clauses for p in c.patterns)], node.redirects, render(node), node.line, top, function))
            for clause in node.clauses:
                visit(clause.body, function)
        elif isinstance(node, FunctionDef):
            visit(node.body, node.name)
        elif isinstance(node, Conditional):
            _add(_header(node.words, node.redirects, render(node), node.line, top, function))
        elif isinstance(node, ArithCommand):
            _add(_header((), node.redirects, render(node), node.line, top, function))
        elif isinstance(node, Unparsed):
            bad.update(range(node.line, node.end + 1))
            found.append(Unit(node.line, node.text, top, (), ok=False, function=function))

    def _add(unit: Unit | None) -> None:
        if unit is not None:
            found.append(unit)

    visit(script, None)
    return found, bad


def flatten(text: str) -> tuple[tuple, bool]:
    """All the commands of a command string (the payload of `sh -c`, `eval`, `su -c`) as one group, in the
    numbering `extract_commands` would give them. The second value is False when the string did not parse."""
    result = shast.parse(text)
    collector = _Collector(_Counter(), False)
    for item in result.script.items:
        collector.statement(item.node)
    collector.drain()
    return tuple(command for command, _ in collector.found), result.ok


def loose(text: str) -> tuple:
    """The commands of a string that is not valid shell (the payload of `sh -c` can be anything): cut at the
    operators and read each piece as one command. Used only when `flatten` could not parse the string."""
    import shlex
    try:
        lexer = shlex.shlex(text.replace(r"\;", " __SEMI__ "), posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return ()
    found: list[Command] = []
    words: list[str] = []
    piped = False
    stage = 0

    def flush(next_piped: bool) -> None:
        nonlocal words, piped, stage
        if words:
            found.extend(c._replace(segment=stage) for c in _segment(words, piped))
            stage += 1
        words, piped = [], next_piped

    for token in tokens:
        if token and set(token) <= set(";&|()"):
            flush(token in ("|", "|&"))
        else:
            words.append(token)
    flush(False)
    return tuple(found)
