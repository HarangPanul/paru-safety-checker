"""A syntax tree for shell scripts (PKGBUILD and *.install).

`preprocess.py` cuts a script into one command per line and `strict.extract_commands` splits those lines
into words with `shlex`. Both work on flat text, so every construct that nests (a pipe into a group, an
array inside a function, a command substitution in a word, a here-document) needed its own patch. This
module builds the tree instead: the checkers can ask what a command is *inside* instead of guessing
from the neighbouring tokens.

The tokenizer is the one preprocess.py already has (`_Scanner`): it knows how bash reads words, quotes,
expansions and here-documents, and it is what the cross-check against `bash --pretty-print` validates.
This module adds the grammar on top of those tokens and parses the inside of words (quotes,
`$(...)`, `${...}`, `$'...'`) into parts.

    parse(text) -> ParseResult(script, errors, comments)

Nothing here executes or expands anything. A statement the grammar cannot read becomes an `Unparsed`
node and the parser resumes at the next line, so one bad line does not hide the rest of the file.

Every node carries `line` and `end`, the first and last original line it covers (1-based).
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import Iterator

from .preprocess import MAX_NESTING, _Failure, _Scanner, _Tok

NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?(\+?)=(.*)$", re.S)
ARRAY_VALUE = re.compile(r"^\((.*)\)$", re.S)
PARAM_NAME = re.compile(r"^[!#]?([A-Za-z_][A-Za-z0-9_]*|\d+|[@*#?$!-])")
FD = re.compile(r"^(\d+)(.*)$")
CLOSERS = frozenset({"then", "else", "elif", "fi", "do", "done", "esac", "}"})
CASE_TERMINATORS = frozenset({";;", ";&", ";;&"})
ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
               "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


class ParseError(Exception):
    def __init__(self, message: str, line: int = 0):
        super().__init__(message)
        self.message = message
        self.line = line


# ---- nodes ----

@dataclass(frozen=True, kw_only=True)
class Node:
    line: int = 0
    end: int = 0


@dataclass(frozen=True)
class Lit(Node):
    text: str
    quoted: bool = False            # inside '...' or "...": no globbing, no word splitting


@dataclass(frozen=True)
class Param(Node):
    raw: str                        # `$x`, `${x:-y}`
    name: str                       # the variable, "" if it could not be read
    subs: tuple = ()                # substitutions inside, e.g. ${x:-$(cmd)}
    quoted: bool = False


@dataclass(frozen=True)
class CmdSub(Node):
    script: "Script"
    raw: str
    backtick: bool = False
    quoted: bool = False


@dataclass(frozen=True)
class ProcSub(Node):
    script: "Script"
    raw: str
    direction: str = "<"            # `<(...)` or `>(...)`


@dataclass(frozen=True)
class Arith(Node):
    raw: str                        # `$((1 + 2))`
    quoted: bool = False


@dataclass(frozen=True)
class Word(Node):
    raw: str                        # as written
    parts: tuple

    @property
    def value(self) -> str:
        """The word with quotes removed and escapes resolved. Expansions stay as written (`$x`, `$(cmd)`)."""
        out = []
        for part in self.parts:
            out.append(part.text if isinstance(part, Lit) else part.raw)
        return "".join(out)

    @property
    def literal(self) -> bool:
        """True when nothing in the word is expanded at run time (no variable, substitution or arithmetic)."""
        return all(isinstance(p, Lit) for p in self.parts)

    @property
    def substitutions(self) -> tuple:
        found = []
        for part in self.parts:
            if isinstance(part, (CmdSub, ProcSub)):
                found.append(part)
            elif isinstance(part, Param):
                found.extend(part.subs)
        return tuple(found)


@dataclass(frozen=True)
class HereDoc(Node):
    delimiter: str
    body: tuple                     # the lines between the operator line and the terminator
    strip_tabs: bool = False        # `<<-`
    quoted: bool = False            # `<<'EOF'`: the body is not expanded
    body_line: int = 0


@dataclass(frozen=True)
class Redirect(Node):
    op: str                         # > >> < << <<- <<< >& <& &> &>> >| <>
    fd: str | None
    target: "Word | HereDoc"


@dataclass(frozen=True)
class Assign(Node):
    name: str
    value: Word | None              # None for an array
    array: tuple | None = None      # the elements of `name=(...)`
    append: bool = False
    index: str | None = None        # `name[index]=...`


@dataclass(frozen=True)
class Simple(Node):
    assigns: tuple
    words: tuple
    redirects: tuple = ()

    @property
    def name(self) -> str | None:
        return self.words[0].value if self.words else None

    @property
    def args(self) -> tuple:
        return tuple(w.value for w in self.words[1:])


@dataclass(frozen=True)
class Pipeline(Node):
    commands: tuple
    negated: bool = False
    stderr: tuple = ()              # per pipe: True for `|&`


@dataclass(frozen=True)
class AndOr(Node):
    first: Node
    rest: tuple                     # ((`&&` | `||`, node), ...)


@dataclass(frozen=True)
class Statement(Node):
    node: Node
    background: bool = False


@dataclass(frozen=True)
class Script(Node):
    items: tuple


@dataclass(frozen=True)
class Group(Node):
    body: Script
    redirects: tuple = ()


@dataclass(frozen=True)
class Subshell(Node):
    body: Script
    redirects: tuple = ()


@dataclass(frozen=True)
class If(Node):
    branches: tuple                 # ((condition: Script, body: Script), ...) for if and each elif
    orelse: Script | None = None
    redirects: tuple = ()


@dataclass(frozen=True)
class While(Node):
    condition: Script
    body: Script
    until: bool = False
    redirects: tuple = ()


@dataclass(frozen=True)
class For(Node):
    variable: str
    items: tuple | None             # None for `for x; do` (the positional parameters)
    body: Script
    arith: str | None = None        # `for ((i=0; i<3; i++))`
    select: bool = False
    redirects: tuple = ()


@dataclass(frozen=True)
class CaseClause(Node):
    patterns: tuple
    body: Script
    terminator: str = ";;"


@dataclass(frozen=True)
class Case(Node):
    word: Word
    clauses: tuple
    redirects: tuple = ()


@dataclass(frozen=True)
class FunctionDef(Node):
    name: str
    body: Node


@dataclass(frozen=True)
class Conditional(Node):
    words: tuple                    # the words between `[[` and `]]`
    redirects: tuple = ()


@dataclass(frozen=True)
class ArithCommand(Node):
    expression: str                 # `((i++))`
    redirects: tuple = ()


@dataclass(frozen=True)
class Unparsed(Node):
    text: str
    reason: str = ""


@dataclass(frozen=True)
class ParseResult:
    script: Script
    errors: tuple                   # ((line, message), ...)
    comments: tuple                 # ((line, text), ...)

    @property
    def ok(self) -> bool:
        return not self.errors


# ---- inside words ----

def decode_ansi_c(text: str) -> str:
    """The value of `$'...'`: escapes resolved the way bash does."""
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c != "\\" or i + 1 >= len(text):
            out.append(c)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in ANSI_SIMPLE:
            out.append(ANSI_SIMPLE[nxt])
            i += 2
        elif nxt == "x" and (m := re.match(r"[0-9a-fA-F]{1,2}", text[i + 2:])):
            out.append(chr(int(m.group(), 16)))
            i += 2 + len(m.group())
        elif nxt in "01234567" and (m := re.match(r"[0-7]{1,3}", text[i + 1:])):
            out.append(chr(int(m.group(), 8) & 0xFF))
            i += 1 + len(m.group())
        elif nxt in "uU" and (m := re.match(r"[0-9a-fA-F]{1,%d}" % (4 if nxt == "u" else 8), text[i + 2:])):
            try:
                out.append(chr(int(m.group(), 16)))
            except (ValueError, OverflowError):
                out.append("\ufffd")
            i += 2 + len(m.group())
        elif nxt == "c" and i + 2 < len(text):
            out.append(chr(ord(text[i + 2]) & 0x1F))
            i += 3
        else:
            out.append("\\" + nxt)
            i += 2
    return "".join(out)


def _unescape_backticks(text: str) -> str:
    return re.sub(r"\\([\\`$])", r"\1", text)


class _Words:
    """Cuts the raw text of a word into parts. `nested` parses the commands of a substitution."""

    def __init__(self, nested, depth: int):
        self.nested = nested
        self.depth = depth

    def parts(self, raw: str, line: int, quoted: bool = False) -> tuple:
        if not any(c in raw for c in "\\'\"$`<>"):
            return (Lit(raw, quoted, line=line, end=line),) if raw else ()
        scanner = _Scanner(raw)
        parts: list = []
        buf: list[str] = []
        i, n = 0, len(raw)

        def flush() -> None:
            if buf:
                parts.append(Lit("".join(buf), quoted, line=line, end=line))
                buf.clear()

        def here(index: int) -> int:
            return line + raw.count("\n", 0, index)

        try:
            while i < n:
                c = raw[i]
                if c == "\\":
                    nxt = raw[i + 1] if i + 1 < n else ""
                    if quoted and nxt not in ('$', '`', '"', "\\", "\n"):
                        buf.append("\\" + nxt)
                    elif nxt != "\n":
                        buf.append(nxt if nxt else "\\")
                    i += 2
                elif c == "'" and not quoted:
                    j = raw.find("'", i + 1)
                    if j < 0:
                        raise ParseError("unterminated single quote", here(i))
                    flush()
                    parts.append(Lit(raw[i + 1:j], True, line=here(i), end=here(j)))
                    i = j + 1
                elif c == '"' and not quoted:
                    j = scanner._scan_dquote(i)
                    flush()
                    inner = self.parts(raw[i + 1:j - 1], here(i), quoted=True)
                    parts.extend(inner or (Lit("", True, line=here(i), end=here(i)),))
                    i = j
                elif c == "`":
                    j = scanner._scan_backtick(i)
                    flush()
                    inner = _unescape_backticks(raw[i + 1:j - 1])
                    parts.append(CmdSub(self.nested(inner, here(i)), raw[i:j], True, quoted, line=here(i), end=here(j)))
                    i = j
                elif c == "$":
                    i = self._dollar(raw, i, scanner, parts, buf, flush, here, quoted)
                elif c in "<>" and i == 0 and raw.startswith("(", 1) and not quoted:
                    j = scanner._scan_subst(2)
                    inner = raw[2:j - 1]
                    parts.append(ProcSub(self.nested(inner, here(0)), raw[:j], c, line=here(0), end=here(j)))
                    i = j
                else:
                    buf.append(c)
                    i += 1
        except _Failure as exc:
            raise ParseError(str(exc), line) from exc
        flush()
        return tuple(parts)

    def _dollar(self, raw, i, scanner, parts, buf, flush, here, quoted) -> int:
        n = len(raw)
        if raw.startswith("$((", i):
            j = scanner._scan_arith(i + 3)
            flush()
            parts.append(Arith(raw[i:j], quoted, line=here(i), end=here(j)))
            return j
        if raw.startswith("$(", i):
            j = scanner._scan_subst(i + 2)
            flush()
            parts.append(CmdSub(self.nested(raw[i + 2:j - 1], here(i)), raw[i:j], False, quoted, line=here(i), end=here(j)))
            return j
        if raw.startswith("${", i):
            j = scanner._scan_param(i + 2)
            flush()
            inner = raw[i + 2:j - 1]
            match = PARAM_NAME.match(inner)
            nested = self.parts(inner, here(i), quoted=True)
            subs = tuple(p for p in nested if isinstance(p, (CmdSub, ProcSub, Arith)))
            parts.append(Param(raw[i:j], match.group(1) if match else "", subs, quoted, line=here(i), end=here(j)))
            return j
        if raw.startswith("$'", i) and not quoted:
            j = scanner._scan_dollar(i)
            flush()
            parts.append(Lit(decode_ansi_c(raw[i + 2:j - 1]), True, line=here(i), end=here(j)))
            return j
        if raw.startswith('$"', i) and not quoted:
            j = scanner._scan_dquote(i + 1)
            flush()
            parts.extend(self.parts(raw[i + 2:j - 1], here(i), quoted=True) or ())
            return j
        match = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*|\d|[@*#?$!-])").match(raw, i)
        if match:
            flush()
            parts.append(Param(match.group(0), match.group(1), (), quoted, line=here(i), end=here(i)))
            return match.end()
        buf.append("$")
        return i + 1


# ---- the parser ----

class _Parser:
    def __init__(self, text: str, base_line: int = 1, depth: int = 0, errors: list | None = None):
        if depth > MAX_NESTING:
            raise ParseError("nesting too deep", base_line)
        self.depth = depth
        self.base = base_line - 1
        self.errors: list[tuple[int, str]] = errors if errors is not None else []
        self.scanner = _Scanner(text)
        try:
            tokens = self.scanner.tokenize("top")
        except (_Failure, RecursionError) as exc:
            raise ParseError(str(exc) or type(exc).__name__, base_line) from exc
        self.toks, self.heredocs = self._split_heredocs(tokens)
        self.next_heredoc = 0
        self.pos = 0
        self.words = _Words(self._nested, depth)

    # -- plumbing --

    @staticmethod
    def _split_heredocs(tokens: list[_Tok]):
        """The tokens without here-document bodies, and the bodies in order: (lines, terminator)."""
        clean: list[_Tok] = []
        groups: list[tuple] = []
        lines: list[tuple[int, str]] = []
        for tok in tokens:
            if tok.kind == "heredoc":
                lines.append((tok.start, tok.value))
            elif tok.kind == "heredoc-end":
                groups.append((tuple(lines), tok.value.strip("\t"), tok.start))
                lines = []
            else:
                clean.append(tok)
        return clean, groups

    def line_of(self, offset: int) -> int:
        return self.scanner.line_of(offset) + self.base

    def _nested(self, text: str, line: int) -> Script:
        parser = _Parser(text, line, self.depth + 1, self.errors)
        return parser.parse_program()

    def peek(self, ahead: int = 0) -> _Tok | None:
        index = self.pos + ahead
        return self.toks[index] if index < len(self.toks) else None

    def take(self) -> _Tok:
        tok = self.toks[self.pos]
        self.pos += 1
        return tok

    def fail(self, message: str, tok: _Tok | None = None) -> ParseError:
        tok = tok or self.peek()
        return ParseError(message, self.line_of(tok.start) if tok else self.last_line())

    def last_line(self) -> int:
        return self.line_of(self.toks[-1].end) if self.toks else self.base + 1

    def is_word(self, tok: _Tok | None, *values: str) -> bool:
        return tok is not None and tok.kind == "word" and tok.value in values

    def expect_word(self, value: str) -> _Tok:
        tok = self.peek()
        if not self.is_word(tok, value):
            raise self.fail(f"expected `{value}`" + (f", found `{tok.value}`" if tok else ", found end of input"), tok)
        return self.take()

    def skip_newlines(self) -> None:
        while (tok := self.peek()) is not None and tok.kind == "newline":
            self.pos += 1

    def skip_separators(self, after_statement: bool = False) -> None:
        """Newlines, and at most one `;` straight after a statement (`a;;` and `a ; ;` are syntax errors)."""
        allow = after_statement
        while (tok := self.peek()) is not None:
            if tok.kind == "newline":
                self.pos += 1
                allow = False
            elif tok.kind == "ctrl" and tok.value == ";" and allow:
                self.pos += 1
                allow = False
            else:
                break
        tok = self.peek()
        if tok is not None and tok.kind == "ctrl" and tok.value == ";":
            raise self.fail("unexpected `;`", tok)

    def end_line(self) -> int:
        return self.line_of(max(self.toks[self.pos - 1].start, self.toks[self.pos - 1].end - 1)) if self.pos else self.base + 1

    # -- lists --

    def parse_program(self) -> Script:
        script = self.parse_list(frozenset())
        if (tok := self.peek()) is not None:       # something the grammar could not place at the top level
            raise self.fail(f"unexpected `{tok.value}`", tok)
        return script

    def parse_body(self, stops: frozenset, rparen: bool = False) -> Script:
        """A list that bash requires to hold at least one command (`{ }`, `( )`, `then`, `do`, `else`)."""
        body = self.parse_list(stops, rparen)
        if not body.items:
            tok = self.peek()
            raise self.fail("expected a command" + (f" before `{tok.value}`" if tok else ""), tok)
        return body

    def _stops(self, tok: _Tok, stops: frozenset, rparen: bool, case: bool) -> bool:
        if tok.kind == "word":
            return tok.value in stops
        if tok.kind == "rparen":
            return rparen
        return tok.kind == "ctrl" and case and tok.value in CASE_TERMINATORS

    def parse_list(self, stops: frozenset, rparen: bool = False, case: bool = False) -> Script:
        items: list[Statement] = []
        first = self.peek()
        start_line = self.line_of(first.start) if first else self.base + 1
        after_statement = False
        while True:
            begin = self.pos
            try:
                self.skip_separators(after_statement)
                tok = self.peek()
                if tok is None or self._stops(tok, stops, rparen, case):
                    break
                begin = self.pos
                items.append(self.parse_statement())
                after_statement = not items[-1].background
                after = self.peek()
                if not items[-1].background and after is not None and after.kind not in ("newline", "ctrl", "rparen") \
                        and not self._stops(after, stops, rparen, case):
                    raise self.fail(f"unexpected `{after.value}`", after)
            except ParseError as error:
                items.append(self._recover(begin, error))
                after_statement = False
            if self.pos == begin:
                self.pos += 1
        end = items[-1].end if items else start_line
        return Script(tuple(items), line=start_line, end=end)

    def _recover(self, begin: int, error: ParseError) -> Statement:
        """Record the error and skip to the end of the line the bad statement started on."""
        self.errors.append((error.line, error.message))
        self.pos = max(self.pos, begin)
        start = self.toks[min(begin, len(self.toks) - 1)]
        line = self.line_of(start.start)
        while (tok := self.peek()) is not None and tok.kind != "newline":
            self.pos += 1
        last = self.toks[self.pos - 1] if self.pos > begin else start
        end = max(line, self.line_of(max(last.start, last.end - 1)))
        text = self.scanner.t[start.start:max(start.end, last.end)]
        return Statement(Unparsed(text, error.message, line=line, end=end), line=line, end=end)

    def parse_statement(self) -> Statement:
        first = self.peek()
        line = self.line_of(first.start)
        node = self.parse_and_or()
        background = False
        tok = self.peek()
        if tok is not None and tok.kind == "ctrl" and tok.value == "&":
            self.pos += 1
            background = True
            after = self.peek()
            if after is not None and after.kind == "ctrl" and after.value == ";":
                raise self.fail("unexpected `;` after `&`", after)
        return Statement(node, background, line=line, end=node.end)

    def parse_and_or(self) -> Node:
        first = self.parse_pipeline()
        rest = []
        while (tok := self.peek()) is not None and tok.kind == "ctrl" and tok.value in ("&&", "||"):
            self.pos += 1
            self.skip_newlines()
            rest.append((tok.value, self.parse_pipeline()))
        if not rest:
            return first
        return AndOr(first, tuple(rest), line=first.line, end=rest[-1][1].end)

    def parse_pipeline(self) -> Node:
        negated = False
        if self.is_word(self.peek(), "!"):
            self.pos += 1
            negated = True
        commands = [self.parse_command()]
        stderr = []
        while (tok := self.peek()) is not None and tok.kind == "pipe":
            self.pos += 1
            stderr.append(tok.value == "|&")
            self.skip_newlines()
            commands.append(self.parse_command())
        if len(commands) == 1 and not negated:
            return commands[0]
        return Pipeline(tuple(commands), negated, tuple(stderr), line=commands[0].line, end=commands[-1].end)

    # -- commands --

    def parse_command(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise self.fail("expected a command, found end of input")
        if tok.kind == "lparen":
            return self.parse_subshell()
        if tok.kind != "word":
            if tok.kind == "redir":
                return self.parse_simple()
            raise self.fail(f"unexpected `{tok.value}`", tok)
        value = tok.value
        if value in CLOSERS:
            raise self.fail(f"unexpected `{value}`", tok)
        if value == "if":
            return self.parse_if()
        if value in ("while", "until"):
            return self.parse_while()
        if value in ("for", "select"):
            return self.parse_for()
        if value == "case":
            return self.parse_case()
        if value == "{":
            return self.parse_group()
        if value == "[[":
            return self.parse_dbracket()
        if value == "function":
            return self.parse_function_keyword()
        if value.startswith("((") and value.endswith("))"):
            self.pos += 1
            line = self.line_of(tok.start)
            return ArithCommand(value[2:-2], self.parse_redirects(), line=line, end=self.end_line())
        nxt, after = self.peek(1), self.peek(2)
        if nxt is not None and nxt.kind == "lparen" and after is not None and after.kind == "rparen" \
                and not any(c in value for c in "=$`'\"\\"):
            return self.parse_function_def(value)
        return self.parse_simple()

    def parse_redirects(self) -> tuple:
        redirects = []
        while (tok := self.peek()) is not None and tok.kind == "redir":
            redirects.append(self.parse_redirect())
        return tuple(redirects)

    def parse_redirect(self) -> Redirect:
        tok = self.take()
        line = self.line_of(tok.start)
        match = FD.match(tok.value)
        fd, op = (match.group(1), match.group(2)) if match else (None, tok.value)
        target = self.peek()
        if target is None or target.kind != "word":
            raise self.fail(f"redirection `{tok.value}` has no target", target or tok)
        self.pos += 1
        if op in ("<<", "<<-"):
            return Redirect(op, fd, self._heredoc(op, target), line=line, end=self.end_line())
        return Redirect(op, fd, self.make_word(target), line=line, end=self.end_line())

    def _heredoc(self, op: str, tok: _Tok) -> HereDoc:
        raw = tok.value.replace("\\\n", "")
        quoted = bool(re.search(r"['\"\\]", raw))
        delimiter = re.sub(r"['\"\\]", "", raw)
        line = self.line_of(tok.start)
        body: tuple = ()
        body_line = line
        for index in range(self.next_heredoc, len(self.heredocs)):
            lines, terminator, _ = self.heredocs[index]
            if terminator == delimiter:
                body = tuple(text for _, text in lines)
                body_line = self.line_of(lines[0][0]) if lines else line + 1
                self.next_heredoc = index + 1
                break
        return HereDoc(delimiter, body, op == "<<-", quoted, body_line, line=line, end=line + len(body) + 1)

    def make_word(self, tok: _Tok) -> Word:
        line = self.line_of(tok.start)
        parts = self.words.parts(tok.value, line)
        return Word(tok.value, parts, line=line, end=self.line_of(max(tok.start, tok.end - 1)))

    def parse_simple(self) -> Simple:
        first = self.peek()
        line = self.line_of(first.start)
        assigns: list[Assign] = []
        words: list[Word] = []
        redirects: list[Redirect] = []
        while (tok := self.peek()) is not None:
            if tok.kind == "redir":
                redirects.append(self.parse_redirect())
            elif tok.kind == "word":
                if not words and (assign := self._assignment(tok)) is not None:
                    self.pos += 1
                    assigns.append(assign)
                else:
                    self.pos += 1
                    words.append(self.make_word(tok))
            elif tok.kind == "lparen":
                raise self.fail("unexpected `(`", tok)
            else:
                break
        if not (assigns or words or redirects):
            raise self.fail("expected a command")
        return Simple(tuple(assigns), tuple(words), tuple(redirects), line=line, end=self.end_line())

    def _assignment(self, tok: _Tok) -> Assign | None:
        match = ASSIGNMENT.match(tok.value)
        if not match:
            return None
        name, index, plus, value = match.groups()
        line = self.line_of(tok.start)
        end = self.line_of(max(tok.start, tok.end - 1))
        array = ARRAY_VALUE.match(value)
        if array:
            inner = array.group(1)
            offset = tok.start + len(tok.value) - len(value) + 1
            items = self._array_items(inner, self.line_of(offset))
            return Assign(name, None, items, bool(plus), index, line=line, end=end)
        parts = self.words.parts(value, line)
        word = Word(value, parts, line=line, end=end)
        return Assign(name, word, None, bool(plus), index, line=line, end=end)

    def _array_items(self, inner: str, line: int) -> tuple:
        scanner = _Scanner(inner)
        try:
            tokens = scanner.tokenize("top")
        except _Failure as exc:
            raise ParseError(str(exc), line) from exc
        items = []
        for tok in tokens:
            if tok.kind == "word":
                word_line = line + scanner.line_of(tok.start) - 1
                items.append(Word(tok.value, self.words.parts(tok.value, word_line), line=word_line,
                                  end=line + scanner.line_of(max(tok.start, tok.end - 1)) - 1))
        return tuple(items)

    # -- compound commands --

    def parse_group(self) -> Group:
        start = self.take()
        body = self.parse_body(frozenset({"}"}))
        self.expect_word("}")
        return Group(body, self.parse_redirects(), line=self.line_of(start.start), end=self.end_line())

    def parse_subshell(self) -> Subshell:
        start = self.take()
        body = self.parse_body(frozenset(), rparen=True)
        tok = self.peek()
        if tok is None or tok.kind != "rparen":
            raise self.fail("expected `)`", tok)
        self.pos += 1
        return Subshell(body, self.parse_redirects(), line=self.line_of(start.start), end=self.end_line())

    def parse_if(self) -> If:
        start = self.take()
        branches = []
        orelse = None
        while True:
            condition = self.parse_body(frozenset({"then"}))
            self.expect_word("then")
            body = self.parse_body(frozenset({"elif", "else", "fi"}))
            branches.append((condition, body))
            tok = self.peek()
            if self.is_word(tok, "elif"):
                self.pos += 1
                continue
            if self.is_word(tok, "else"):
                self.pos += 1
                orelse = self.parse_body(frozenset({"fi"}))
            break
        self.expect_word("fi")
        return If(tuple(branches), orelse, self.parse_redirects(), line=self.line_of(start.start), end=self.end_line())

    def parse_while(self) -> While:
        start = self.take()
        condition = self.parse_body(frozenset({"do"}))
        self.expect_word("do")
        body = self.parse_body(frozenset({"done"}))
        self.expect_word("done")
        return While(condition, body, start.value == "until", self.parse_redirects(),
                     line=self.line_of(start.start), end=self.end_line())

    def parse_for(self) -> For:
        start = self.take()
        select = start.value == "select"
        tok = self.peek()
        if tok is not None and tok.kind == "word" and tok.value.startswith("((") and tok.value.endswith("))"):
            self.pos += 1
            arith, variable, items = tok.value[2:-2], "", None
        else:
            if tok is None or tok.kind != "word" or not NAME.match(tok.value):
                raise self.fail("expected a variable name after `for`", tok)
            self.pos += 1
            variable, arith, items = tok.value, None, None
            self.skip_newlines()
            if self.is_word(self.peek(), "in"):
                self.pos += 1
                words = []
                while (word := self.peek()) is not None and word.kind == "word":
                    words.append(self.make_word(self.take()))
                items = tuple(words)
        self.skip_separators(True)
        self.expect_word("do")
        body = self.parse_body(frozenset({"done"}))
        self.expect_word("done")
        return For(variable, items, body, arith, select, self.parse_redirects(),
                   line=self.line_of(start.start), end=self.end_line())

    def parse_case(self) -> Case:
        start = self.take()
        subject = self.peek()
        if subject is None or subject.kind != "word":
            raise self.fail("expected a word after `case`", subject)
        self.pos += 1
        word = self.make_word(subject)
        self.skip_newlines()
        self.expect_word("in")
        clauses = []
        while True:
            self.skip_newlines()
            tok = self.peek()
            if tok is None:
                raise self.fail("expected `esac`")
            if self.is_word(tok, "esac"):
                self.pos += 1
                break
            clause_start = tok
            if tok.kind == "lparen":
                self.pos += 1
            patterns = []
            while True:
                pattern = self.peek()
                if pattern is None or pattern.kind != "word":
                    raise self.fail("expected a case pattern", pattern)
                self.pos += 1
                patterns.append(self.make_word(pattern))
                tok = self.peek()
                if tok is not None and tok.kind == "pipe":
                    self.pos += 1
                    continue
                break
            tok = self.peek()
            if tok is None or tok.kind != "rparen":
                raise self.fail("expected `)` after the case pattern", tok)
            self.pos += 1
            body = self.parse_list(frozenset({"esac"}), case=True)
            terminator = ";;"
            tok = self.peek()
            if tok is not None and tok.kind == "ctrl" and tok.value in CASE_TERMINATORS:
                terminator = tok.value
                self.pos += 1
            clauses.append(CaseClause(tuple(patterns), body, terminator, line=self.line_of(clause_start.start), end=self.end_line()))
        return Case(word, tuple(clauses), self.parse_redirects(), line=self.line_of(start.start), end=self.end_line())

    def parse_dbracket(self) -> Conditional:
        start = self.take()
        words = []
        while True:
            tok = self.peek()
            if tok is None:
                raise self.fail("expected `]]`")
            self.pos += 1
            if tok.kind == "word" and tok.value == "]]":
                break
            if tok.kind == "word":
                words.append(self.make_word(tok))
            elif tok.kind not in ("newline",):
                words.append(Word(tok.value, (Lit(tok.value, line=self.line_of(tok.start), end=self.line_of(tok.start)),),
                                  line=self.line_of(tok.start), end=self.line_of(tok.start)))
        return Conditional(tuple(words), self.parse_redirects(), line=self.line_of(start.start), end=self.end_line())

    def parse_function_def(self, name: str) -> FunctionDef:
        start = self.take()
        self.pos += 2                      # `(` `)`
        self.skip_newlines()
        return FunctionDef(name, self.parse_command(), line=self.line_of(start.start), end=self.end_line())

    def parse_function_keyword(self) -> FunctionDef:
        start = self.take()
        tok = self.peek()
        if tok is None or tok.kind != "word":
            raise self.fail("expected a function name after `function`", tok)
        self.pos += 1
        name = tok.value
        nxt, after = self.peek(), self.peek(1)
        if nxt is not None and nxt.kind == "lparen" and after is not None and after.kind == "rparen":
            self.pos += 2
        self.skip_newlines()
        return FunctionDef(name, self.parse_command(), line=self.line_of(start.start), end=self.end_line())


def parse(text: str) -> ParseResult:
    """Parse a shell script. Never raises: a script that cannot be tokenized comes back as one `Unparsed`."""
    errors: list[tuple[int, str]] = []
    try:
        parser = _Parser(text, 1, 0, errors)
        script = parser.parse_program()
        spans = sorted(parser.scanner.comments)
        comments = tuple((parser.scanner.line_of(a), text[a:b]) for a, b in spans)
        return ParseResult(script, tuple(errors), comments)
    except (ParseError, RecursionError) as exc:
        message = exc.message if isinstance(exc, ParseError) else "nesting too deep"
        line = exc.line if isinstance(exc, ParseError) else 1
        last = max(1, text.count("\n") + 1)
        whole = Statement(Unparsed(text, message, line=1, end=last), line=1, end=last)
        return ParseResult(Script((whole,), line=1, end=last), tuple(errors) + ((line, message),), ())


# ---- walking and printing ----

def children(node: Node) -> Iterator[Node]:
    """The nodes directly inside `node`, including the commands of substitutions in its words."""
    for field in dataclasses.fields(node):
        yield from _nodes_in(getattr(node, field.name))


def _nodes_in(value) -> Iterator[Node]:
    if isinstance(value, Node):
        yield value
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _nodes_in(item)


def walk(node: Node) -> Iterator[Node]:
    """`node` and everything inside it, parents before children, in source order."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(list(_node_children(current))))


def _node_children(node: Node):
    if isinstance(node, CmdSub) or isinstance(node, ProcSub):
        yield node.script
        return
    yield from children(node)


@dataclass(frozen=True)
class Located:
    node: Simple
    function: str | None            # the innermost function it is defined in, None at the top level
    substitution: bool              # inside `$(...)`, backticks or `<(...)`
    stage: int | None               # position in its pipeline, None when not piped
    stages: int                     # length of that pipeline (1 when not piped)


def simple_commands(root: Node) -> list[Located]:
    """Every simple command under `root` in source order, with where it sits."""
    found: list[Located] = []

    def visit(node, function, substitution, stage, stages):
        if isinstance(node, Simple):
            found.append(Located(node, function, substitution, stage, stages))
            for child in children(node):
                visit(child, function, substitution, None, 1)
        elif isinstance(node, Pipeline):
            for index, command in enumerate(node.commands):
                visit(command, function, substitution, index, len(node.commands))
        elif isinstance(node, FunctionDef):
            visit(node.body, node.name, substitution, None, 1)
        elif isinstance(node, (CmdSub, ProcSub)):
            visit(node.script, function, True, None, 1)
        else:
            for child in children(node):
                visit(child, function, substitution, None, 1)

    visit(root, None, False, None, 1)
    return found


def dump(node) -> str:
    """A compact s-expression, for tests and for reading the tree."""
    if isinstance(node, tuple):
        return " ".join(dump(n) for n in node)
    if node is None:
        return ""
    if isinstance(node, Script):
        return " ".join(dump(item) for item in node.items)
    if isinstance(node, Statement):
        inner = dump(node.node)
        return f"(& {inner})" if node.background else inner
    if isinstance(node, Word):
        return _dump_word(node)
    if isinstance(node, Simple):
        bits = [dump(a) for a in node.assigns] + [_dump_word(w) for w in node.words] + [dump(r) for r in node.redirects]
        return "(cmd " + " ".join(bits) + ")" if bits else "(cmd)"
    if isinstance(node, Assign):
        value = f"({' '.join(_dump_word(w) for w in node.array)})" if node.array is not None else _dump_word(node.value)
        index = f"[{node.index}]" if node.index is not None else ""
        return f"{node.name}{index}{'+' if node.append else ''}={value}"
    if isinstance(node, Redirect):
        target = node.target
        if isinstance(target, HereDoc):
            body = "|".join(target.body)
            return f"{node.fd or ''}{node.op}{target.delimiter}[{body}]"
        return f"{node.fd or ''}{node.op}{_dump_word(target)}"
    if isinstance(node, Pipeline):
        return f"({'!' if node.negated else ''}| " + " ".join(dump(c) for c in node.commands) + ")"
    if isinstance(node, AndOr):
        return "(list " + dump(node.first) + "".join(f" {op} {dump(n)}" for op, n in node.rest) + ")"
    if isinstance(node, Group):
        return "(group " + dump(node.body) + _dump_redirects(node.redirects) + ")"
    if isinstance(node, Subshell):
        return "(subshell " + dump(node.body) + _dump_redirects(node.redirects) + ")"
    if isinstance(node, If):
        parts = [f"(if {dump(c)} (then {dump(b)}))" if i == 0 else f"(elif {dump(c)} (then {dump(b)}))"
                 for i, (c, b) in enumerate(node.branches)]
        if node.orelse is not None:
            parts.append(f"(else {dump(node.orelse)})")
        return "(" + " ".join(parts) + _dump_redirects(node.redirects) + ")"
    if isinstance(node, While):
        return f"({'until' if node.until else 'while'} ({dump(node.condition)}) (do {dump(node.body)}){_dump_redirects(node.redirects)})"
    if isinstance(node, For):
        head = f"((({node.arith})))" if node.arith is not None else node.variable
        items = "" if node.items is None else " (in " + " ".join(_dump_word(w) for w in node.items) + ")"
        return f"({'select' if node.select else 'for'} {head}{items} (do {dump(node.body)}){_dump_redirects(node.redirects)})"
    if isinstance(node, Case):
        clauses = " ".join(f"(clause ({' '.join(_dump_word(p) for p in c.patterns)}) {dump(c.body)} {c.terminator})" for c in node.clauses)
        return f"(case {_dump_word(node.word)} {clauses}{_dump_redirects(node.redirects)})"
    if isinstance(node, FunctionDef):
        return f"(function {node.name} {dump(node.body)})"
    if isinstance(node, Conditional):
        return "(dbracket " + " ".join(_dump_word(w) for w in node.words) + _dump_redirects(node.redirects) + ")"
    if isinstance(node, ArithCommand):
        return f"(arith {node.expression!r}{_dump_redirects(node.redirects)})"
    if isinstance(node, Unparsed):
        return f"(unparsed {node.text!r})"
    raise TypeError(type(node).__name__)


def _dump_redirects(redirects: tuple) -> str:
    return "".join(" " + dump(r) for r in redirects)


def _dump_word(word: Word) -> str:
    out = []
    for part in word.parts:
        if isinstance(part, Lit):
            out.append(part.text)
        elif isinstance(part, CmdSub):
            out.append("$[" + dump(part.script) + "]")
        elif isinstance(part, ProcSub):
            out.append(part.direction + "[" + dump(part.script) + "]")
        else:
            out.append(part.raw)
    return "".join(out)
