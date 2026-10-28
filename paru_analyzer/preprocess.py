"""Shell preprocessing: remove comments and put every command on its own line.

This is the lexical layer. The pattern rules match its lines, the AI is shown its rendering, and
crosscheck.py compares it with bash, so layout tricks cannot hide anything from them: several
commands on one line, continuation lines, commands spread over many lines, comments in odd places.
The structure of a script (commands, pipes, assignments, functions) is not read from these lines: it
comes from the syntax tree in shast.py, which is built on this module's scanner.

One output line is one *command*. A pipeline (`a | b`) stays together, because the rules that look
for `curl | sh` need to see both sides; commands joined by `;`, `&&`, `||`, `&` or a newline are
split. A `$(...)` stays inline in the command that contains it. Control keywords (`if`, `then`,
`fi`, `{`, `}`, ...) are dropped; the command after `if` / `while` is kept. Every line carries the
number of the original line it started on, and whether it is inside a function.

The scanner mirrors how bash reads words, quotes, expansions, here-documents and comments. Because a
difference between this scanner and bash is exactly what an attacker would use to hide code, the
result is cross-checked against `bash --pretty-print` (see crosscheck.py). Anything the scanner
cannot parse is reported (`ok=False`) and the caller falls back to the raw lines.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import NamedTuple

ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
ARRAY_START = re.compile(r"^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=\(")
ARRAY_WORD_PREFIX = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
FD_PREFIX = re.compile(r"\d+(?=[<>])")
DROPPED = frozenset({"then", "else", "do", "fi", "done", "!"})
CONDITIONAL = frozenset({"if", "elif", "while", "until"})
MAX_NESTING = 40


class Line(NamedTuple):
    number: int      # original line the command starts on
    text: str        # the command, comments removed, on one line
    region: str      # "top" (runs when the file is parsed) or "function"
    kind: str        # command | assignment | array | function | control | case-pattern | heredoc | heredoc-end
    expands: bool = False   # heredoc body that the shell expands ($(...) and backticks run)
    end: int = 0     # original line the command ends on


@dataclass(frozen=True)
class Preprocessed:
    lines: tuple
    comments: tuple          # ((line, text), ...) of the comments that were removed
    ok: bool
    error: str = ""
    statements: tuple = ()   # ((line, text), ...) original lines with comments removed, continuations joined
    source_lines: tuple = () # the original file, line by line
    notes: tuple = ()        # things worth reporting that are not parse failures

    @property
    def commands(self):
        return [l for l in self.lines if l.kind in ("command", "assignment", "array", "control")]


class _Tok(NamedTuple):
    kind: str    # word newline ctrl pipe lparen rparen redir heredoc heredoc-end
    start: int
    end: int
    value: str
    expands: bool = False


class _Failure(Exception):
    pass


class _Scanner:
    def __init__(self, text: str):
        self.t = text
        self.n = len(text)
        self.i = 0
        self.comments: list[tuple[int, int]] = []
        self.sep_newlines: set[int] = set()
        self.pending: list[tuple[str, bool, bool]] = []   # (delimiter, strip tabs, expands)
        self.nesting = 0
        self.dbracket = False
        self.notes: list[str] = []
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    # ---- tokenizer ----

    def tokenize(self, mode: str = "top") -> list[_Tok]:
        """mode: top | subst (stop after the matching ')') | array (same, newlines are blanks)."""
        t, toks, depth = self.t, [], 0
        while self.i < self.n:
            c = t[self.i]
            if c in " \t":
                self.i += 1
            elif c == "\n":
                start = self.i
                self.i += 1
                toks.append(_Tok("newline", start, self.i, ""))
                if mode == "subst":
                    self.sep_newlines.add(start)
                if self.pending:
                    self._read_heredocs(toks)
            elif c == "\\" and t.startswith("\n", self.i + 1):
                self.i += 2
            elif c == "#":
                end = t.find("\n", self.i)
                end = self.n if end < 0 else end
                self.comments.append((self.i, end))
                self.i = end
            else:
                kind = None if self.dbracket else self._operator(toks, mode, depth)
                if kind is None:
                    toks.append(self._word())
                elif kind == "done":
                    return toks
                elif kind == "open":
                    depth += 1
                elif kind == "close":
                    depth -= 1
        if mode != "top":
            raise _Failure("unterminated ( ... )")
        if self.pending:                 # a here-document announced on the last line of the file
            self._read_heredocs(toks)
        return toks

    def _operator(self, toks, mode, depth):
        """Consume an operator at self.i. Returns None if there is none, or what happened."""
        t, i = self.t, self.i
        c = t[i]

        def emit(kind, length, value=None):
            toks.append(_Tok(kind, i, i + length, value if value is not None else t[i:i + length]))
            self.i = i + length

        for op in (";;&", ";;", ";&", ";"):
            if t.startswith(op, i):
                emit("ctrl", len(op))
                return "ctrl"
        if t.startswith("&>>", i) or t.startswith("&>", i):
            emit("redir", 3 if t.startswith("&>>", i) else 2)
            return "redir"
        if t.startswith("&&", i):
            emit("ctrl", 2)
            return "ctrl"
        if c == "&":
            emit("ctrl", 1)
            return "ctrl"
        if t.startswith("||", i):
            emit("ctrl", 2)
            return "ctrl"
        if t.startswith("|&", i):
            emit("pipe", 2)
            return "pipe"
        if c == "|":
            emit("pipe", 1)
            return "pipe"
        if c == "(":
            if t.startswith("((", i):
                end = self._scan_arith(i + 2)
                toks.append(_Tok("word", i, end, t[i:end]))
                self.i = end
                return "word"
            emit("lparen", 1)
            return "open"
        if c == ")":
            if mode != "top" and depth == 0:
                self.i = i + 1
                return "done"
            emit("rparen", 1)
            return "close" if depth > 0 else "rparen"
        if c in "<>":
            if t.startswith("(", i + 1):
                return None   # process substitution: a word
            for op in ("<<<", "<<-", "<<", "<&", "<>", "<", ">>", ">&", ">|", ">"):
                if t.startswith(op, i):
                    emit("redir", len(op))
                    if op in ("<<", "<<-"):
                        self._heredoc_delimiter(toks, strip=(op == "<<-"))
                    return "redir"
        m = FD_PREFIX.match(t, i)
        if m:
            j = m.end()
            for op in ("<<<", "<<-", "<<", "<&", "<>", "<", ">>", ">&", ">|", ">"):
                if t.startswith(op, j) and not t.startswith("(", j + 1):
                    toks.append(_Tok("redir", i, j + len(op), t[i:j + len(op)]))
                    self.i = j + len(op)
                    if op in ("<<", "<<-"):
                        self._heredoc_delimiter(toks, strip=(op == "<<-"))
                    return "redir"
        return None

    def _heredoc_delimiter(self, toks, strip: bool) -> None:
        while self.i < self.n and self.t[self.i] in " \t":
            self.i += 1
        if self.i >= self.n or self.t[self.i] in "\n;&|()<>":
            raise _Failure("here-document without a delimiter")
        word = self._word()
        toks.append(word)
        raw = word.value.replace("\\\n", "")        # a continuation inside the word joins it
        expands = not re.search(r"['\"\\]", raw)
        self.pending.append((re.sub(r"['\"\\]", "", raw), strip, expands))

    def _read_heredocs(self, toks) -> None:
        for delimiter, strip, expands in self.pending:
            while self.i < self.n:
                end = self.t.find("\n", self.i)
                stop = self.n if end < 0 else end
                text = self.t[self.i:stop]
                candidate = text.lstrip("\t") if strip else text
                start = self.i
                self.i = min(self.n, stop + 1)
                if candidate == delimiter:
                    toks.append(_Tok("heredoc-end", start, stop, text))
                    break
                toks.append(_Tok("heredoc", start, stop, text, expands))
            else:
                # bash treats the rest of the file as the body and supplies the terminator itself
                toks.append(_Tok("heredoc-end", self.n, self.n, delimiter))
                self.notes.append(f"here-document <<{delimiter} is never terminated: everything after it is data, not code")
        self.pending = []

    # ---- words and the things that can sit inside them ----

    def _word(self) -> _Tok:
        t, start = self.t, self.i
        i = start
        while i < self.n:
            c = t[i]
            if c in " \t\n":
                break
            if self.dbracket and c in ";&|()<>" and t[start:i] == "]]":
                break           # `]]` closes the conditional even when an operator follows it directly
            if not self.dbracket and c in ";&|()<>":
                if c in "<>" and i == start and t.startswith("(", i + 1):
                    i = self._scan_subst(i + 2)
                    continue
                if c == "(" and ARRAY_WORD_PREFIX.fullmatch(t[start:i]):
                    i = self._scan_array(i + 1)
                    continue
                break
            if c == "\\":
                i += 2
            elif c == "'":
                j = t.find("'", i + 1)
                if j < 0:
                    raise _Failure("unterminated single quote")
                i = j + 1
            elif c == '"':
                i = self._scan_dquote(i)
            elif c == "`":
                i = self._scan_backtick(i)
            elif c == "$":
                i = self._scan_dollar(i)
            else:
                i += 1
        self.i = min(i, self.n)
        value = t[start:self.i]
        if value == "[[":
            self.dbracket = True
        elif value == "]]":
            self.dbracket = False
        return _Tok("word", start, self.i, value)

    def _scan_dollar(self, i: int) -> int:
        t = self.t
        if t.startswith("$((", i):
            return self._scan_arith(i + 3)
        if t.startswith("$(", i):
            return self._scan_subst(i + 2)
        if t.startswith("${", i):
            return self._scan_param(i + 2)
        if t.startswith("$'", i):
            j = i + 2
            while j < self.n and t[j] != "'":
                j += 2 if t[j] == "\\" else 1
            if j >= self.n:
                raise _Failure("unterminated $'...'")
            return j + 1
        if t.startswith('$"', i):
            return self._scan_dquote(i + 1)
        return i + 1

    def _scan_dquote(self, i: int) -> int:
        t, j = self.t, i + 1
        while j < self.n:
            c = t[j]
            if c == "\\":
                j += 2
            elif c == '"':
                return j + 1
            elif c == "`":
                j = self._scan_backtick(j)
            elif c == "$":
                j = self._scan_dollar(j)
            else:
                j += 1
        raise _Failure("unterminated double quote")

    def _scan_backtick(self, i: int) -> int:
        t, j = self.t, i + 1
        while j < self.n:
            if t[j] == "\\":
                j += 2
            elif t[j] == "`":
                return j + 1
            else:
                j += 1
        raise _Failure("unterminated backtick")

    def _scan_param(self, j: int) -> int:
        t, depth = self.t, 1
        while j < self.n:
            c = t[j]
            if c == "\\":
                j += 2
            elif c == "'":
                k = t.find("'", j + 1)
                if k < 0:
                    raise _Failure("unterminated quote in ${...}")
                j = k + 1
            elif c == '"':
                j = self._scan_dquote(j)
            elif c == "`":
                j = self._scan_backtick(j)
            elif c == "$":
                if t.startswith("${", j):
                    depth += 1
                    j += 2
                else:
                    j = self._scan_dollar(j)
            elif c == "}":
                depth -= 1
                j += 1
                if depth == 0:
                    return j
            else:
                j += 1
        raise _Failure("unterminated ${...}")

    def _scan_arith(self, j: int) -> int:
        """After `((` or `$((`: scan to the matching `))`."""
        t, depth = self.t, 2
        while j < self.n:
            c = t[j]
            if c == "\\":
                j += 2
                continue
            if c in "'\"":
                j = self._scan_dquote(j) if c == '"' else (t.find("'", j + 1) + 1 or self.n + 1)
                continue
            if c == "$" and t.startswith("(", j + 1) and not t.startswith("((", j + 1):
                j = self._scan_subst(j + 2)
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise _Failure("unterminated (( ... ))")

    def _scan_subst(self, j: int) -> int:
        """After `$(`, `<(` or `>(`: scan the commands inside to the matching `)`."""
        return self._nested(j, "subst")

    def _scan_array(self, j: int) -> int:
        return self._nested(j, "array")

    def _nested(self, j: int, mode: str) -> int:
        self.nesting += 1
        if self.nesting > MAX_NESTING:
            raise _Failure("nesting too deep")
        saved_i, saved_pending, saved_db = self.i, self.pending, self.dbracket
        self.i, self.pending, self.dbracket = j, [], False
        try:
            self.tokenize(mode)
            end = self.i
            carried = self.pending      # announced inside, body starts after the outer line ends
        finally:
            self.nesting -= 1
            self.dbracket = saved_db
            self.i = saved_i
        self.pending = saved_pending + carried
        return end

    # ---- text of a command ----

    def text(self, start: int, end: int) -> str:
        """The source between two offsets, comments removed, newlines turned into blanks or `;`."""
        result = []
        for piece_start, piece_end in self._ranges(start, end):
            chunk = self.t[piece_start:piece_end]
            k = 0
            while k < len(chunk):
                ch = chunk[k]
                if ch == "\\" and chunk.startswith("\n", k + 1):
                    k += 2
                    continue
                if ch == "\n":
                    tail = "".join(result).rstrip()
                    separator = (piece_start + k) in self.sep_newlines and tail and tail[-1] not in "(;&|"
                    result.append("; " if separator else " ")
                else:
                    result.append(ch)
                k += 1
        return re.sub(r"[ \t]+", " ", "".join(result)).strip()

    def _ranges(self, start: int, end: int):
        pos = start
        index = bisect.bisect_left(self.comments, (start, -1))
        if index and self.comments[index - 1][1] > start:
            index -= 1
        while index < len(self.comments) and self.comments[index][0] < end:
            c_start, c_end = self.comments[index]
            if c_start > pos:
                yield pos, min(c_start, end)
            pos = max(pos, c_end)
            index += 1
        if pos < end:
            yield pos, end


# ---- grouping tokens into lines ----

def _is_plain(tok: _Tok, word: str) -> bool:
    return tok.kind == "word" and tok.value == word


def _build(scanner: _Scanner, toks: list[_Tok]) -> list[Line]:
    out: list[Line] = []
    cur: list[_Tok] = []
    regions: list[str] = []
    cases: list[str] = []          # "patterns" | "body" for every open case
    pending_function = False

    def region() -> str:
        return "function" if any(r.startswith("function") for r in regions) else "top"

    def emit(tokens: list[_Tok], kind: str | None = None, text: str | None = None, expands: bool = False) -> None:
        if not tokens:
            return
        start, end = tokens[0].start, tokens[-1].end
        body = scanner.text(start, end) if text is None else text
        if not body:
            return
        if kind is None:
            words = [x.value for x in tokens if x.kind == "word"]
            if words and ARRAY_START.match(words[0]):
                kind = "array"
            elif words and all(ASSIGNMENT.match(w) for w in words):
                kind = "assignment"
            else:
                kind = "command"
        out.append(Line(scanner.line_of(start), body, region(), kind, expands, scanner.line_of(max(start, end - 1))))

    def flush() -> None:
        nonlocal cur
        emit(cur)
        cur = []

    i, n = 0, len(toks)
    while i < n:
        tok = toks[i]
        kind = tok.kind
        if kind in ("heredoc", "heredoc-end"):
            flush()
            out.append(Line(scanner.line_of(tok.start), tok.value, region(), kind, tok.expands, scanner.line_of(tok.start)))
        elif kind == "newline":
            if not (cur and cur[-1].kind == "pipe"):
                flush()
        elif kind == "ctrl":
            flush()
            if tok.value in (";;", ";&", ";;&") and cases:
                cases[-1] = "patterns"
        elif cases and cases[-1] == "patterns" and not cur and kind == "word" and tok.value == "esac":
            cases.pop()
        elif cases and cases[-1] == "patterns":
            # a case pattern: everything up to the ')' that closes it
            pattern = []
            while i < n and toks[i].kind != "rparen":
                if toks[i].kind not in ("newline", "lparen"):
                    pattern.append(toks[i])
                i += 1
            emit(pattern, kind="case-pattern")
            cases[-1] = "body"
        elif kind == "pipe" or kind == "redir":
            cur.append(tok)
        elif kind == "lparen":
            nxt = toks[i + 1] if i + 1 < n else None
            if len(cur) == 1 and cur[0].kind == "word" and nxt is not None and nxt.kind == "rparen":
                emit(cur, kind="function", text=scanner.text(cur[0].start, nxt.end))
                cur = []
                i += 1
                pending_function = True
            elif not cur:
                regions.append("function-sub" if pending_function else "subshell")
                pending_function = False
            else:
                cur.append(tok)
        elif kind == "rparen":
            if not cur and regions and regions[-1] in ("subshell", "function-sub"):
                regions.pop()
            elif regions and regions[-1] in ("subshell", "function-sub"):
                flush()
                regions.pop()
            else:
                cur.append(tok)
        else:  # word
            if cur:
                cur.append(tok)
            else:
                word = tok.value
                if word in DROPPED or word in CONDITIONAL:
                    pass
                elif word == "esac":
                    if cases:
                        cases.pop()
                elif word == "{":
                    regions.append("function" if pending_function else "group")
                    pending_function = False
                elif word == "}":
                    if regions and regions[-1] in ("group", "function"):
                        regions.pop()
                elif word == "function":
                    j = i + 1
                    header = [tok]
                    while j < n and toks[j].kind not in ("newline", "ctrl") and not _is_plain(toks[j], "{"):
                        header.append(toks[j])
                        j += 1
                    name = next((h.value for h in header[1:] if h.kind == "word"), "")
                    out.append(Line(scanner.line_of(tok.start), f"{name}()", region(), "function", False, scanner.line_of(tok.start)))
                    pending_function = True
                    i = j - 1
                elif word in ("for", "select"):
                    j = i
                    header = []
                    while j < n and toks[j].kind not in ("newline",) and not (toks[j].kind == "ctrl") and not _is_plain(toks[j], "do"):
                        header.append(toks[j])
                        j += 1
                    emit(header, kind="control")
                    i = j - 1
                elif word == "case":
                    j = i
                    header = []
                    while j < n and not _is_plain(toks[j], "in"):
                        header.append(toks[j])
                        j += 1
                    header.append(toks[j]) if j < n else None
                    emit(header, kind="control")
                    cases.append("patterns")
                    i = j
                else:
                    cur.append(tok)
        i += 1
    flush()
    return out


def _statements(text: str, comment_spans) -> tuple:
    chars = list(text)
    for start, end in comment_spans:
        for k in range(start, end):
            chars[k] = ""
    out, buf, first = [], "", 0
    for number, line in enumerate("".join(chars).split("\n"), 1):
        if not buf:
            first = number
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        joined = (buf + line).strip()
        if joined:
            out.append((first, joined))
        buf = ""
    if buf.strip():
        out.append((first, buf.strip()))
    return tuple(out)


def _fallback(text: str, error: str) -> Preprocessed:
    """Could not parse: every physical line, comments kept, treated as function code (the strictest reading)."""
    lines = tuple(
        Line(number, raw.strip(), "function", "command", False, number)
        for number, raw in enumerate(text.splitlines(), 1) if raw.strip()
    )
    plain = tuple((number, raw.strip()) for number, raw in enumerate(text.split("\n"), 1) if raw.strip())
    return Preprocessed(lines, (), False, error, plain, tuple(text.split("\n")))


@lru_cache(maxsize=256)
def preprocess(text: str) -> Preprocessed:
    scanner = _Scanner(text)
    try:
        toks = scanner.tokenize("top")
        lines = _build(scanner, toks)
    except (_Failure, RecursionError) as exc:
        return _fallback(text, str(exc) or type(exc).__name__)
    spans = sorted(scanner.comments)
    comments = tuple((scanner.line_of(a), text[a:b]) for a, b in spans)
    return Preprocessed(tuple(lines), comments, True, "", _statements(text, spans), tuple(text.split("\n")), tuple(scanner.notes))


def render(pre: Preprocessed) -> str:
    """The preprocessed file as text, every line prefixed with its original line number."""
    return "\n".join(f"{line.number}: {line.text}" for line in pre.lines)
