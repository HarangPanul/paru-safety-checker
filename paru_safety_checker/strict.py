"""Default-deny review of PKGBUILD / *.install shell code.

The regex rules in heuristics.py look for known-bad patterns, so anything new passes them.
This module inverts that: every command the script runs must be on a list of ordinary
packaging tools, used in an ordinary way. Whatever cannot be recognised (an unknown command,
a command built from a variable, inline interpreter code, code at the top level, shell that
does not even parse) is reported, so that "not understood" can never end up as "safe".
"""
from __future__ import annotations

import re
import shlex
from typing import NamedTuple

from .models import Finding

BUILD_ALLOWED = frozenset("""
cd pushd popd pwd echo printf true false : test export unset local declare readonly set shopt shift return exit
hash type read let wait
ls cat cp mv rm mkdir rmdir ln install chmod chown chgrp touch find xargs sed grep egrep fgrep sort uniq head tail
wc tr cut tee basename dirname readlink realpath date nproc uname id which stat du df diff cmp patch
tar unzip zip bsdtar gzip gunzip bzip2 bunzip2 xz unxz zstd 7z 7za cpio ar strip objcopy objdump readelf nm
sha256sum sha512sum sha1sum md5sum b2sum cksum gpg gpgv
make gmake cmake ctest cpack ninja meson ./configure configure autoreconf autoconf automake autoheader libtoolize
aclocal gettextize intltoolize glib-gettextize scons qmake qmake6 qmake-qt5 xmkmf pkg-config pkgconf
gcc g++ cc c++ clang clang++ cpp ld ranlib as rustc cargo go gofmt
python pypy pypy3 pip pip3 poetry pdm uv node npm pnpm yarn ruby gem bundle perl php composer
java javac mvn gradle ant sbt dotnet dart flutter cabal stack ghc opam ocaml dune ocamlfind mix elixir erl rebar3
luarocks lua luajit nim nimble zig crystal shards dub dmd ldc2 swift valac vala
msgfmt msgmerge xgettext glib-compile-schemas glib-compile-resources desktop-file-validate desktop-file-install
appstreamcli xdg-icon-resource gtk-update-icon-cache update-desktop-database fc-cache mkfontscale mkfontdir
rsvg-convert convert magick sphinx-build doxygen asciidoctor help2man sass protoc flex bison yacc lex m4 nasm yasm
patchelf chrpath install-info makeinfo texi2any fakeroot
time nice env command timeout stdbuf ionice builtin
""".split())

# install hooks run as root on the live system: a much shorter list
HOOK_ALLOWED = frozenset("""
echo printf true false : test export unset local declare readonly set shift return exit read
rm mkdir rmdir ln cp mv chmod chown touch grep getent id cat
ldconfig update-desktop-database update-mime-database gtk-update-icon-cache gtk4-update-icon-cache
glib-compile-schemas fc-cache depmod systemd-sysusers systemd-tmpfiles systemctl udevadm
xdg-icon-resource xdg-desktop-menu xdg-mime gio gdk-pixbuf-query-loaders
""".split())

GIT_SAFE = frozenset("""rev-parse rev-list describe log show status config apply init add diff ls-files cat-file
symbolic-ref branch tag archive checkout reset am format-patch cherry-pick version""".split())
SED_SUBST = re.compile(
    r"s(?P<d>[^\w\s\\])(?:\\.|(?!(?P=d)).)*(?P=d)(?:\\.|(?!(?P=d)).)*(?P=d)(?P<flags>[A-Za-z0-9]*)"
)
TAR_EXEC_OPTIONS = re.compile(r"^--(?:to-command|checkpoint-action|use-compress-program|rsh-command|info-script|new-volume-script)")
RISKY_GIT_CONFIG = re.compile(r"(?i)^!|core\.(?:sshcommand|pager|editor|fsmonitor|hookspath)|credential\.helper|alias\.|filter\.\w+\.(?:clean|smudge)")
SEARCH_TOOLCHAIN_VARS = re.compile(r"\$\{?(?:CC|CXX|MAKE|AR|LD|PYTHON|CMAKE|CPP|STRIP)\}?")
INTERPRETERS = re.compile(r"^(?:python[\d.]*|pypy3?|perl|ruby|node|php|lua|luajit)$")
INLINE_FLAG = re.compile(r"^(?:-[A-Za-z]*[cCeErp]|--(?:eval|print|exec|command|execute))")
FUNCTION_DEF = re.compile(r"^(?:function\s+)?[A-Za-z_][\w:.-]*\s*\(\s*\)\s*")
HEREDOC = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_]\w*)\1")
REDIRECTS = frozenset({">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|", "<<-", "<>"})
SEGMENT_OPS = frozenset({";", ";;", "&&", "||", "|", "|&", "&", "(", ")"})
BENIGN_WRAPPERS = frozenset({"time", "nice", "env", "command", "fakeroot", "xvfb-run", "timeout", "stdbuf", "ionice", "builtin"})
STOP_WRAPPERS = frozenset({"sudo", "nohup", "setsid", "exec", "su", "doas", "chroot", "strace", "ltrace"})
SKIP_SEGMENT = frozenset({"fi", "done", "esac", "in", ";;", "for", "case", "select", "[[", "[", "test", "function"})
PREFIXES = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"})
XARGS_VALUE_FLAGS = frozenset({"-n", "-I", "-P", "-L", "-d", "-E", "-s", "-a", "-i"})


class Command(NamedTuple):
    name: str
    args: list[str]
    piped: bool


def logical_lines(text: str):
    """Yield (first line number, line) joining backslash continuations."""
    buf, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = number
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        yield start, buf + line
        buf = ""
    if buf:
        yield start, buf


def _match_paren(s: str, i: int) -> int:
    """Index of the ')' closing the '(' just before s[i], skipping quotes; len(s) if unbalanced."""
    depth, quote = 1, ""
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)


def strip_substitutions(s: str) -> tuple[str, list[str]]:
    """Replace $(...), `...`, <(...) and >(...) by a placeholder; return the inner command strings."""
    out: list[str] = []
    subs: list[str] = []
    i, quote = 0, ""
    while i < len(s):
        c = s[i]
        if c == "\\" and quote != "'":
            out.append(s[i:i + 2])
            i += 2
            continue
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = ""
            i += 1
            continue
        if c == "'" and not quote:
            quote = "'"
        elif c == '"':
            quote = "" if quote == '"' else '"'
        elif s.startswith("$((", i):
            end = _match_paren(s, i + 2)
            subs.extend(strip_substitutions(s[i + 3:end])[1])
            out.append("0")
            i = end + 2
            continue
        elif s.startswith("$(", i) or (not quote and s[i:i + 2] in ("<(", ">(")):
            start = i + 2
            end = _match_paren(s, start)
            subs.append(s[start:end])
            out.append("__SUB__")
            i = end + 1
            continue
        elif c == "`":
            end = s.find("`", i + 1)
            end = len(s) if end < 0 else end
            subs.append(s[i + 1:end])
            out.append("__SUB__")
            i = end + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), subs


def _xargs_target(args: list[str]) -> list[str]:
    i = 0
    while i < len(args):
        if args[i] in XARGS_VALUE_FLAGS:
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            return args[i:]
    return []


def _find_targets(args: list[str]) -> list[list[str]]:
    targets = []
    for i, arg in enumerate(args):
        if arg in ("-exec", "-execdir", "-ok", "-okdir"):
            rest = []
            for word in args[i + 1:]:
                if word in ("__SEMI__", "+"):
                    break
                rest.append(word)
            targets.append(rest)
    return targets


def _segment(words: list[str], piped: bool) -> list[Command]:
    words = list(words)
    while words:
        word = words[0]
        if word in PREFIXES or re.match(r"^[A-Za-z_]\w*\+?=", word):
            words.pop(0)
        elif word in SKIP_SEGMENT:
            return []
        else:
            break
    if not words:
        return []
    commands: list[Command] = []
    while words:
        name, args = words[0], words[1:]
        commands.append(Command(name, args, piped))
        if name == "command" and args[:1] in (["-v"], ["-V"]):
            return commands
        if name not in BENIGN_WRAPPERS:
            break
        rest = list(args)
        while rest and (rest[0].startswith("-") or re.match(r"^[A-Za-z_]\w*=", rest[0]) or re.match(r"^\d+[smhd]?$", rest[0])):
            rest.pop(0)
        words = rest
    last = commands[-1]
    if last.name == "xargs":
        target = _xargs_target(last.args)
        if target:
            commands.extend(_segment(target, False))
    elif last.name == "find":
        for target in _find_targets(last.args):
            commands.extend(_segment(target, False))
    return commands


MAX_NESTING = 30


def extract_commands(text: str, _depth: int = 0) -> tuple[list[Command], bool]:
    """Every simple command in `text`, including those inside substitutions. ok=False if unparseable
    (including nesting deeper than MAX_NESTING, which only an attacker writes)."""
    if _depth > MAX_NESTING:
        return [], False
    text = text.replace(r"\;", " __SEMI__ ")
    outer, subs = strip_substitutions(text)
    outer = re.sub(r"\(\([^()]*\)\)", " ", outer)
    try:
        lexer = shlex.shlex(outer, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [], False

    commands: list[Command] = []
    segments: list[tuple[list[str], bool]] = []
    current: list[str] = []
    seg_piped = False
    open_parens = 0
    skip_next = False
    for token in tokens:
        if token in SEGMENT_OPS:
            if token == ")" and open_parens == 0:
                # a case pattern like `x86_64)` or `a|b)`: not a command
                if current and seg_piped:
                    while segments and segments[-1][1]:
                        segments.pop()
                    if segments:
                        segments.pop()
                current = []
                seg_piped = False
                continue
            if token == "(":
                open_parens += 1
            elif token == ")":
                open_parens -= 1
            if current:
                segments.append((current, seg_piped))
            current = []
            seg_piped = token in ("|", "|&")
            continue
        if token in REDIRECTS:
            skip_next = True
            if current and current[-1].isdigit():
                current.pop()
            continue
        if skip_next:
            skip_next = False
            continue
        current.append(token)
    if current:
        segments.append((current, seg_piped))

    ok = True
    for words, piped in segments:
        commands.extend(_segment(words, piped))
    for inner in subs:
        inner_commands, inner_ok = extract_commands(inner, _depth + 1)
        commands.extend(inner_commands)
        ok = ok and inner_ok
    return commands, ok


def _normalise(name: str) -> str:
    if name.startswith("/"):
        return name.rsplit("/", 1)[-1]
    return name


def _sed_script_is_active(args: list[str]) -> bool:
    """GNU sed can run commands (e) and write or read arbitrary files (w, r) from inside its script."""
    for arg in args:
        if arg.startswith("-") and not arg.startswith("-e"):
            continue
        script = arg[2:] if arg.startswith("-e") else arg
        if any(set(m.group("flags")) & set("ewW") for m in SED_SUBST.finditer(script)):
            return True
        rest = re.sub(r"/(?:\\.|[^/])*/", " ", SED_SUBST.sub(" ", script))
        if re.search(r"(?:^|[;{}]|\d|\$|\s)[ewWrR](?:\s|$|;)", rest):
            return True
    return False


def classify(command: Command, allowed: frozenset[str], local_functions: set[str]) -> tuple[str, str] | None:
    """(rule, message) if the command is not an ordinary packaging step, else None."""
    raw = command.name
    if raw == "__SUB__" or raw.startswith("$"):
        if SEARCH_TOOLCHAIN_VARS.fullmatch(raw):
            return None
        return "dynamic-command", f"Command is built at run time ({raw}), so what runs cannot be reviewed"
    name = _normalise(raw)
    if name in local_functions:
        return None
    if name == "sed" and _sed_script_is_active(command.args):
        return "inline-code", "sed script can run commands or write/read files (e, w, r)"
    if name == "find" and any(a in ("-fprint", "-fprint0", "-fprintf", "-fls") for a in command.args):
        return "inline-code", "find writes its output to a file"
    if name in ("tar", "bsdtar") and any(TAR_EXEC_OPTIONS.match(a) or a == "-I" for a in command.args):
        return "inline-code", f"{name} is told to run another program"
    if name == "git" and any(RISKY_GIT_CONFIG.search(a) for a in command.args):
        return "inline-code", "git is configured to run another program (alias, ssh command, filter, hook path)"
    if name == "git":
        args = list(command.args)
        while args[:1] == ["-C"]:
            args = args[2:]
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub in GIT_SAFE:
            return None
        return "unknown-command", f"git {sub or '(no subcommand)'} is not an ordinary local packaging step"
    if INTERPRETERS.match(name):
        for arg in command.args:
            if arg == "-m" or not arg.startswith("-"):
                break
            if INLINE_FLAG.match(arg):
                return "inline-code", f"{name} runs code given on the command line ({arg})"
        if command.piped:
            return "inline-code", f"{name} receives its program from a pipe"
        return None if (name in allowed or INTERPRETERS.match(name) and name.rstrip("0123456789.") in allowed) else (
            "unknown-command", f"Command not on the allowlist (default-deny): {name}")
    if name in allowed:
        return None
    return "unknown-command", f"Command not on the allowlist (default-deny): {name}"


def scan_strict(name: str, text: str) -> list[Finding]:
    allowed = HOOK_ALLOWED if name.endswith(".install") else BUILD_ALLOWED
    local_functions = set(re.findall(r"^\s*(?:function\s+)?([A-Za-z_][\w:.-]*)\s*\(\s*\)", text, re.M))
    local_functions |= set(re.findall(r"^\s*function\s+([A-Za-z_][\w:.-]*)", text, re.M))
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, message: str, line: int, key: str) -> None:
        if (rule, key) not in seen:
            seen.add((rule, key))
            findings.append(Finding("caution", message, name, line, rule))

    brace = paren = 0
    heredoc: str | None = None
    for number, line in logical_lines(text):
        stripped = line.strip()
        if heredoc is not None:
            if stripped == heredoc:
                heredoc = None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        top = brace == 0 and paren == 0
        in_function = brace > 0
        body = stripped
        if FUNCTION_DEF.match(body):
            body = FUNCTION_DEF.sub("", body, count=1)
        body = re.sub(r"^function\s+[A-Za-z_][\w:.-]*\s*", "", body)

        if top and body and not re.match(r"^(?:(?:export|declare|readonly|unset)\b|[A-Za-z_]\w*\+?=|\{|\}|\))", body):
            add("toplevel-code", f"Code outside any function runs when the file is merely parsed: {stripped[:100]}", number, str(number))
        if top or paren > 0:
            _, subs = strip_substitutions(body)
            for inner in subs:
                commands, _ = extract_commands(inner)
                label = commands[0].name if commands else inner.strip()[:30]
                add("parse-time-command", f"A command substitution runs at parse time ({label}): {stripped[:100]}", number, str(number))
        if in_function and body and not body.startswith(("{", "}")):
            commands, ok = extract_commands(body)
            if not ok:
                add("unparseable-shell", f"Shell that could not be parsed, so it was not reviewed: {stripped[:100]}", number, str(number))
            heredoc_match = HEREDOC.search(body)
            for command in commands:
                verdict = classify(command, allowed, local_functions)
                if verdict:
                    rule, message = verdict
                    add(rule, f"{message}: {stripped[:100]}", number, command.name if rule == "unknown-command" else str(number))
                elif heredoc_match and INTERPRETERS.match(_normalise(command.name)):
                    add("inline-code", f"{command.name} receives its program from a here-document: {stripped[:100]}", number, str(number))
        if in_function or top:
            match = HEREDOC.search(body)
            if match:
                heredoc = match.group(2)

        bare = re.sub(r"'[^']*'|\"[^\"]*\"", "", re.sub(r"\s#.*$", "", stripped))
        brace = max(0, brace + bare.count("{") - bare.count("}"))
        paren = max(0, paren + bare.count("(") - bare.count(")"))
    return findings
