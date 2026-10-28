"""How a parsed command is really invoked: the wrappers around it and what its arguments mean.

`sudo -u nobody env X=1 bash -s` is one `Command` named `sudo`; the program that runs is `bash`.
`views()` unwraps it so a rule asks "is this a shell reading its program from stdin?" once, instead
of every rule re-deriving it from text. Everything here works on words with the quotes already
removed, so `"ba"sh` and `bash` are the same word before any rule sees them.
"""
from __future__ import annotations

import re
from typing import Iterator

from .strict import Command, normalise

SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "csh", "tcsh", "busybox"})
INTERPRETER = re.compile(r"^(?:python[\d.]*|pypy3?|perl|ruby|node|php|lua|luajit)$")
FETCHERS = frozenset({"curl", "wget", "wget2", "aria2c", "axel", "http", "https", "xh"})
NETWORK_CLIENTS = frozenset({"nc", "ncat", "netcat", "telnet", "socat"})
PRIVILEGE = frozenset({"sudo", "su", "doas", "pkexec"})

# wrapper -> options that take a value (the value is not the program)
_WRAPPERS: dict[str, frozenset] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-U", "-r", "-t", "-C", "-D", "-R", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "nice": frozenset({"-n"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "timeout": frozenset({"-s", "-k"}),
    "nohup": frozenset(), "setsid": frozenset(), "time": frozenset(), "command": frozenset(),
    "builtin": frozenset(), "exec": frozenset(), "busybox": frozenset(),
    "xargs": frozenset({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "-J", "-R", "-S"}), "fakeroot": frozenset(), "xvfb-run": frozenset(),
}


def base(name: str) -> str:
    """The program name: no directory, so `/usr/bin/curl` and `curl` match."""
    return normalise(name)


def interpreter(name: str) -> bool:
    return bool(INTERPRETER.match(name))


def _unwrap(name: str, args: list[str]):
    wrapper = base(name)
    if wrapper not in _WRAPPERS:
        return None
    takes_value = _WRAPPERS[wrapper]
    i, duration = 0, wrapper != "timeout"
    while i < len(args):
        word = args[i]
        if word == "--":
            i += 1
            break
        if word.startswith("-") and len(word) > 1:
            i += 2 if word in takes_value else 1
        elif re.match(r"^[A-Za-z_]\w*=", word):
            i += 1
        elif not duration and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", word):
            duration = True
            i += 1
        else:
            break
    rest = args[i:]
    return (rest[0], rest[1:]) if rest else None


def views(command: Command) -> Iterator[Command]:
    """The command itself, then the program each wrapper would start (sudo -> env -> bash)."""
    seen = 0
    current = command
    yield current
    while seen < 8:
        inner = _unwrap(current.name, current.args)
        if inner is None:
            return
        current = current._replace(name=inner[0], args=list(inner[1]))
        seen += 1
        yield current


STDIN_PATHS = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})


def reads_program_from_stdin(name: str, args: list[str]) -> bool:
    """A shell or interpreter that takes its program from stdin: no script operand and no -c/-e/-m. `source`
    and `.` do when their file is /dev/stdin."""
    name = base(name)
    if name in ("source", "."):
        return any(a in STDIN_PATHS for a in args[:1])
    if name not in SHELLS and not interpreter(name):
        return False
    for arg in args:
        if arg in STDIN_PATHS:
            return True
        if arg == "--":
            continue
        if arg.startswith("--"):
            if name not in SHELLS and arg in ("--eval", "--command", "--exec"):
                return False
            continue
        if arg.startswith("-"):
            letters = arg[1:]
            if "c" in letters or (name not in SHELLS and ("e" in letters or "m" in letters)):
                return False
            if name in SHELLS and "s" in letters:
                return True
            continue
        return False
    return True


def payload(name: str, args: list[str]) -> str | None:
    """The command string a shell (`sh -c STR`), `su -c STR` or `eval STR` would run, if any."""
    name = base(name)
    if name == "eval":
        text = " ".join(args).strip()
        return text or None
    if name in SHELLS or name == "su":
        for index, arg in enumerate(args):
            if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:] and index + 1 < len(args):
                return args[index + 1]
            if not arg.startswith("-"):
                return None
    return None


def operands(args: list[str]) -> list[str]:
    """Arguments that are not options."""
    out, rest = [], False
    for arg in args:
        if not rest and arg == "--":
            rest = True
        elif rest or not arg.startswith("-") or arg == "-":
            out.append(arg)
    return out


def flags(args: list[str]) -> set[str]:
    """Single letters of short options (`-rf` -> r, f) and whole long options."""
    found: set[str] = set()
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("--"):
            found.add(arg.split("=", 1)[0])
        elif arg.startswith("-") and len(arg) > 1:
            found.update(arg[1:])
    return found
