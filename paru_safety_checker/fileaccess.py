"""Which files a parsed command reads, writes or deletes.

Works on a `Command` (name, arguments with quotes removed, redirections), never on text, so
`"cp" a "/etc/x"`, `c''p a /etc/x` and `cp a /e""tc/x` all read the same. Used by the activity
report and by the structured rules in cmdrules.py.
"""
from __future__ import annotations

import re

from .parsed import expand
from .strict import Command, normalise

PATHLESS = frozenset("echo printf true false : test export unset local declare readonly set shift return exit read let wait hash type shopt".split())
WRITE_LAST = frozenset({"cp", "mv", "install", "ln", "rsync"})
WRITE_ALL = frozenset({"tee", "touch", "mkdir", "chmod", "chown", "chgrp", "chattr", "truncate", "mkfifo", "patch"})
DELETE = frozenset({"rm", "rmdir", "unlink", "shred"})
SCRIPT_FIRST = frozenset({"sed", "grep", "egrep", "fgrep", "awk", "perl"})
EXTRACTORS = frozenset({"tar", "bsdtar", "unzip", "cpio", "7z", "7za"})
FILE_COMMANDS = WRITE_LAST | WRITE_ALL | DELETE | frozenset(
    "cat ls head tail stat readlink sed grep egrep fgrep awk wc sort diff cmp find tar unzip cd pushd".split()
)
OUTPUT_OPTIONS = frozenset({"-o", "--output", "-t", "--target-directory", "--destdir", "--root"})
ACCESS_OPTIONS = frozenset({"-C", "-d", "--directory"})
PATH_ASSIGNMENTS = re.compile(r"^(?:DESTDIR|INSTALL_ROOT|ROOT)=(.*)$")
ROUTINE_VARS = frozenset({"srcdir", "pkgdir", "startdir"})
HARMLESS_TARGETS = frozenset({"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "-"})


def _looks_like_path(arg: str, hook: bool = False, name: str = "") -> bool:
    if re.match(r"^\w+://", arg):
        return False
    if arg.startswith(("/", "~", "./", "../", "$")) or "/" in arg:
        return True
    # An install hook runs with the live system as its working directory, so a bare name is a real file.
    return (hook and name in FILE_COMMANDS and not re.fullmatch(r"\d+|[+=-]?[ugoa]*[+=-][rwxXst]+", arg))


def _extracts(args: list[str]) -> bool:
    """tar/bsdtar/cpio/7z unpacking rather than listing or creating: `tar xf`, `-xzf`, `--extract`, `7z x`."""
    for arg in args:
        if arg == "--extract" or arg == "--get":
            return True
        if arg.startswith("--"):
            continue
        letters = arg[1:] if arg.startswith("-") else arg
        if re.fullmatch(r"[A-Za-z]+", letters) and ("x" in letters or letters in ("i",)):
            return True
        break
    return False


def file_accesses(command: Command, hook: bool = False) -> list[tuple[str, str]]:
    """(verb, path) pairs a command touches. Approximate: verbs come from a table of known tools."""
    name = normalise(command.name)
    found: list[tuple[str, str]] = []
    for op, target in command.redirects:
        if target in HARMLESS_TARGETS or op == "<<<":      # a here-string is text, not a file
            continue
        found.append(("read" if op == "<" else "access" if op == "<>" else "write", target))
    if name in PATHLESS:
        return found

    args = list(command.args)
    skip: set[int] = set()
    if name in SCRIPT_FIRST:
        flagged = [i for i, a in enumerate(args) if a in ("-e", "--expression", "-f", "--file") or (a.startswith("-e") and len(a) > 2)
                   or (name == "perl" and re.fullmatch(r"-[a-zA-Z]*e", a))]
        if flagged:
            for i in flagged:
                skip.update({i, i + 1})
        else:
            first = next((i for i, a in enumerate(args) if not a.startswith("-")), None)
            if first is not None:
                skip.add(first)

    extracting = name == "unzip" or (name in EXTRACTORS and _extracts(args))
    operands: list[int] = []
    for i, arg in enumerate(args):
        if i in skip or arg == "--":
            continue
        if arg.startswith("-"):
            key, _, value = arg.partition("=")
            verb = "write" if key in OUTPUT_OPTIONS else "access" if key in ACCESS_OPTIONS else None
            if verb == "access" and extracting:
                verb = "write"                      # tar -C DIR / unzip -d DIR: the files land there
            if name in ("7z", "7za") and arg.startswith("-o") and len(arg) > 2 and _looks_like_path(arg[2:], hook, name):
                found.append(("write", arg[2:]))
                continue
            if verb and value and _looks_like_path(value, hook, name):
                found.append((verb, value))
            elif verb and not value and i + 1 < len(args) and _looks_like_path(args[i + 1], hook, name):
                skip.add(i + 1)
                found.append((verb, args[i + 1]))
            continue
        assignment = PATH_ASSIGNMENTS.match(arg)
        if name == "dd" and arg.startswith(("of=", "if=")):
            found.append(("write" if arg.startswith("of=") else "read", arg[3:]))
        elif assignment:
            if assignment.group(1):
                found.append(("write", assignment.group(1)))
        else:
            operands.append(i)

    in_place = (name == "sed" and any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args)) or (
        name == "perl" and any(re.fullmatch(r"-[a-zA-Z]*i\S*", a) for a in args))
    has_target_dir = any(a == "-t" or a.startswith("--target-directory") for a in args)
    destination = operands[-1] if operands else None
    for index in operands:
        arg = args[index]
        if index in skip or arg in HARMLESS_TARGETS or not _looks_like_path(arg, hook, name):
            continue
        if name in DELETE:
            verb = "delete"
        elif name in WRITE_ALL or in_place:
            verb = "write"
        elif name in WRITE_LAST:
            verb = "write" if index == destination and not has_target_dir else "delete" if name == "mv" else "read"
        elif name == "find" and "-delete" in args:
            verb = "delete"
        else:
            verb = "read"
        found.append((verb, arg))
    return found


def classify_path(raw: str, variables: dict[str, str], hook: bool) -> tuple[bool, str]:
    """(routine, reason). Routine = inside the build directories; anything else is reported."""
    path = expand(raw, variables)
    if hook:
        return False, "install hook: runs as root on your system"
    if ".." in path.split("/"):
        return False, "path leaves the build directory (..)"
    if re.match(r"^(?:~|\$HOME|\$\{HOME\}|\$XDG_\w+)", path):
        return False, "your home directory"
    if path.startswith("/"):
        if path.startswith(("/tmp", "/var/tmp", "/dev/shm")):
            return False, "temporary directory"
        if path.startswith("/etc"):
            return False, "system configuration"
        if path.startswith(("/home", "/root")):
            return False, "home directory"
        if path.startswith(("/proc", "/sys", "/dev")):
            return False, "kernel or device files"
        if re.match(r"^/(?:usr|opt|bin|sbin|lib|lib64|var|boot|srv)\b", path):
            return False, "system directory"
        return False, "absolute path"
    match = re.match(r"^\$\{?(\w+)\}?", path)
    if match and match.group(1) not in ROUTINE_VARS:
        return False, f"path built from ${match.group(1)}, which could not be resolved"
    return True, ""
