"""Inventory of what a package script does, reported to the user whether or not it looks bad.

Findings (heuristics.py, strict.py) answer "is this suspicious?". The inventory answers
"what does it do?": every download, every file touched outside the build directories, every
command, and everything that runs when the PKGBUILD is merely parsed or an install hook runs
as root. Routine file operations inside $srcdir / $pkgdir are collected too but collapsed in
the display unless the user asks for them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .heuristics import RULES, _applies, _expand, _variables, source_entries
from .strict import Command, normalise, walk

NETWORK_RULE_IDS = frozenset({
    "build-time-download", "vcs-fetch", "dependency-fetch", "registry-install", "download-tool", "system-install",
    "curl-in-substitution", "install-hook-network", "ip-download", "inline-script-network", "remote-copy",
    "raw-socket-connect", "listen-socket", "curl-upload", "exfil-webhook",
})
_NETWORK_RULES = tuple(r for r in RULES if r.id in NETWORK_RULE_IDS)
NETWORK_COMMANDS = frozenset("""
curl wget aria2c lftp axel ftp sftp tftp scp ssh nc ncat netcat socat telnet gsutil rclone gh aws az yt-dlp youtube-dl
transmission-cli wget2 ipfs http https xh docker podman flatpak snap pacman paru yay pamac apt apt-get dnf yum zypper
brew dig nslookup host ping traceroute svn hg bzr fossil
""".split())
GIT_NETWORK = frozenset({"clone", "fetch", "pull", "submodule", "remote", "ls-remote", "push", "lfs"})
URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|ssh|git|rsync|wss?)://[^\s'\")>;|]+")

PATHLESS = frozenset("echo printf true false : test export unset local declare readonly set shift return exit read let wait hash type shopt".split())
WRITE_LAST = frozenset({"cp", "mv", "install", "ln", "rsync"})
WRITE_ALL = frozenset({"tee", "touch", "mkdir", "chmod", "chown", "chgrp", "truncate", "mkfifo", "patch"})
DELETE = frozenset({"rm", "rmdir", "unlink", "shred"})
SCRIPT_FIRST = frozenset({"sed", "grep", "egrep", "fgrep", "awk"})
FILE_COMMANDS = WRITE_LAST | WRITE_ALL | DELETE | frozenset(
    "cat ls head tail stat readlink sed grep egrep fgrep awk wc sort diff cmp find tar unzip cd pushd".split()
)
OUTPUT_OPTIONS = frozenset({"-o", "--output", "-t", "--target-directory", "--destdir", "--root"})
ACCESS_OPTIONS = frozenset({"-C", "-d", "--directory"})
PATH_ASSIGNMENTS = re.compile(r"^(?:DESTDIR|INSTALL_ROOT|ROOT)=(.*)$")
ROUTINE_VARS = frozenset({"srcdir", "pkgdir", "startdir"})
HARMLESS_TARGETS = frozenset({"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "-"})


@dataclass
class Activity:
    kind: str           # network | file | command | hook | parse-time
    text: str
    file: str
    line: int | None
    routine: bool = False


def _looks_like_path(arg: str, hook: bool = False, name: str = "") -> bool:
    if re.match(r"^\w+://", arg):
        return False
    if arg.startswith(("/", "~", "./", "../", "$")) or "/" in arg:
        return True
    # An install hook runs with the live system as its working directory, so a bare name is a real file.
    return (hook and name in FILE_COMMANDS and not re.fullmatch(r"\d+|[+=-]?[ugoa]*[+=-][rwxXst]+", arg))


def _bare_url(url: str) -> str:
    return re.sub(r"^[a-z]+\+(?=\w+://)", "", url).split("#", 1)[0]


def _is_remote_rsync(args: list[str]) -> bool:
    return any(re.search(r"^[\w.-]+@[\w.-]+:|^[\w.-]+::|^rsync://", a) for a in args)


def file_accesses(command: Command, hook: bool = False) -> list[tuple[str, str]]:
    """(verb, path) pairs a command touches. Approximate: verbs come from a table of known tools."""
    name = normalise(command.name)
    found: list[tuple[str, str]] = []
    for op, target in command.redirects:
        if target in HARMLESS_TARGETS:
            continue
        found.append(("read" if op == "<" else "access" if op == "<>" else "write", target))
    if name in PATHLESS:
        return found

    args = list(command.args)
    skip: set[int] = set()
    if name in SCRIPT_FIRST:
        flagged = [i for i, a in enumerate(args) if a in ("-e", "--expression", "-f", "--file") or (a.startswith("-e") and len(a) > 2)]
        if flagged:
            for i in flagged:
                skip.update({i, i + 1})
        else:
            first = next((i for i, a in enumerate(args) if not a.startswith("-")), None)
            if first is not None:
                skip.add(first)

    operands: list[int] = []
    for i, arg in enumerate(args):
        if i in skip or arg == "--":
            continue
        if arg.startswith("-"):
            key, _, value = arg.partition("=")
            verb = "write" if key in OUTPUT_OPTIONS else "access" if key in ACCESS_OPTIONS else None
            if verb and value and _looks_like_path(value, hook, name):
                found.append((verb, value))
            elif verb and not value and i + 1 < len(args) and _looks_like_path(args[i + 1], hook, name):
                skip.add(i + 1)
                found.append((verb, args[i + 1]))
            continue
        assignment = PATH_ASSIGNMENTS.match(arg)
        if assignment:
            if assignment.group(1):
                found.append(("write", assignment.group(1)))
        else:
            operands.append(i)

    in_place = name == "sed" and any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args)
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
            verb = "write" if index == destination and not has_target_dir else "read"
        elif name == "find" and "-delete" in args:
            verb = "delete"
        else:
            verb = "read"
        found.append((verb, arg))
    return found


def classify_path(raw: str, variables: dict[str, str], hook: bool) -> tuple[bool, str]:
    """(routine, reason). Routine = inside the build directories; anything else is reported."""
    path = _expand(raw, variables)
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


def _git_is_network(command: Command) -> bool:
    args = list(command.args)
    while args[:1] == ["-C"]:
        args = args[2:]
    return next((a for a in args if not a.startswith("-")), "") in GIT_NETWORK


def build_activity(files: dict[str, str]) -> list[Activity]:
    activities: list[Activity] = []
    pkgbuild = files.get("PKGBUILD", "")
    reported_urls: set[str] = set()
    for entry in source_entries(pkgbuild):
        reported_urls.add(_bare_url(entry.url))
        note = f"checksum: {entry.checksum}" + ("" if entry.pinned else ", unpinned VCS source")
        activities.append(Activity("network", f"downloads source {entry.url} ({note})", "PKGBUILD", entry.line))

    for name, text in files.items():
        if name == "(omitted-files)" or not (name == "PKGBUILD" or name.endswith(".install")):
            continue
        hook = name.endswith(".install")
        variables = _variables(text)
        counts: dict[str, list] = {}
        for step in walk(text):
            network_lines = False
            for rule in _NETWORK_RULES:
                if _applies(rule.scope, name) and rule.pattern.search(step.text):
                    activities.append(Activity("network", f"{rule.message}: {step.text[:100]}", name, step.line))
                    network_lines = True
            if not network_lines and not step.text.startswith("url="):
                for url in URL_RE.findall(step.text):
                    if _bare_url(url) not in reported_urls:
                        reported_urls.add(_bare_url(url))
                        activities.append(Activity("network", f"mentions {url}", name, step.line))
                        network_lines = True
            commands = step.commands + step.parse_time
            if not network_lines:
                for command in commands:
                    base = normalise(command.name)
                    if (base in NETWORK_COMMANDS or (base == "git" and _git_is_network(command))
                            or (base == "rsync" and _is_remote_rsync(command.args))):
                        activities.append(Activity("network", f"runs {base}: {step.text[:100]}", name, step.line))
                        break
            for command in commands:
                base = normalise(command.name)
                entry = counts.setdefault(base, [step.line, 0])
                entry[1] += 1
                for verb, path in file_accesses(command, hook):
                    routine, reason = classify_path(path, variables, hook)
                    shown = f"{verb} {path}" + (f" ({reason})" if reason else "")
                    activities.append(Activity("hook" if hook else "file", shown, name, step.line, routine))
            if step.toplevel_code or step.parse_time_substitution:
                activities.append(Activity("parse-time", f"runs when the file is parsed: {step.text[:100]}", name, step.line))
        for base, (line, count) in counts.items():
            activities.append(Activity("command", f"{base}" + (f" x{count}" if count > 1 else ""), name, line))
    return activities


def format_activity(package: str, activities: list[Activity], verbose: bool = False) -> str:
    def where(a: Activity) -> str:
        return f"{a.file}:{a.line}" if a.line else a.file

    lines = [f"What {package} does (reported whether or not it looks suspicious):"]
    network = [a for a in activities if a.kind == "network"]
    outside = [a for a in activities if a.kind == "file" and not a.routine]
    hooks = [a for a in activities if a.kind == "hook"]
    parse_time = [a for a in activities if a.kind == "parse-time"]
    commands = [a for a in activities if a.kind == "command"]
    routine = [a for a in activities if a.kind == "file" and a.routine]

    def section(title: str, items: list[Activity]) -> None:
        if items:
            lines.append(f"  {title} ({len(items)}):")
            lines.extend(f"    {where(a)}  {a.text}" for a in items)

    section("Network: downloads and remote access", network)
    section("Files outside the build directories", outside)
    section("Install hooks (run as root on your system)", hooks)
    section("Code that runs when the PKGBUILD is only parsed", parse_time)
    if commands:
        lines.append("  Commands run: " + ", ".join(a.text for a in commands))
    if routine:
        if verbose:
            section("Routine file operations inside $srcdir / $pkgdir", routine)
        else:
            lines.append(f"  Routine file operations inside $srcdir / $pkgdir: {len(routine)} (not listed; use --safe-verbose)")
    if len(lines) == 1:
        lines.append("  no network access, file access or commands found")
    return "\n".join(lines)


def inventory_for_ai(activities: list[Activity], limit: int = 150) -> str:
    """Compact text version of the inventory, so the model can look for what it does NOT show."""
    items = [a for a in activities if not a.routine]
    lines = [f"[{a.kind}] {a.file}:{a.line or '-'} {a.text}" for a in items[:limit]]
    if len(items) > limit:
        lines.append(f"... {len(items) - limit} more entries omitted")
    routine = sum(1 for a in activities if a.routine)
    if routine:
        lines.append(f"[file] {routine} routine file operations inside $srcdir/$pkgdir (not listed)")
    return "\n".join(lines)
