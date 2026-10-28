"""Default-deny review of PKGBUILD / *.install shell code.

The regex rules in heuristics.py look for known-bad patterns, so anything new passes them.
This module inverts that: every command the script runs must be on a list of ordinary
packaging tools, used in an ordinary way. Whatever cannot be recognised (an unknown command,
a command built from a variable, inline interpreter code, code at the top level, shell that
does not even parse) is reported, so that "not understood" can never end up as "clear".
"""
from __future__ import annotations

import re
import shlex
from typing import NamedTuple

from . import commandtable
from .models import Finding

# Which commands are ordinary packaging steps, and what their options and arguments do, is the command table
# (commandtable_data.py, docs/COMMANDS.md); this module only turns what the table says into findings.

SED_SUBST = re.compile(
    r"s(?P<d>[^\w\s\\])(?:\\.|(?!(?P=d)).)*(?P=d)(?:\\.|(?!(?P=d)).)*(?P=d)(?P<flags>[A-Za-z0-9]*)"
)
TAR_EXEC_OPTIONS = re.compile(r"^--(?:to-command|checkpoint-action|use-compress-program|rsh-command|info-script|new-volume-script)")
RISKY_GIT_CONFIG = re.compile(r"(?i)^!|core\.(?:sshcommand|pager|editor|fsmonitor|hookspath)|credential\.helper|alias\.|filter\.\w+\.(?:clean|smudge)")
SEARCH_TOOLCHAIN_VARS = re.compile(r"\$\{?(?:CC|CXX|MAKE|AR|LD|PYTHON|CMAKE|CPP|STRIP)\}?")
INTERPRETERS = re.compile(r"^(?:python[\d.]*|pypy3?|perl|ruby|node|php|lua|luajit)$")
INLINE_FLAG = re.compile(r"^(?:-[A-Za-z]*[cCeErp]|--(?:eval|print|exec|command|execute))")
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
    redirects: tuple = ()  # ((operator, target), ...) for > >> < etc.; heredoc bodies are not files
    segment: int = 0       # commands of one pipeline stage share a number; a piped stage reads stage - 1
    inside: bool = False   # runs inside a `$(...)`, `<(...)` or backtick substitution


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


AWK_ACTIVE = re.compile(r"\bsystem\s*\(|\|\s*getline\b|\bprintf?\b[^;}\n]*\|\s*[\"$\w]|\|&")
AWKS = frozenset({"awk", "gawk", "mawk"})
PACMAN_READ_ONLY = re.compile(r"^(?:--(?:query|deptest|sync)\b.*|-[A-Za-z]*[TQ][A-Za-z]*|-S[iqslgp]+)$")
# commands whose output is harmless to compute while the file is merely parsed (`bold="$(tput bold)"`)
PARSE_TIME_SAFE = frozenset("tput echo printf date uname nproc basename dirname pwd id whoami hostname tr cut head tail wc sort uniq expr seq".split())


def _awk_script_is_active(args: list[str]) -> bool:
    """awk can run commands (system, `| getline`, `print | "cmd"`); a program read from a file (-f) is not visible."""
    for arg in args:
        if arg == "-f" or arg.startswith("--file") or (arg.startswith("-f") and len(arg) > 2 and not arg.startswith("-F")):
            return True
    return any(AWK_ACTIVE.search(a) for a in args if not a.startswith("-"))


def inline_flag(args: list[str]) -> str | None:
    """The first option that gives an interpreter its program on the command line (-c, -e, ...), if any."""
    for arg in args:
        if arg == "-m" or not arg.startswith("-"):
            return None
        if INLINE_FLAG.match(arg):
            return arg
    return None


# What a predicate in the table means as a finding. A rule of the command's entry whose predicate holds is reported
# with this rule name and message ({name} is the program, {arg} the option that gave the code).
PREDICATE_FINDINGS = {
    "sed-active": ("inline-code", "sed script can run commands or write/read files (e, w, r)"),
    "awk-active": ("inline-code", "{name} program can run commands (system, getline, a pipe) or is read from a file"),
    "find-writes": ("inline-code", "find writes its output to a file"),
    "tar-exec": ("inline-code", "{name} is told to run another program"),
    "git-config-exec": ("inline-code", "git is configured to run another program (alias, ssh command, filter, hook path)"),
    "inline-code": ("inline-code", "{name} runs code given on the command line ({arg})"),
    "piped": ("inline-code", "{name} receives its program from a pipe"),
    "pacman-write": ("unknown-command", "Command not on the allowlist (default-deny): {name}"),
}


# Programs at these directories are the system's own; a command at any other absolute path is that file, whatever
# its name, and is not the standard command of the same name.
SYSTEM_BIN = frozenset({"/usr/bin", "/usr/sbin", "/bin", "/sbin"})
# makepkg defines these; a PKGBUILD that redefines one is not shadowing a standard command.
MAKEPKG_FUNCTIONS = frozenset("msg msg2 warning error plain plainerr".split())
# bash calls these whenever a command is not found
COMMAND_LOOKUP_HANDLERS = frozenset({"command_not_found_handle", "command_not_found_handler"})
# a system effect of this kind in the table (`hash -p`, `shopt -s expand_aliases`) is reported with this rule
SYSTEM_EFFECT_FINDINGS = {
    "command-lookup": ("command-lookup-change", "{name} changes which program a command name runs"),
    "shell-options": ("alias-definition", "{name} turns on alias expansion, so aliases rewrite the commands that follow"),
}


def _table_key(table: commandtable.Table, name: str) -> str:
    """The table's name for a command: `python3.11` is the `python` entry."""
    if table.lookup(name) is None and INTERPRETERS.match(name):
        base = name.rstrip("0123456789.")
        if table.lookup(base) is not None:
            return base
    return name


def classify(command: Command, where: str, local_functions: set[str]) -> tuple[str, str] | None:
    """(rule, message) if the command is not an ordinary packaging step, else None. `where` is "build" for a
    PKGBUILD and "hook" for an install script."""
    raw = command.name
    if raw == "__SUB__" or raw.startswith("$"):
        if SEARCH_TOOLCHAIN_VARS.fullmatch(raw):
            return None
        return "dynamic-command", f"Command is built at run time ({raw}), so what runs cannot be reviewed"
    table = commandtable.load()
    name = raw
    if raw.startswith("/") and table.lookup(raw) is None:
        directory, _, name = raw.rpartition("/")
        if directory not in SYSTEM_BIN:
            return "unknown-command", f"Command is run from a path outside the system program directories ({raw})"
    elif not raw.startswith("/"):
        name = _normalise(raw)
    key = _table_key(table, name)
    if name in local_functions:
        # a function of this file. If it also has the name of a command this one is checked as the command too,
        # since which of the two runs depends on the order of definitions, which is not followed.
        entry = table.lookup(key)
        if entry is None or where not in (entry.where or ("build",)):
            return None
    for rule, _, _ in table.fired(key, command.args, command.piped):
        if rule.kind == "system" and rule.target.word in SYSTEM_EFFECT_FINDINGS:
            found, message = SYSTEM_EFFECT_FINDINGS[rule.target.word]
            return found, message.format(name=name)
        for condition in rule.conditions:
            if condition.kind == "predicate" and not condition.negated and condition.names[0] in PREDICATE_FINDINGS:
                found, message = PREDICATE_FINDINGS[condition.names[0]]
                return found, message.format(name=name, arg=inline_flag(command.args) or "")
    entry = table.lookup(key)
    if entry is None or where not in (entry.where or ("build",)):
        return "unknown-command", f"Command not on the allowlist (default-deny): {name}"
    if entry.subs is not None:
        for effect in table.effects_of(key, command.args, command.piped) or ():
            if effect.kind == "unknown" and effect.target.startswith("subcommand"):
                sub = effect.target[len("subcommand"):].strip()
                return "unknown-command", f"{name} {sub or '(no subcommand)'} is not an ordinary local packaging step"
    return None


def normalise(name: str) -> str:
    return _normalise(name)


def scan_strict(name: str, source) -> list[Finding]:
    """`source` is a ParsedFile, or the script text."""
    from .parsed import parse                       # parsed.py imports this module
    parsed = parse(name, source)
    where = "hook" if name.endswith(".install") else "build"
    local_functions = parsed.function_names
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, message: str, line: int, key: str) -> None:
        if (rule, key) not in seen:
            seen.add((rule, key))
            findings.append(Finding("info", message, name, line, rule))

    table = commandtable.load()
    for function, line in parsed.function_definitions.items():
        if function in COMMAND_LOOKUP_HANDLERS:
            add("command-lookup-change", f"Function {function} runs whenever a command is not found", line, function)
        elif function not in MAKEPKG_FUNCTIONS and table.lookup(function) is not None:
            add("shadowed-command", f"Function {function} has the name of a standard command, so a call to it may run "
                                    f"the function instead of the command", line, function)
    aliases = _aliases(parsed, add)

    for step in parsed.steps:
        shown = step.text[:100]
        if step.toplevel_code:
            add("toplevel-code", f"Code outside any function runs when the file is merely parsed: {shown}", step.line, str(step.line))
        if step.parse_time_substitution and not (
                step.parse_time and all(_normalise(c.name) in PARSE_TIME_SAFE for c in step.parse_time)):
            label = step.parse_time[0].name if step.parse_time else "?"
            add("parse-time-command", f"A command substitution runs at parse time ({label}): {shown}", step.line, str(step.line))
        if not step.ok:
            add("unparseable-shell", f"Shell that could not be parsed, so it was not reviewed: {shown}", step.line, str(step.line))
        for command in step.commands:
            called = _normalise(command.name)
            if called == "alias":
                continue                                    # reported as alias-definition
            checked = [(command, "")]
            if called in aliases:                           # the alias is the definition; what it stands for is what runs
                checked = [(inner, f" (through the alias {called})") for inner in _alias_commands(aliases[called], command)]
            for each, how in checked:
                verdict = classify(each, where, local_functions)
                if verdict:
                    rule, message = verdict
                    add(rule, f"{message}{how}: {shown}", step.line, each.name if rule == "unknown-command" else str(step.line))
                elif step.heredoc and INTERPRETERS.match(_normalise(each.name)):
                    add("inline-code", f"{each.name} receives its program from a here-document: {shown}", step.line, str(step.line))
    return findings


def _aliases(parsed, add) -> dict:
    """name -> value of every alias the file defines (in any order, in any branch). Defining one is a finding:
    an alias can change what a later command runs."""
    found: dict = {}
    for pc in parsed.commands:
        if _normalise(pc.command.name) != "alias":
            continue
        operands = [arg for arg in pc.command.args if not arg.startswith("-")]
        if not operands:                                    # `alias` and `alias -p` only list
            continue
        defined = [arg for arg in operands if "=" in arg]
        for arg in defined:
            name, _, value = arg.partition("=")
            found[name] = value
        label = ", ".join(a.partition("=")[0] for a in defined) or "(none readable)"
        add("alias-definition", f"The script defines an alias ({label}), which can change what a command runs", pc.line, str(pc.line))
    return found


def _alias_commands(value: str, call: Command) -> list:
    """The commands an alias stands for, with the call's own arguments added to the last one."""
    from . import astadapt                                  # astadapt imports this module
    commands, ok = astadapt.flatten(value)
    if not ok:
        commands = astadapt.loose(value) or commands
    commands = list(commands)
    if commands and call.args:
        commands[-1] = commands[-1]._replace(args=list(commands[-1].args) + list(call.args))
    return commands or [Command("__SUB__", [], False)]
