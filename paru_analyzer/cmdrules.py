"""Rules that read parsed commands, not text.

A regex over a command line has to guess where words, quotes and pipes are. These rules get the
words already split with quotes removed, the pipeline each command sits in, and the files it
writes, so `c''url x | "ba"sh`, `sudo -u nobody env bash -s` and `cp x /etc//pam.d/../pam.d/login`
are the ordinary cases they were written for. Their regex twins in heuristics.py (`fallback=True`)
run only on lines this parser could not read.

Each rule is a function of one command (and the commands that feed it); it answers yes or no.
Severity, message and scope live next to it, the same as for the regex rules.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Callable, NamedTuple

from .fileaccess import file_accesses
from .invocation import (FETCHERS, NETWORK_CLIENTS, PRIVILEGE, SHELLS, base, flags, interpreter, operands,
                         reads_program_from_stdin, views)
from .models import Finding
from .parsed import ParsedCommand, ParsedFile, expand
from .strict import Command

SYSTEM_ROOTS = ("usr", "etc", "opt", "bin", "sbin", "lib", "lib64", "boot", "var", "root", "home", "srv")
TOP_LEVEL_DIRS = frozenset("/" + d for d in ("etc", "usr", "bin", "sbin", "lib", "lib64", "boot", "var", "home", "root",
                                             "opt", "srv", "dev", "sys", "proc"))
TEMP_DIRS = ("/tmp", "/dev/shm", "/var/tmp")
SETUID_TARGETS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python2", "python3", "perl", "find",
                            "cp", "env", "vim", "vi", "nmap", "awk", "ruby", "node", "php"})
SENSITIVE_HOOK_PATHS = re.compile(
    r"^/(?:etc/(?:pam\.d|ssh|ld\.so\.conf(?:\.d)?|ld\.so\.preload|profile(?:\.d)?|bash\.bashrc|bashrc|zsh|environment|rc\.local|init\.d|crontab|cron\.\w+|hosts|shells|skel|xdg/autostart|doas\.conf|polkit-1"
    r"|resolv\.conf|nsswitch\.conf|fstab|modules-load\.d|modprobe\.d|udev|security|pacman\.d)|boot|usr/lib/security|lib/security)(?:/|$)"
)
HOME_PERSISTENCE = re.compile(
    r"^(?:~|\$HOME|\$\{HOME\}|/home/[^/]+|/root)/(?:\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|xprofile"
    r"|xinitrc|xsession)|\.config/(?:autostart|systemd/user|fish/config\.fish)(?:/|$)|\.local/share/systemd/user(?:/|$)"
    r"|\.ssh/authorized_keys2?)$|^(?:~|\$HOME|\$\{HOME\}|/home/[^/]+|/root)/\.(?:config/(?:autostart|systemd/user)|local/share/systemd/user)/"
)
ACCOUNT_FILES = re.compile(r"^/etc/(?:sudoers(?:\.d)?|passwd|shadow|gshadow|group)(?:/|$)")
PACMAN_FILES = re.compile(r"^/etc/(?:pacman\.conf|makepkg\.conf|pacman\.d/gnupg)(?:/|$)")


class Ctx(NamedTuple):
    pc: ParsedCommand
    view: Command            # the program that runs: the command itself, or what a wrapper starts
    name: str                # its base name
    outer: bool              # this is the command as written, not something a wrapper starts
    hook: bool               # the file is an install scriptlet (runs as root on the live system)
    parsed: ParsedFile


@dataclass(frozen=True)
class CmdRule:
    id: str
    severity: str
    message: str
    check: Callable[[Ctx], bool]
    scope: str = "code"      # same meaning as Rule.scope in heuristics.py
    outer_only: bool = False


# ---- paths ----

def resolve(path: str, hook: bool) -> str:
    """The path with `//`, `.` and `..` folded away. In an install scriptlet a relative path is
    relative to `/`, because pacman runs the scriptlet from there. Anything built from a variable or
    `~` is returned unchanged."""
    if not path or "$" in path or "`" in path or path.startswith("~"):
        return path
    if not path.startswith("/"):
        if not hook or path == "-":
            return path
        path = "/" + path
    return posixpath.normpath(re.sub(r"/{2,}", "/", path))


def under(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def live_path(path: str) -> bool:
    if not path.startswith("/") or under(path, ("/var/tmp",)):
        return False
    if path == "/":
        return True                          # `tar -C /`: unpacking over the whole system
    first = path.split("/", 2)[1]
    return first in SYSTEM_ROOTS


def known(ctx: Ctx, text: str) -> str:
    """`$d` and `${d}` replaced by the value of a variable the file assigns once, as a literal."""
    return expand(text, ctx.parsed.stable_variables) if "$" in text else text


def changed(ctx: Ctx) -> list[tuple[str, str]]:
    """(verb, resolved path) for every path this command writes or deletes."""
    return [(verb, resolve(known(ctx, path), ctx.hook))
            for verb, path in file_accesses(ctx.view, ctx.hook) if verb in ("write", "delete")]


def written(ctx: Ctx) -> list[str]:
    """Resolved paths this command writes or deletes."""
    return [path for _, path in changed(ctx)]


def in_temp(path: str, hook: bool = False) -> bool:
    return under(resolve(path, hook), TEMP_DIRS)


# ---- pipelines: something downloaded or decoded, then run ----

def _substituted(command: Command) -> bool:
    return "__SUB__" in command.args or any("__SUB__" in target for _, target in command.redirects)


def _fed_by_substitution(command: Command) -> bool:
    """`sh <<< "$(curl x)"`, `sh < <(curl x)`: the shell's stdin is the output of a substitution."""
    return any(op in ("<<<", "<") and "__SUB__" in target for op, target in command.redirects)


def command_tags(command: Command) -> frozenset:
    """What a command contributes to a pipeline it feeds: 'fetch', 'net', 'base64', 'decode', 'echo', and
    'sub' when it takes a substitution's output as an argument."""
    tags: set[str] = set()
    for view in views(command):
        name = base(view.name)
        if name in FETCHERS:
            tags.add("fetch")
        if name in NETWORK_CLIENTS or (name == "openssl" and "s_client" in view.args):
            tags.add("net")
        kind = _decodes(view)
        if kind:
            tags.add("base64" if kind == "base64" else "other")
        if name in ("echo", "printf"):
            tags.add("echo")
        if _substituted(view):
            tags.add("sub")
    return frozenset(tags)


def _feeding(ctx: Ctx) -> frozenset:
    """Tags of what feeds this command: earlier pipeline stages, and the commands of any `$(...)` / `<(...)`
    that one of them (or this one) takes as input, since `cat <(curl x) | sh` and `echo "$(curl x)" | sh`
    run what the substitution printed."""
    tags = ctx.pc.upstream_tags(command_tags)
    if "sub" in tags or _substituted(ctx.view):
        tags = tags | ctx.pc.substitution_tags(command_tags)
    return tags


def _receives_program(ctx: Ctx) -> bool:
    return (ctx.view.piped or _fed_by_substitution(ctx.view)) and reads_program_from_stdin(ctx.name, ctx.view.args)


def xargs_exec(ctx: Ctx) -> bool:
    """`curl x | xargs sh -c ...`: downloaded text becomes the arguments of a shell or interpreter."""
    if ctx.name != "xargs" or not ctx.view.piped:
        return False
    inner = list(views(ctx.view))[1:2]
    if not inner or not (base(inner[0].name) in SHELLS or base(inner[0].name) == "eval" or interpreter(base(inner[0].name))):
        return False
    return "fetch" in _feeding(ctx)


def pipe_to_shell(ctx: Ctx) -> bool:
    return _receives_program(ctx) and "fetch" in _feeding(ctx)


def network_pipe_shell(ctx: Ctx) -> bool:
    return _receives_program(ctx) and "net" in _feeding(ctx)


def echo_to_shell(ctx: Ctx) -> bool:
    """`echo ... | sh`: a string built in the script is run as a program. Quoted text that merely
    contains a pipe (`echo 'curl x | sh'`) is not this."""
    return _receives_program(ctx) and "echo" in _feeding(ctx)


def _decodes(command: Command) -> str:
    """'base64' or 'other' when the command decodes or decompresses its input, else ''."""
    name, args = base(command.name), command.args
    letters = flags(args)
    if name == "base64":
        return "base64" if letters & {"d", "D", "--decode"} else ""
    if name in ("base32",):
        return "other" if letters & {"d", "--decode"} else ""
    if name == "xxd":
        return "other" if "r" in letters else ""
    if name == "openssl":
        return "other" if "-d" in args or "-decrypt" in args else ""
    if name == "tr":
        return "other" if any(re.search(r"n-za-m", a, re.I) for a in args) else ""
    if name in ("gzip", "bzip2", "xz", "zstd", "lzma"):
        return "other" if letters & {"d", "--decompress", "--uncompress"} else ""
    if name in ("uudecode", "gunzip", "zcat", "bzcat", "xzcat", "unxz", "unzstd", "zstdcat", "lzcat", "unlzma",
                "brotli", "rev"):
        return "other"
    return ""


def base64_exec(ctx: Ctx) -> bool:
    return _receives_program(ctx) and "base64" in _feeding(ctx)


def decode_exec(ctx: Ctx) -> bool:
    return _receives_program(ctx) and "other" in _feeding(ctx)


# ---- privilege ----

def uses_privilege(ctx: Ctx) -> bool:
    return ctx.name in PRIVILEGE


def _mode_sets_id_bit(mode: str) -> bool:
    """True for a mode that sets setuid or setgid: 4755, 2755, u+s, g+s, +s, a+s, u=rwxs."""
    if re.fullmatch(r"[0-7]{4,5}", mode):
        return bool(int(mode[-4], 8) & 6)
    for clause in mode.split(","):
        match = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", clause)
        if match and match.group(2) in "+=" and "s" in match.group(3) and (
                not match.group(1) or set(match.group(1)) & set("uga")):
            return True
    return False


def _chmod_mode_and_targets(ctx: Ctx):
    if ctx.name != "chmod":
        return None, []
    ops = [a for a in ctx.view.args if a != "--" and not a.startswith("-")]
    return (ops[0], ops[1:]) if ops else (None, [])


def setuid_bit(ctx: Ctx) -> bool:
    mode, _ = _chmod_mode_and_targets(ctx)
    return mode is not None and _mode_sets_id_bit(mode)


def setuid_shell(ctx: Ctx) -> bool:
    mode, targets = _chmod_mode_and_targets(ctx)
    if mode is None or not _mode_sets_id_bit(mode):
        return False
    return any(base(t) in SETUID_TARGETS or in_temp(t, ctx.hook) for t in targets)


# ---- the system's files ----

def live_system_write(ctx: Ctx) -> bool:
    return any(live_path(p) for p in written(ctx))


OWN_SUDOERS_FILE = re.compile(r"^/etc/sudoers\.d/[^/*?\[]+$")
HOME_FILE = re.compile(r"^(?:~|\$HOME|\$\{HOME\}|/home/[^/]+|/root)/(?:\.|\w)")


def account_write(ctx: Ctx) -> bool:
    """Writes sudoers or the account databases, or deletes more than one sudoers.d file. Deleting a single
    file there is `sudoers_remove`: still reported, but a lower level than writing a rule."""
    return any(ACCOUNT_FILES.match(p) and not (verb == "delete" and OWN_SUDOERS_FILE.match(p)) for verb, p in changed(ctx))


def sudoers_remove(ctx: Ctx) -> bool:
    """Deletes one file under /etc/sudoers.d. An uninstall hook does this with the rule the package added, but
    a sudoers file can also hold a restriction (`Defaults`, a denied command) or belong to another package or
    to the administrator, and nothing here can tell whose it is, so it is never silent."""
    return any(verb == "delete" and OWN_SUDOERS_FILE.match(p) for verb, p in changed(ctx))


def home_delete(ctx: Ctx) -> bool:
    return any(verb == "delete" and HOME_FILE.match(p) for verb, p in changed(ctx))


PERSISTENT_SYSTEMCTL = frozenset({"enable", "reenable", "start", "restart", "link"})


def hook_persistence(ctx: Ctx) -> bool:
    """An install hook that starts a service, installs a cron job or edits one. A message that only
    mentions the command (`echo "run: systemctl enable x"`) is not that."""
    if ctx.name == "crontab":
        return True
    if ctx.name == "systemctl" and any(a in PERSISTENT_SYSTEMCTL for a in ctx.view.args):
        return True
    return any(re.match(r"^/etc/(?:cron|anacron)", p) or HOME_PERSISTENCE.match(p) for p in written(ctx))


def apparmor_unload(ctx: Ctx) -> bool:
    return ctx.name == "apparmor_parser" and any(a in ("-R", "--remove") or re.fullmatch(r"-\w*R\w*", a) for a in ctx.view.args)


def pacman_config_write(ctx: Ctx) -> bool:
    return any(PACMAN_FILES.match(p) for p in written(ctx))


def hook_system_files(ctx: Ctx) -> bool:
    return any(SENSITIVE_HOOK_PATHS.match(p) for p in written(ctx))


def home_persistence_write(ctx: Ctx) -> bool:
    """Writes a file the user's session loads on its own: shell rc, autostart, user units, authorized_keys.
    A build runs as the user, so this is the package reaching out of the build tree to run later."""
    return any(HOME_PERSISTENCE.match(path) for path in written(ctx))


LD_PRELOAD_FILE = re.compile(r"^/etc/ld\.so\.preload$")
AUTHORIZED_KEYS = re.compile(r"(?:^|/)authorized_keys2?$")
DISK_DEVICE = re.compile(r"^/dev/(?:sd|nvme|vd|hd|xvd|mmcblk|disk)")
DISK_TOOLS = re.compile(r"^(?:mkfs(?:\.\w+)?|wipefs|blkdiscard|shred)$")
WORLD_WRITABLE_SYMBOLIC = re.compile(r"([ugoa]*)([-+=])([rwxXst]*)")
HOME_DIR = r"(?:~|\$HOME|\$\{HOME\}|/home/[^/]+|/root)"
CREDENTIAL_LOCATIONS = (
    HOME_DIR + r"/\.(?:ssh|gnupg|aws|kube|azure|mozilla|thunderbird|password-store|electrum|bitcoin|ethereum|monero|netrc"
    r"|npmrc|pypirc|git-credentials|bash_history|zsh_history|python_history|docker/config\.json"
    r"|config/(?:google-chrome|chromium|BraveSoftware|vivaldi|opera|microsoft-edge|discord|Slack|Signal|Element|gh|rclone|gcloud|solana|1Password|Bitwarden|Code))"
)
CREDENTIAL_PATH = re.compile("^" + CREDENTIAL_LOCATIONS + r"(?:/|$)")
SHADOW_FILE = re.compile(r"^/etc/(?:shadow|gshadow)(?:/|$)")
# the same locations written inside a longer string (`python -c 'open("/etc/shadow")'`), outside the package directory
CREDENTIAL_IN_TEXT = re.compile("(?<![\\w}])" + CREDENTIAL_LOCATIONS + r"\b")
SHADOW_IN_TEXT = re.compile(r"(?<![\w}])/etc/(?:shadow|gshadow)\b")
IN_HOME = re.compile("^" + HOME_DIR + "(?:/|$)")
ARCHIVERS = frozenset({"tar", "zip", "7z", "7za", "rar"})
MESSAGE_COMMANDS = frozenset({"echo", "printf"})                # their arguments are text, not files
HOME_AND_SYSTEM_TARGETS = frozenset({"/", "~", "$HOME", "${HOME}", "/home", "/etc", "/usr"})


def ld_preload_file(ctx: Ctx) -> bool:
    """Writes or deletes /etc/ld.so.preload, the file that makes every program load a library (a rootkit technique)."""
    return any(LD_PRELOAD_FILE.match(p) for p in written(ctx))


def authorized_keys(ctx: Ctx) -> bool:
    """Any command that reads, writes or deletes a file called authorized_keys."""
    return any(AUTHORIZED_KEYS.search(resolve(known(ctx, path), ctx.hook)) for _, path in file_accesses(ctx.view, ctx.hook))


def _makes_world_writable(mode: str) -> bool:
    if re.fullmatch(r"0?777", mode):
        return True
    for clause in mode.split(","):
        match = WORLD_WRITABLE_SYMBOLIC.fullmatch(clause)
        if match and match.group(2) in "+=" and "w" in match.group(3) and set(match.group(1)) & set("oa"):
            return True
    return False


def world_writable(ctx: Ctx) -> bool:
    mode, _ = _chmod_mode_and_targets(ctx)
    return mode is not None and _makes_world_writable(mode)


def _paths_named(ctx: Ctx):
    """Every path the command line names, resolved: operands, option values (`--file=p`, `-F f=@p`) and redirection
    targets. The words of `echo` and `printf` are a message, so only their redirections count."""
    words = [] if ctx.name in MESSAGE_COMMANDS else list(ctx.view.args)
    words += [target for _, target in ctx.view.redirects]
    for word in words:
        for piece in {word, *re.split(r"[=@:]", word)}:
            if piece:
                yield resolve(known(ctx, piece), ctx.hook)


def _in_words(ctx: Ctx, pattern) -> bool:
    """The pattern occurs inside one of the words, such as a program given to an interpreter (not in a message)."""
    return ctx.name not in MESSAGE_COMMANDS and any(pattern.search(word) for word in ctx.view.args)


def credential_paths(ctx: Ctx) -> bool:
    """Names a credential, wallet, history or browser-profile location in the user's home."""
    return any(CREDENTIAL_PATH.match(p) for p in _paths_named(ctx)) or _in_words(ctx, CREDENTIAL_IN_TEXT)


def read_shadow(ctx: Ctx) -> bool:
    return any(SHADOW_FILE.match(p) for p in _paths_named(ctx)) or _in_words(ctx, SHADOW_IN_TEXT)


def home_archive(ctx: Ctx) -> bool:
    """tar, zip, 7z or rar given the home directory, or anything in it, as one of its arguments (the old pattern did the same)."""
    return ctx.name in ARCHIVERS and any(IN_HOME.match(p) for p in _paths_named(ctx))


# ---- destruction ----

def _root_like(target: str) -> bool:
    path = re.sub(r"/{2,}", "/", target)
    if path.endswith("/*"):
        path = path[:-2] or "/"
    path = path.rstrip("/") or "/"
    if path.startswith("/"):
        path = posixpath.normpath(path)
    return path in ("/", "~", "$HOME", "${HOME}")


def rm_root(ctx: Ctx) -> bool:
    if ctx.name != "rm":
        return False
    return "--no-preserve-root" in ctx.view.args or any(_root_like(known(ctx, t)) for t in operands(ctx.view.args))


def rm_system_dir(ctx: Ctx) -> bool:
    if ctx.name != "rm" or not (flags(ctx.view.args) & {"r", "R", "--recursive"}):
        return False
    for target in operands(ctx.view.args):
        path = re.sub(r"/{2,}", "/", known(ctx, target))
        if path.endswith("/*"):
            path = path[:-2]
        if path.startswith("/") and posixpath.normpath(path.rstrip("/") or "/") in TOP_LEVEL_DIRS:
            return True
    return False


def disk_wipe(ctx: Ctx) -> bool:
    """Writes to a raw disk (`dd of=/dev/sda`, `> /dev/sda`), formats or wipes one, or zaps a partition table."""
    if ctx.name == "sgdisk" and any(a in ("--zap-all", "-Z") for a in ctx.view.args):
        return True
    if DISK_TOOLS.match(ctx.name) and any(DISK_DEVICE.match(known(ctx, a)) for a in operands(ctx.view.args)):
        return True
    return any(DISK_DEVICE.match(p) for p in written(ctx))


def find_delete_root(ctx: Ctx) -> bool:
    """`find / ... -delete` or `-exec rm`, over the whole system or the home directory."""
    if ctx.name != "find":
        return False
    args = ctx.view.args
    starts = []
    for arg in args:
        if arg.startswith(("-", "(", "!")):
            break
        starts.append(resolve(known(ctx, arg), ctx.hook))
    deletes = "-delete" in args or any(a == "-exec" and i + 1 < len(args) and base(args[i + 1]) == "rm" for i, a in enumerate(args))
    return deletes and any(t in HOME_AND_SYSTEM_TARGETS for t in starts)


def recursive_perm_root(ctx: Ctx) -> bool:
    """`chmod -R` / `chown -R` on / or the home directory (the first operand is the mode or the owner)."""
    if ctx.name not in ("chmod", "chown") or not (flags(ctx.view.args) & {"R", "--recursive"}):
        return False
    return any(_root_like(known(ctx, t)) for t in operands(ctx.view.args)[1:])


# ---- the network ----

CURLS = frozenset({"curl", "wget", "aria2c"})
NETCATS = frozenset({"nc", "ncat", "netcat"})
GIT_VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
VCS_FETCH = {"svn": {"co", "checkout", "export", "up", "update"}, "hg": {"clone", "pull"}, "bzr": {"branch", "checkout"},
             "fossil": {"clone"}}
DOWNLOAD_TOOLS = frozenset("lftp axel tftp ftp sftp gsutil rclone yt-dlp youtube-dl transmission-cli wget2 ipfs http https xh".split())
SYSTEM_INSTALLERS = frozenset("pacman paru yay pamac aura trizen yaourt apt apt-get dnf yum zypper snap flatpak brew nix nix-env".split())
INSTALL_VERBS = frozenset({"install", "add", "pull", "update", "upgrade"})
REGISTRY_INSTALL = {"pip": {"install"}, "pip3": {"install"}, "npm": {"install", "i"}, "gem": {"install"}, "cargo": {"install"}}
UPLOAD_OPTIONS = frozenset({"-T", "--upload-file"})
RAW_IP_URL = re.compile(r"https?://(?!(?:127|0|10)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}\b")


def _subcommand(args: list[str]) -> tuple[str | None, list[str]]:
    """The git subcommand and the words after it (options that take a value, like `-C dir`, are skipped)."""
    i = 0
    while i < len(args):
        if args[i] in GIT_VALUE_OPTIONS:
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            return args[i], args[i + 1:]
    return None, []


def _vcs_fetch(ctx: Ctx) -> bool:
    if ctx.name == "git":
        sub, rest = _subcommand(ctx.view.args)
        return sub in ("clone", "fetch", "pull") or (sub == "submodule" and rest[:1] in (["update"], ["add"])) or (
            sub == "remote" and rest[:1] == ["add"])
    wanted = VCS_FETCH.get(ctx.name)
    return bool(wanted) and bool(ctx.view.args) and ctx.view.args[0] in wanted


def build_time_download(ctx: Ctx) -> bool:
    return ctx.name in CURLS and not ctx.view.inside


def curl_in_substitution(ctx: Ctx) -> bool:
    return ctx.name in ("curl", "wget") and ctx.view.inside


def install_hook_network(ctx: Ctx) -> bool:
    if ctx.name in CURLS or ctx.name in ("nc", "ncat"):
        return True
    if ctx.name == "git":
        return _subcommand(ctx.view.args)[0] == "clone"
    return bool(ctx.view.args) and ctx.view.args[0] in REGISTRY_INSTALL.get(ctx.name, ())


def curl_upload(ctx: Ctx) -> bool:
    if ctx.name not in CURLS:
        return False
    args = ctx.view.args
    for i, arg in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if arg in UPLOAD_OPTIONS or arg.startswith("--upload-file="):
            return True
        if re.fullmatch(r"-d@.*", arg) or (arg == "-d" and following.startswith("@")):
            return True
        if re.fullmatch(r"--data(?:-binary|-raw|-urlencode)?=@.*", arg) or (
                re.fullmatch(r"--data(?:-binary|-raw|-urlencode)?", arg) and following.startswith("@")):
            return True
        if arg == "-F" and re.search(r"=@", following):
            return True
    return False


def remote_copy(ctx: Ctx) -> bool:
    return ctx.name in ("scp", "sftp", "rsync") and any(re.match(r"^[\w.-]+@[\w.-]+:", a) for a in ctx.view.args)


def vcs_fetch(ctx: Ctx) -> bool:
    return _vcs_fetch(ctx)


def ip_download(ctx: Ctx) -> bool:
    if ctx.name in CURLS or (ctx.name == "git" and _subcommand(ctx.view.args)[0] == "clone"):
        return any(RAW_IP_URL.match(a) for a in ctx.view.args)
    return False


def raw_socket_connect(ctx: Ctx) -> bool:
    if ctx.name not in NETCATS and ctx.name != "telnet":
        return False
    words = [a for a in ctx.view.args if not a.startswith("-")]
    return len(words) >= 2 and bool(re.fullmatch(r"[\w.-]+", words[0])) and bool(re.fullmatch(r"\d{2,5}", words[1]))


def listen_socket(ctx: Ctx) -> bool:
    args = ctx.view.args
    if ctx.name in NETCATS:
        return any(re.fullmatch(r"-\w*l\w*", a) for a in args)
    if ctx.name == "socat":
        return any(re.search(r"(?:TCP4?|UDP)-LISTEN", a) for a in args)
    if re.fullmatch(r"python[\d.]*", ctx.name):
        return args[:1] == ["-m"] and args[1:2] in (["http.server"], ["SimpleHTTPServer"])
    return ctx.name == "php" and args[:1] == ["-S"] and args[1:2] != [] and args[1].startswith("0.0.0.0")


def download_tool(ctx: Ctx) -> bool:
    args = ctx.view.args
    if ctx.name in DOWNLOAD_TOOLS:
        return bool(args)
    if ctx.name == "git":
        return _subcommand(args)[0] == "lfs"
    if ctx.name == "gh":
        return args[:1] in (["release"], ["repo"], ["api"])
    if ctx.name == "aws":
        return args[:1] == ["s3"]
    return ctx.name == "az" and args[:1] == ["storage"]


def system_install(ctx: Ctx) -> bool:
    args = ctx.view.args
    if ctx.name in SYSTEM_INSTALLERS:
        return any(re.fullmatch(r"-[SU]\w*", a) for a in args) or args[:1] and args[0] in INSTALL_VERBS
    if ctx.name in ("docker", "podman"):
        return args[:1] and args[0] in ("pull", "run", "build", "create", "compose")
    return False


# ---- execution from world-writable places ----

def exec_from_temp(ctx: Ctx) -> bool:
    name, args = ctx.name, ctx.view.args
    if ctx.view.name.startswith("/") and in_temp(ctx.view.name, ctx.hook):
        return True
    if name == "chmod":
        return any(in_temp(a, ctx.hook) for a in operands(args))
    if name in ("source", ".") or name in SHELLS or interpreter(name):
        for arg in args:
            if arg.startswith("-"):
                continue
            return in_temp(arg, ctx.hook)
    return False


# ---- named tools: the program, not a string that mentions it ----

def _named(*names: str) -> Callable[[Ctx], bool]:
    wanted = frozenset(names)
    return lambda ctx: ctx.name in wanted


def immutable_attr(ctx: Ctx) -> bool:
    return ctx.name == "chattr" and any(re.fullmatch(r"[+=][a-zA-Z]*i[a-zA-Z]*", a) for a in ctx.view.args)


CMD_RULES: tuple[CmdRule, ...] = (
    CmdRule("pipe-to-shell", "warning", "Downloads remote code and executes it directly", pipe_to_shell, "all"),
    CmdRule("base64-exec", "warning", "Decodes an obfuscated payload and executes it", base64_exec, "all"),
    CmdRule("decode-exec", "warning", "Decodes or decompresses a hidden payload and executes it", decode_exec, "all"),
    CmdRule("network-pipe-shell", "warning", "Pipes data from a raw network connection into a shell", network_pipe_shell, "all"),
    CmdRule("fetched-xargs-exec", "warning", "Hands downloaded data to a shell or interpreter through xargs", xargs_exec, "all"),
    CmdRule("echo-to-shell", "info", "Pipes a string into a shell", echo_to_shell, "code"),
    CmdRule("sudoers-passwd-write", "warning", "Writes to sudoers or the account databases", account_write),
    CmdRule("pacman-config-write", "warning", "Modifies pacman/makepkg configuration or its keyring directly", pacman_config_write),
    CmdRule("setuid-shell", "warning", "Sets the setuid bit on a shell/interpreter (privilege-escalation backdoor)", setuid_shell),
    CmdRule("ld-preload-file", "warning", "Modifies /etc/ld.so.preload (rootkit technique)", ld_preload_file, "all"),
    CmdRule("ssh-authorized-keys", "warning", "Touches SSH authorized_keys (backdoor access)", authorized_keys, "all"),
    CmdRule("find-delete-root", "warning", "Deletes files across the system or home directory", find_delete_root),
    CmdRule("recursive-perm-root", "warning", "Recursively changes permissions or ownership of / or the home directory", recursive_perm_root),
    CmdRule("disk-wipe", "warning", "Writes to or wipes a raw disk device", disk_wipe),
    CmdRule("world-writable", "info", "Makes files world-writable", world_writable),
    CmdRule("credential-paths", "info", "Accesses credential, wallet, history or browser-profile data in the user's home", credential_paths),
    CmdRule("read-shadow", "info", "Reads the password hash database", read_shadow),
    CmdRule("home-archive", "info", "Archives the user's home directory", home_archive),
    CmdRule("build-time-download", "info", "Downloads at build time, bypassing source checksums", build_time_download, "build"),
    CmdRule("install-hook-network", "info", "Install hook uses the network or a package registry", install_hook_network, "install"),
    CmdRule("curl-in-substitution", "info", "Downloads inside a command substitution (runs whenever the file is parsed)", curl_in_substitution),
    CmdRule("curl-upload", "info", "Uploads a local file to a remote host", curl_upload),
    CmdRule("remote-copy", "info", "Copies files to or from a remote host", remote_copy),
    CmdRule("vcs-fetch", "info", "Fetches code from a remote repository during the build or install", vcs_fetch),
    CmdRule("ip-download", "info", "Downloads from a raw IP address", ip_download),
    CmdRule("raw-socket-connect", "info", "Opens a raw network connection", raw_socket_connect),
    CmdRule("listen-socket", "info", "Starts a network listener", listen_socket),
    CmdRule("download-tool", "info", "Uses a download tool at build time", download_tool),
    CmdRule("system-install", "info", "Installs software or pulls container images from inside the package script", system_install),
    CmdRule("rm-root", "warning", "Deletes the root or home directory", rm_root, "all"),
    CmdRule("rm-system-dir", "warning", "Deletes a top-level system directory", rm_system_dir),
    CmdRule("home-persistence-write", "warning",
            "Writes to a shell rc, autostart entry, user unit or authorized_keys from the build", home_persistence_write, "build"),
    CmdRule("sudo", "info", "Calls sudo/su; packaging scripts should not", uses_privilege, outer_only=True),
    CmdRule("setuid", "info", "Sets the setuid/setgid bit", setuid_bit),
    CmdRule("exec-from-tmp", "info", "Makes executable or runs files from a world-writable directory", exec_from_temp),
    CmdRule("kernel-module", "info", "Loads or unloads kernel modules", _named("insmod", "rmmod", "modprobe")),
    CmdRule("setcap", "info", "Grants file capabilities", _named("setcap")),
    CmdRule("sudoers-remove", "info",
            "Deletes a file under /etc/sudoers.d (it may hold a restriction, or belong to someone else)", sudoers_remove),
    CmdRule("apparmor-unload", "info", "Unloads an AppArmor profile", apparmor_unload),
    CmdRule("home-delete", "info", "Deletes files in the user's home", home_delete),
    CmdRule("install-hook-persistence", "info", "Install hook sets up persistence (cron, services, shell rc)",
            hook_persistence, "install"),
    CmdRule("pacman-key", "info", "Changes the pacman trust keyring", _named("pacman-key")),
    CmdRule("chattr-immutable", "info", "Makes files immutable (hard to remove)", immutable_attr),
    CmdRule("user-management", "info", "Creates or modifies system users",
            _named("useradd", "usermod", "adduser", "chpasswd", "gpasswd")),
    CmdRule("background-exec", "info", "Starts processes that outlive the build or install",
            _named("nohup", "setsid", "disown"), outer_only=True),
    CmdRule("live-system-write", "info", "Writes to the live system instead of $pkgdir", live_system_write, "build"),
    CmdRule("install-system-files", "info", "Install hook edits sensitive system files", hook_system_files, "install"),
)

IDS = frozenset(r.id for r in CMD_RULES)
DATAFLOW_IDS = frozenset({"fetch-then-execute"})
# no pattern twin: these look at what a command does to a path, which a line of text cannot say
STRUCTURED_ONLY = frozenset({"home-persistence-write", "fetch-then-execute", "fetched-xargs-exec"})


def _applies(scope: str, parsed: ParsedFile) -> bool:
    return (
        scope == "all"
        or (scope == "code" and not parsed.is_patch)
        or (scope == "build" and not parsed.is_patch and not parsed.is_install)
        or (scope == "install" and parsed.is_install)
    )


# ---- dataflow: a file fetched earlier and run later ----

_OUTPUT_FLAGS = {"curl": ("-o", "--output"), "wget": ("-O", "--output-document"), "wget2": ("-O", "--output-document"),
                 "aria2c": ("-o", "--out"), "axel": ("-o", "--output")}
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def _fetched_files(command: Command) -> list[str]:
    """Where a download command puts the file: -o/-O/--output, a redirect, or the URL's own name."""
    name = base(command.name)
    if name not in FETCHERS:
        return []
    args, found = list(command.args), []
    short, long = _OUTPUT_FLAGS.get(name, ("-o", "--output"))
    for index, arg in enumerate(args):
        if (arg == short or (arg.startswith("-") and not arg.startswith("--") and len(arg) > 2 and arg[-1] == short[1])) \
                and index + 1 < len(args):
            found.append(args[index + 1])           # -o f, or a cluster ending in the flag: -qO f, -sLo f
        elif arg.startswith(long + "="):
            found.append(arg.split("=", 1)[1])
        elif len(arg) > 2 and arg.startswith(short) and not arg.startswith("--") and arg[1] == short[1]:
            found.append(arg[2:])
    found += [target for op, target in command.redirects if op in (">", ">>", ">|")]
    if not found and (("O" in flags(args) and name == "curl") or name in ("wget", "wget2")):
        found += [posixpath.basename(a.split("?", 1)[0].rstrip("/")) for a in args if _URL.match(a)]
    return [f for f in found if f and f != "-" and "$" not in f.split("/")[-1]]


def _runs(command: Command, files: dict[str, int]) -> str | None:
    """The fetched file this command executes, if it does."""
    name = base(command.name)
    candidates: list[str] = []
    if command.name.startswith(("./", "/")) or command.name in files:
        candidates.append(command.name)
    if name in ("source", ".") or name in SHELLS or interpreter(name):
        candidates += [a for a in operands(command.args)[:1]] if not (flags(command.args) & {"c", "e", "m"}) else []
    for path in candidates:
        key = posixpath.normpath(path)
        if key in files:
            return key
    return None


def fetch_then_execute(parsed: ParsedFile) -> list[Finding]:
    """`curl -o f URL; sh f`, `wget URL; ./name`, `curl URL > f; chmod +x f; ./f`: the same trust as
    `curl | sh`, with a step in between that a pipe-only rule never sees."""
    findings: list[Finding] = []
    fetched: dict[str, int] = {}
    reported: set[int] = set()
    for pc in parsed.commands:
        piped_from_fetch = None
        for view in views(pc.command):
            writes = [path for verb, path in file_accesses(view, True) if verb == "write"] if pc.command.piped else []
            if writes:                             # `curl x | tee f`, `curl x | dd of=f`, `curl x | sed ... > f`
                if piped_from_fetch is None:
                    piped_from_fetch = "fetch" in pc.upstream_tags(command_tags)
                for path in writes if piped_from_fetch else ():
                    fetched.setdefault(posixpath.normpath(path), pc.line)
            hit = _runs(view, fetched)
            if hit and pc.line not in reported:
                reported.add(pc.line)
                findings.append(Finding("warning", f"Downloads a file and then executes it ({hit}, fetched on line "
                                        f"{fetched[hit]}): {pc.text.strip()[:120]}", parsed.name, pc.line, "fetch-then-execute"))
            for path in _fetched_files(view):
                fetched.setdefault(posixpath.normpath(path), pc.line)
    return findings


def check(parsed: ParsedFile) -> list[Finding]:
    """Findings from the structured rules, one per (rule, line)."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    rules = [r for r in CMD_RULES if _applies(r.scope, parsed)]
    for pc in parsed.commands:
        for depth, view in enumerate(views(pc.command)):
            ctx = Ctx(pc, view, base(view.name), depth == 0, parsed.is_install, parsed)
            for rule in rules:
                if (rule.id, pc.line) in seen or (rule.outer_only and depth):
                    continue
                if rule.check(ctx):
                    seen.add((rule.id, pc.line))
                    findings.append(Finding(rule.severity, f"{rule.message}: {pc.text.strip()[:120]}",
                                            parsed.name, pc.line, rule.id))
    findings += fetch_then_execute(parsed)
    return findings
