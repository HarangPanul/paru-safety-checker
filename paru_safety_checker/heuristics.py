"""Rule-based pre-scan of AUR package files.

Deterministic, free, and independent of the model: a `danger` finding here blocks the
install even if the AI is unavailable or has been talked into answering "safe".
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Finding, worst

# Package / npm names from real incidents (Arch AUR notice, July 2025; npm payload campaign).
KNOWN_BAD_PACKAGES = frozenset({"librewolf-fix-bin", "firefox-patch-bin", "zen-browser-patched-bin"})
KNOWN_BAD_NPM = ("atomic-lockfile", "js-lockfile")

SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rb.gy"})
PASTE_HOSTS = frozenset({
    "pastebin.com", "paste.ee", "transfer.sh", "0x0.st", "anonfiles.com", "ghostbin.com",
    "cdn.discordapp.com", "hastebin.com", "termbin.com",
})
VCS_PREFIXES = ("git+", "svn+", "hg+", "bzr+", "fossil+")
SUMS_RE = re.compile(r"^(?:md5|sha1|sha224|sha256|sha384|sha512|b2|ck)sums(_\w+)?$")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    scope: str = "all"  # all | code (not patches) | build (PKGBUILD & scripts) | install (*.install)
    comments: bool = False  # also match inside full-line comments


def _r(id: str, severity: str, pattern: str, message: str, scope: str = "all",
       comments: bool = False, flags: int = 0) -> Rule:
    return Rule(id, severity, re.compile(pattern, flags), message, scope, comments)


_FETCH = r"\b(?:curl|wget)\b"
_SHELL = r"(?:(?:ba|z|da|k)?sh|python[\d.]*|perl|ruby|node)"

RULES: tuple[Rule, ...] = (
    _r("pipe-to-shell", "danger",
       rf"{_FETCH}[^|]*\|\s*(?:sudo\s+)?{_SHELL}\b"
       rf"|\b(?:ba|z|da)?sh\b[^\n]*<\(\s*(?:curl|wget)\b"
       rf"|\b(?:ba|z|da)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b"
       rf"|\beval\b[^\n]*\$\(\s*(?:curl|wget)\b",
       "Downloads remote code and executes it directly"),
    _r("base64-exec", "danger",
       r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\beval\b[^\n]*\bbase64\b",
       "Decodes an obfuscated payload and executes it"),
    _r("reverse-shell", "danger",
       r"/dev/(?:tcp|udp)/|\bnc(?:at)?\b[^\n]*\s-\w*e\b|\bbash\s+-i\b[^\n]*>&|\bmkfifo\b[^\n]*\bnc\b|\bsocat\b[^\n]*exec:",
       "Looks like a reverse shell"),
    _r("rm-root", "danger",
       r"\brm\s+(?:-\w+\s+)*(?:/|~|\$HOME|\"\$HOME\")/?\s*(?:$|[;&|])",
       "Deletes the root or home directory"),
    _r("ssh-authorized-keys", "danger", r"authorized_keys", "Touches SSH authorized_keys (backdoor access)"),
    _r("ld-preload-file", "danger", r"/etc/ld\.so\.preload", "Modifies /etc/ld.so.preload (rootkit technique)"),
    _r("prompt-injection", "danger",
       r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts?)"
       r"|you\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|language\s+model|security\s+reviewer)"
       r"|(?:this|the)\s+package\s+is\s+(?:completely\s+)?safe|mark\s+(?:this|it)\s+as\s+safe|report_verdict",
       "Text addressed to an AI reviewer (prompt-injection attempt)", comments=True, flags=re.IGNORECASE),
    _r("known-bad-npm", "danger", r"\b(?:" + "|".join(map(re.escape, KNOWN_BAD_NPM)) + r")\b",
       "References an npm package used in a known AUR malware campaign"),
    _r("private-key-or-wallet", "danger", r"\bid_(?:rsa|ed25519|ecdsa)\b|\bwallet\.dat\b",
       "Reads SSH private keys or crypto wallets"),
    _r("credential-paths", "caution",
       r"(?:~|\$HOME|/home/[^/\s]+)/\.(?:ssh|gnupg|aws|kube|mozilla|password-store|config/(?:google-chrome|chromium|BraveSoftware))\b",
       "Accesses credential or browser-profile directories in the user's home", scope="code"),
    _r("curl-upload", "caution",
       rf"{_FETCH}[^\n]*(?:\s-d\s*@|--data(?:-binary|-raw|-urlencode)?\s+@|\s-F\s+\S*=@|--upload-file|\s-T\s)",
       "Uploads a local file to a remote host", scope="code"),
    _r("ld-preload-env", "caution", r"\bLD_PRELOAD\b", "Uses LD_PRELOAD", scope="code"),
    _r("eval", "caution", r"\beval\b", "Uses eval", scope="code"),
    _r("base64-decode", "caution", r"\bbase64\s+(?:-d|--decode|-D)\b", "Decodes base64 data", scope="code"),
    _r("long-encoded-blob", "caution", r"[A-Za-z0-9+/]{200,}={0,2}",
       "Contains a long encoded blob that cannot be reviewed", scope="code"),
    _r("sudo", "caution", r"(?:^|[;&|(]\s*)(?:sudo|su)\b", "Calls sudo/su; packaging scripts should not", scope="code"),
    _r("setuid", "caution", r"\bchmod\b\s+(?:-\w+\s+)*(?:[0-7]?[4-7][0-7]{3}|[ugoa]*\+s)\b",
       "Sets the setuid/setgid bit", scope="code"),
    _r("build-time-download", "caution", rf"{_FETCH}\s",
       "Downloads at build time, bypassing source checksums", scope="build"),
    _r("registry-install", "caution", r"\b(?:pip3?\s+install|npm\s+(?:install|i)\b|gem\s+install|cargo\s+install)",
       "Installs from a package registry at build time; verify what it pulls in", scope="build"),
    _r("install-hook-network", "caution",
       rf"{_FETCH}|\bncat?\b|\bgit\s+clone\b|\b(?:pip3?\s+install|npm\s+(?:install|i)\b|gem\s+install|cargo\s+install)",
       "Install hook uses the network or a package registry", scope="install"),
    _r("install-hook-persistence", "caution",
       r"\bcrontab\b|/etc/cron|\bsystemctl\b[^\n]*\b(?:enable|start)\b|"
       r"(?:~|\$HOME|/home/[^/\s]+|/root)/\.(?:bashrc|zshrc|profile|bash_profile|zprofile|config/autostart)",
       "Install hook sets up persistence (cron, services, shell rc)", scope="install"),
)


def _applies(scope: str, name: str) -> bool:
    is_install = name.endswith(".install")
    is_patch = name.endswith((".patch", ".diff"))
    return (
        scope == "all"
        or (scope == "code" and not is_patch)
        or (scope == "build" and not is_patch and not is_install)
        or (scope == "install" and is_install)
    )


def _logical_lines(text: str):
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


def _scan_lines(name: str, text: str) -> list[Finding]:
    rules = [r for r in RULES if _applies(r.scope, name)]
    findings: list[Finding] = []
    for number, line in _logical_lines(text):
        is_comment = line.lstrip().startswith("#")
        stripped = line.strip()
        hits = [
            Finding(r.severity, f"{r.message}: {stripped[:120]}", name, number, r.id)
            for r in rules
            if (r.comments or not is_comment) and r.pattern.search(stripped)
        ]
        if any(h.severity == "danger" for h in hits):
            hits = [h for h in hits if h.severity == "danger"]
        findings.extend(hits)
    return findings


def _array_items(body: str) -> list[str]:
    body = re.sub(r"(?m)(^|\s)#.*$", "", body)
    return [t.strip("'\"") for t in re.findall(r"'[^']*'|\"[^\"]*\"|\S+", body)]


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 0


def _scan_pkgbuild(name: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    sources: dict[str, list[str]] = {}
    sums: list[tuple[str, list[str], int]] = []
    for match in re.finditer(r"^\s*(\w+)=\(([^)]*)\)", text, re.M | re.S):
        key, items = match.group(1), _array_items(match.group(2))
        line = text.count("\n", 0, match.start()) + 1
        if key == "source" or key.startswith("source_"):
            sources[key[len("source"):]] = items
        elif SUMS_RE.match(key):
            sums.append((SUMS_RE.match(key).group(1) or "", items, line))

    for suffix, items in sources.items():
        for item in items:
            url = item.split("::", 1)[-1]
            if "://" not in url:
                continue
            target = url.split("+", 1)[1] if url.startswith(VCS_PREFIXES) else url
            host = (urlsplit(target).hostname or "").lower()
            line = _line_of(text, item)
            if target.startswith(("http://", "ftp://")):
                findings.append(Finding("caution", f"Source over an insecure protocol: {url}", name, line, "insecure-source"))
            if "$" in host:
                continue
            try:
                ipaddress.ip_address(host)
                findings.append(Finding("caution", f"Source is a raw IP address: {url}", name, line, "ip-source"))
            except ValueError:
                pass
            if host in SHORTENERS or host in PASTE_HOSTS:
                findings.append(Finding("caution", f"Source from a shortener/paste/anonymous host: {url}", name, line, "suspicious-host"))

    for suffix, items, line in sums:
        source_items = sources.get(suffix, [])
        for index, value in enumerate(items):
            if value != "SKIP" or index >= len(source_items):
                continue
            url = source_items[index].split("::", 1)[-1]
            if "://" in url and not url.startswith(VCS_PREFIXES):
                findings.append(Finding("caution", f"Checksum SKIP for non-VCS source: {url}", name, line, "checksum-skip"))

    for match in re.finditer(r"^\s*pkgname=\(?['\"]?([\w@.+-]+)", text, re.M):
        if re.search(r"-(?:fix|fixed|patch|patched|crack|cracked)(?:-bin|-git)?$", match.group(1)):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding("caution", f"Name suggests an unofficial patched/cracked variant: {match.group(1)}", name, line, "impersonation-name"))
    return findings


def scan(files: dict[str, str], package: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if package in KNOWN_BAD_PACKAGES:
        findings.append(Finding("danger", f"{package} was removed from the AUR as malware", "", None, "known-bad-package"))
    for name, text in files.items():
        if name == "(omitted-files)":
            findings.append(Finding("caution", "Some files were not reviewed (too large or binary)", name, None, "incomplete"))
            continue
        findings.extend(_scan_lines(name, text))
        if name == "PKGBUILD":
            findings.extend(_scan_pkgbuild(name, text))
    return findings


def level_of(findings: list[Finding]) -> str:
    level = "safe"
    for finding in findings:
        level = worst(level, finding.severity)
    return level
