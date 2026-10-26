"""Rule-based pre-scan of AUR package files.

Deterministic, free, and independent of the model: a `danger` finding here blocks the
install even if the AI is unavailable or has been talked into answering "safe".

Severities: `danger` blocks, `caution` asks the user, `info` is only a hint for the reader
and the AI (it never changes the verdict).
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
GITHUB_HOSTS = ("github.com", "github.io", "githubusercontent.com", "githubassets.com", "github.blog", "github.dev")
VCS_PREFIXES = ("git+", "svn+", "hg+", "bzr+", "fossil+")
CORE_PACKAGES = frozenset({
    "glibc", "bash", "coreutils", "pacman", "sudo", "openssh", "openssl", "systemd", "linux", "filesystem",
    "shadow", "util-linux", "gnupg", "archlinux-keyring", "pam", "grub", "polkit", "gcc-libs", "zlib", "curl",
})
PREBUILT_EXT = (".appimage", ".deb", ".rpm", ".run", ".exe", ".msi", ".jar", ".bin", ".snap", ".flatpak", ".sh")
HARMLESS_BINARY_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".icns", ".bmp", ".webp", ".xpm", ".ttf", ".otf", ".woff",
    ".woff2", ".pdf", ".gpg", ".sig", ".pgp", ".kbx",
)
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


def _evasion(*words: str) -> str:
    """Match `word` with quotes/backslashes/empty expansions spliced in (c''url, w\\get, ba${x}sh)."""
    alts = [
        re.escape(w[:i]) + r"(?:''|\"\"|\\|\$@|\$\{\w*\})" + re.escape(w[i:])
        for w in words for i in range(1, len(w))
    ]
    return r"(?:^|[\s;&|(`$])(?:" + "|".join(alts) + r")(?=[\s;&|)]|$)"


_FETCH = r"\b(?:curl|wget|aria2c)\b"
_CS = r"(?:\$\(|`)\s*"  # command substitution opener
_RUN = r"(?:sudo\s+(?:-\S+\s+)*)?(?:(?:/usr)?(?:/local)?/bin/|env\s+)?"  # optional sudo / path / env
_SH = r"(?:ba|z|da|k)?sh"
_INTERP = r"(?:python[\d.]*|perl|ruby|node|php)"
# a shell, or an interpreter reading its script from stdin (not `python -c ...`)
_EXEC_STDIN = "(?:" + _SH + r"\b|" + _INTERP + r"(?:\s+-)?\s*(?:$|[;&|)]))"
_DECODERS = r"(?:base32|xxd|openssl|rev(?![-\w])|uudecode|gunzip|gzip|zcat|bzcat|xzcat|unxz|brotli)"
# a file operation (writes, deletes, moves) that is not a harmless redirect to /dev/null or fd
_WRITE = r"(?:(?<![\d&])>>?|\btee\b|\bsed\s+-i|\bcp\b|\bmv\b|\binstall\b|\bln\b|\brm\b|\bchattr\b)"
# an absolute path that is not under $pkgdir / ${var} / "$pkgdir"
_ABS = r"(?<![\w}])(?<!dir\")(?<!DIR\")"
_PRIVATE_IP = r"(?!(?:127|0|10)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
_HOME = r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/root)"
_SYSDIRS = r"(?:usr|etc|opt|bin|sbin|lib|lib64|boot|var|root|home|srv)"

RULES: tuple[Rule, ...] = (
    # ---- danger: remote code execution and obfuscation ----
    _r("pipe-to-shell", "danger",
       _FETCH + r"[^|]*\|\s*" + _RUN + _EXEC_STDIN
       + r"|\b" + _SH + r"\s[^\n]*<\(\s*(?:curl|wget|aria2c)\b"
       + r"|(?:^|[\s;&|(])(?:source|\.)\s+<\(\s*(?:curl|wget|aria2c)\b"
       + r"|\b" + _SH + r"\s+-c\s+[\"']?" + _CS + r"(?:curl|wget|aria2c)\b"
       + r"|\beval\b[^\n]*" + _CS + r"(?:curl|wget|aria2c)\b",
       "Downloads remote code and executes it directly"),
    _r("base64-exec", "danger",
       r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*" + _RUN + _SH + r"\b|\beval\b[^\n]*\bbase64\b",
       "Decodes an obfuscated payload and executes it"),
    _r("decode-exec", "danger",
       r"\b" + _DECODERS + r"\b[^|\n]*\|\s*" + _RUN + _SH + r"\b"
       + r"|\beval\b[^\n]*\b" + _DECODERS + r"\b"
       + r"|\b" + _SH + r"\s+-c\s+[^\n]*\b(?:base64|base32|xxd|rev(?![-\w]))\b",
       "Decodes or decompresses a hidden payload and executes it"),
    _r("scripted-download-exec", "danger",
       r"\b(?:exec|eval)\s*\([^\n]*(?:urlopen|urlretrieve|requests\.get|urllib|b64decode|base64\.|marshal\.loads|zlib\.decompress)",
       "Script downloads or decodes code and runs it with exec/eval", scope="code"),
    _r("obfuscated-command-name", "danger", _evasion("curl", "wget", "bash", "base64", "python3", "eval"),
       "Command name hidden with quotes/backslashes/empty expansions", scope="code"),
    _r("reverse-shell", "danger",
       r"/dev/(?:tcp|udp)/|/inet/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n]*\s-\w*e\b"
       r"|\b" + _SH + r"\s+-i\b[^\n]*(?:>&|<&)|\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat)\b"
       r"|\bsocat\b[^\n]*(?i:exec|system):",
       "Looks like a reverse or bind shell"),
    _r("scripted-reverse-shell", "danger",
       r"(?:\bsocket\.socket\b|\bSocket\.new\b|TCPSocket|fsockopen|net\.Socket|IO::Socket|\buse\s+Socket\b)"
       r"[^\n]*(?:/bin/(?:ba|z|da)?sh|\bdup2\b|pty\.spawn|\bPopen\b|\bpopen\b|\bpassthru\b|shell_exec|proc_open|\bexecve?\b|\bsystem\s*\()"
       r"|\bpty\.spawn\s*\(",
       "Script opens a socket and attaches a shell to it", scope="code"),
    _r("network-pipe-shell", "danger",
       r"\b(?:nc|ncat|netcat|telnet|socat)\b[^|\n]*\|\s*" + _RUN + _SH + r"\b"
       r"|\bopenssl\s+s_client\b[^|\n]*\|\s*" + _RUN + _SH + r"\b",
       "Pipes data from a raw network connection into a shell"),
    _r("trap-exec", "danger",
       r"\btrap\s+(?:'[^']*(?:\b(?:curl|wget|nc|ncat|base64|eval)\b|/dev/tcp)[^']*'"
       r"|\"[^\"]*(?:\b(?:curl|wget|nc|ncat|base64|eval)\b|/dev/tcp)[^\"]*\")",
       "Trap handler runs network or obfuscated code on exit", scope="code"),
    # ---- danger: exfiltration and credential theft ----
    _r("pipe-to-network", "danger",
       r"\b(?:cat|tar|zip|base64|env|printenv|whoami|uname|hostname|hostnamectl|ifconfig|dmesg|lsblk|id)\b"
       r"[^|\n]*\|\s*(?:curl|wget|nc|ncat|netcat|socat)\b",
       "Sends local data to a remote host", scope="code"),
    _r("exfil-in-url", "danger",
       _FETCH + r"[^\n]*" + _CS + r"(?:(?:base64|tar|zip|env|printenv|whoami|hostname|hostnamectl|ifconfig)\b"
       r"|cat\s+(?:/etc/|/proc/|/root/|~|\$HOME|/home/))",
       "Embeds local data in a download/upload request", scope="code"),
    _r("exfil-webhook", "danger",
       r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site"
       r"|requestbin\.|\.m\.pipedream\.net|interact\.sh|\.oast\.(?:fun|live|site|pro|me|online)"
       r"|burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io",
       "Talks to a webhook/callback service commonly used for exfiltration", scope="code"),
    _r("private-key-or-wallet", "danger",
       r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bssh_host_\w+_key\b|\bwallet\.dat\b|\.kdbx\b",
       "Reads SSH private keys, password databases or crypto wallets"),
    _r("browser-credential-store", "danger",
       r"\bLogin Data\b|\blogins\.json\b|\bkey[34]\.db\b|\b[cC]ookies\.sqlite\b",
       "Reads browser password or cookie stores", scope="code"),
    _r("cloud-metadata", "danger", r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254",
       "Queries a cloud metadata endpoint (credential theft)", scope="code"),
    _r("ssh-authorized-keys", "danger", r"authorized_keys", "Touches SSH authorized_keys (backdoor access)"),
    # ---- danger: persistence, privilege escalation, defense evasion ----
    _r("ld-preload-file", "danger", r"/etc/ld\.so\.preload", "Modifies /etc/ld.so.preload (rootkit technique)"),
    _r("sudoers-passwd-write", "danger",
       _WRITE + r"[^\n]*" + _ABS + r"/etc/(?:sudoers(?:\.d)?|passwd|shadow|gshadow|group)\b",
       "Writes to sudoers or the account databases", scope="code"),
    _r("uid0-user", "danger", r"\b(?:useradd|usermod|adduser)\b[^\n]*(?:\s-\w*u\s*0\b|--uid[= ]0\b)",
       "Creates or changes a user to UID 0", scope="code"),
    _r("setuid-shell", "danger",
       r"\bchmod\s+(?:-\w+\s+)*(?:[ug]?\+s|[0-7]?[4-7][0-7]{3})\s+\S*(?:/(?:ba|z|da|k)?sh|/(?:python[\d.]*|perl|find|cp|env|vim|nmap|awk))\b"
       r"|\bchmod\s+(?:-\w+\s+)*(?:[ug]?\+s|[0-7]?[4-7][0-7]{3})\s+\S*/(?:tmp|dev/shm)/",
       "Sets the setuid bit on a shell/interpreter (privilege-escalation backdoor)", scope="code"),
    _r("pacman-config-write", "danger",
       _WRITE + r"[^\n]*" + _ABS + r"/etc/(?:pacman\.conf|makepkg\.conf|pacman\.d/gnupg)",
       "Modifies pacman/makepkg configuration or its keyring directly", scope="code"),
    _r("pacman-sig-disable", "danger", r"\bSigLevel\s*=\s*(?:Never\b|Optional\s+TrustAll\b|TrustAll\b)",
       "Disables pacman signature verification", scope="code"),
    _r("security-tool-disable", "danger",
       r"\bufw\s+disable\b|\bsetenforce\s+0\b|\bauditctl\s+-e\s*0\b|\bapparmor_parser\s+-R\b|\baa-teardown\b"
       r"|\bsystemctl\s+(?:stop|disable|mask)\s+[^\n]*\b(?:firewalld|ufw|apparmor|auditd|nftables|iptables|fail2ban|clamd|rkhunter|aide)\b"
       r"|\bpkill\s+(?:-\w+\s+)*(?:auditd|clamd|osqueryd|fail2ban\S*)",
       "Disables a firewall, auditing or security tool", scope="code"),
    _r("history-tamper", "danger",
       r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE\s*=\s*(?:/dev/null|\"\")|\bHISTSIZE\s*=\s*0\b|\bset\s+\+o\s+history\b"
       r"|\b(?:rm|truncate|shred)\b[^\n]*\s/var/log/(?:auth|secure|syslog|messages|wtmp|btmp|lastlog|audit)"
       r"|(?<![\d&])>\s*/var/log/(?:auth|secure|syslog|messages|wtmp|btmp|lastlog)",
       "Erases shell history or system logs (anti-forensics)", scope="code"),
    _r("rootkit-names", "danger",
       r"\b(?:diamorphine|azazel|jynx2|beurk|bdvl|vlany|libprocesshider|suterusu|knark|kinsing|kdevtmpfsi|kthreaddi)\b",
       "Names a known rootkit or malware family", scope="code"),
    _r("mining-pool", "danger",
       r"stratum\+(?:tcp|ssl|tls)://|--donate-level|\b(?:xmrig|minerd|cpuminer)\b[^\n]*(?:\s-o\s|--url\b)"
       r"|\b(?:minexmr|supportxmr|nanopool|2miners|f2pool|hashvault|moneroocean|c3pool|unmineable|nicehash|ethermine|herominers|slushpool|viabtc|hiveon)\.(?:com|org|net|io|to|cc|pro)\b",
       "Configures a cryptocurrency mining pool", scope="code"),
    # ---- danger: destruction ----
    _r("rm-root", "danger",
       r"\brm\s+(?:-\w+\s+)*(?:--\s+)?(?:/|~|\$HOME|\"\$HOME\")/?\*?\s*(?:$|[;&|])|--no-preserve-root",
       "Deletes the root or home directory"),
    _r("rm-system-dir", "danger",
       r"\brm\s+(?:-\w+\s+)+(?:--\s+)?/(?:etc|usr|bin|sbin|lib|lib64|boot|var|home|root|opt|srv|dev|sys|proc)/?\*?\s*(?:$|[;&|])",
       "Deletes a top-level system directory", scope="code"),
    _r("find-delete-root", "danger",
       r"\bfind\s+(?:/|~|\$HOME|\"\$HOME\"|/home|/etc|/usr)\s[^\n]*(?:-delete\b|-exec\s+rm\b)",
       "Deletes files across the system or home directory", scope="code"),
    _r("recursive-perm-root", "danger",
       r"\b(?:chmod|chown)\s+(?:-\w+\s+)*-\w*R\w*\s+(?:-\w+\s+)*\S+\s+(?:/|~|\$HOME)/?\*?\s*(?:$|[;&|])",
       "Recursively changes permissions or ownership of / or the home directory", scope="code"),
    _r("disk-wipe", "danger",
       r"\bdd\b[^\n]*\bof=/dev/(?:sd|nvme|vd|hd|xvd|mmcblk|disk)"
       r"|\b(?:mkfs(?:\.\w+)?|wipefs|blkdiscard|shred)\b[^\n]*\s/dev/(?:sd|nvme|vd|hd|xvd|mmcblk|disk)"
       r"|\bsgdisk\s+(?:--zap-all|-Z)\b|(?<![\d&])>\s*/dev/(?:sd|nvme|vd|hd|xvd|mmcblk)",
       "Writes to or wipes a raw disk device", scope="code"),
    _r("fork-bomb", "danger", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:", "Fork bomb", scope="code"),
    # ---- danger: attacks on the reviewer ----
    _r("prompt-injection", "danger",
       r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)"
       r"|disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|instructions)"
       r"|forget\s+(?:all\s+|your\s+|the\s+)?(?:previous|prior|above|instructions|rules)"
       r"|new\s+instructions?\s*:"
       r"|you\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|language\s+model|security\s+reviewer)"
       r"|(?:this|the)\s+package\s+is\s+(?:completely\s+|totally\s+)?(?:safe|benign|harmless)"
       r"|mark\s+(?:this|it)\s+as\s+(?:safe|benign)"
       r"|do\s+not\s+(?:flag|alert)\s+(?:this|it|the\s+user|anything)"
       r"|(?:respond|answer|reply|output)\s+(?:only\s+)?(?:with\s+)?[\"']?safe\b"
       r"|</?\s*(?:system|assistant|instructions?)\s*>|\"level\"\s*:\s*\"safe\"|report_verdict",
       "Text addressed to an AI reviewer (prompt-injection attempt)", comments=True, flags=re.IGNORECASE),
    _r("prompt-delimiter-forgery", "danger", r"={3,}\s*(?:BEGIN|END)\s+FILE\b|Nonce\s+for\s+file\s+markers",
       "Imitates the reviewer's file delimiters (prompt-injection attempt)", comments=True),
    _r("known-bad-npm", "danger", r"\b(?:" + "|".join(map(re.escape, KNOWN_BAD_NPM)) + r")\b",
       "References an npm package used in a known AUR malware campaign"),
    # ---- caution: credentials and recon ----
    _r("credential-paths", "caution",
       _HOME + r"/\.(?:ssh|gnupg|aws|kube|azure|mozilla|thunderbird|password-store|electrum|bitcoin|ethereum|monero|netrc"
       r"|npmrc|pypirc|git-credentials|bash_history|zsh_history|python_history|docker/config\.json"
       r"|config/(?:google-chrome|chromium|BraveSoftware|vivaldi|opera|microsoft-edge|discord|Slack|Signal|Element|gh|rclone|gcloud|solana|1Password|Bitwarden|Code))\b",
       "Accesses credential, wallet, history or browser-profile data in the user's home", scope="code"),
    _r("secret-env-vars", "caution",
       r"\$\{?(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN"
       r"|PYPI_TOKEN|DOCKER_PASSWORD|ANTHROPIC_API_KEY|OPENAI_API_KEY|HF_TOKEN|SSH_AUTH_SOCK|GPG_PASSPHRASE|SLACK_TOKEN|DISCORD_TOKEN)\b",
       "Reads secret tokens from the environment", scope="code"),
    _r("process-snooping", "caution",
       r"/proc/(?:self|\d+|\*)/(?:environ|mem|maps)\b|\bptrace\b|\bgdb\s+(?:-\w+\s+)*-p\b|\bstrace\s+(?:-\w+\s+)*-p\b",
       "Reads other processes' memory or environment", scope="code"),
    _r("keylogger", "caution", r"\bpynput\b|\blogkeys\b|\bxinput\s+test(?:-xi2)?\b|/dev/input/event\d|\bkeylogger\b",
       "Captures keyboard input", scope="code"),
    _r("read-shadow", "caution", _ABS + r"/etc/(?:shadow|gshadow)\b", "Reads the password hash database", scope="code"),
    _r("crypto-address", "caution",
       r"\bbc1[ac-hj-np-z02-9]{25,60}\b|\b0x[0-9a-fA-F]{40}\b|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
       "Contains a cryptocurrency wallet address", scope="code"),
    _r("home-archive", "caution",
       r"\b(?:tar|zip|7z|7za|rar)\b[^\n]*(?:\s|=)[\"']?" + _HOME + r"(?:/|\s|[\"']|$)",
       "Archives the user's home directory", scope="code"),
    _r("home-delete", "caution", r"\brm\s+[^\n]*" + _HOME + r"/(?:\.|\w)", "Deletes files in the user's home", scope="code"),
    _r("curl-upload", "caution",
       _FETCH + r"[^\n]*(?:\s-d\s*@|--data(?:-binary|-raw|-urlencode)?\s+@|\s-F\s+\S*=@|--upload-file|\s-T\s)",
       "Uploads a local file to a remote host", scope="code"),
    _r("remote-copy", "caution", r"\b(?:scp|sftp|rsync)\b[^\n]*\s[\w.-]+@[\w.-]+:", "Copies files to or from a remote host", scope="code"),
    _r("dns-exfil", "caution", r"(?:^|[;&|]\s*)(?:dig|nslookup)\b[^\n]*(?:\$\(|`)", "DNS lookup built from command output", scope="code"),
    _r("recon-ip-lookup", "caution",
       r"\b(?:ifconfig\.(?:me|co)|ipinfo\.io|api\.ipify\.org|icanhazip\.com|checkip\.amazonaws\.com|ip-api\.com|ipecho\.net|wtfismyip\.com|myexternalip\.com|ident\.me)\b",
       "Looks up the machine's public IP", scope="code"),
    # ---- caution: network and infrastructure ----
    _r("ip-download", "caution",
       r"(?:curl|wget|aria2c|git\s+clone)\b[^\n]*https?://" + _PRIVATE_IP + r"\d{1,3}(?:\.\d{1,3}){3}\b",
       "Downloads from a raw IP address", scope="code"),
    _r("raw-socket-connect", "caution", r"\b(?:nc|ncat|netcat|telnet)\b\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b",
       "Opens a raw network connection", scope="code"),
    _r("listen-socket", "caution",
       r"\b(?:nc|ncat|netcat)\b\s+(?:-\w+\s+)*-\w*l\w*\b|\bsocat\b[^\n]*(?:TCP4?-LISTEN|UDP-LISTEN)"
       r"|\bpython[\d.]*\s+-m\s+(?:http\.server|SimpleHTTPServer)\b|\bphp\s+-S\s+0\.0\.0\.0",
       "Starts a network listener", scope="code"),
    _r("dynamic-dns", "caution",
       r"\b[\w-]+\.(?:ddns\.net|duckdns\.org|no-ip\.(?:org|com|biz)|hopto\.org|zapto\.org|sytes\.net|servebeer\.com"
       r"|serveftp\.com|myftp\.(?:org|biz)|3utilities\.com|dyndns\.\w+|freedns\.\w+|redirectme\.net)\b",
       "Uses a dynamic-DNS host", scope="code"),
    _r("tunnel-service", "caution",
       r"\b(?:ngrok\.io|ngrok-free\.app|ngrok\.com|serveo\.net|localhost\.run|trycloudflare\.com|loca\.lt|pagekite\.me|bore\.pub|tunnelto\.dev)\b",
       "Uses a tunnelling service", scope="code"),
    _r("tor-onion", "caution", r"\.onion\b|\btor2web\b|socks5h?://127\.0\.0\.1:9050", "Uses Tor / onion services", scope="code"),
    _r("free-tld-url", "caution", r"https?://[^/\s'\"]*\.(?:tk|ml|ga|cf|gq)(?:[/:\s'\"]|$)",
       "URL on a free throwaway TLD", scope="code"),
    _r("punycode-url", "caution", r"https?://[^/\s'\"]*\bxn--", "URL with a punycode (homograph) host", scope="code"),
    _r("embedded-credentials", "caution", r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:[^/\s@'\"]+@[\w.-]+",
       "URL with embedded credentials", scope="code"),
    _r("docker-privileged", "caution",
       r"\bdocker\s+run\b[^\n]*(?:--privileged|-v\s+/:/|--pid=host|--net=host|--cap-add)|/(?:var/)?run/docker\.sock",
       "Uses a privileged container or the Docker socket", scope="code"),
    # ---- caution: execution tricks ----
    _r("exec-from-tmp", "caution",
       r"\bchmod\b[^\n]*\s\S*/(?:tmp|dev/shm|var/tmp)/"
       r"|(?:^|[\s;&|(])(?:source|\.|(?:ba|z|da)?sh|python[\d.]*|perl|ruby|node)\s+(?:-\w+\s+)*/(?:tmp|dev/shm|var/tmp)/"
       r"|(?:^|[;&|(]\s*)(?:sudo\s+)?/(?:tmp|dev/shm|var/tmp)/\S",
       "Makes executable or runs files from a world-writable directory", scope="code"),
    _r("inline-script-network", "caution",
       r"\b" + _INTERP + r"\s+-[ce]\w*\s+[^\n]*(?:urllib|urlopen|requests\.|http\.client|\bLWP\b|Net::HTTP|open-uri|XMLHttpRequest|\bfetch\(|fsockopen|\bsocket\b)",
       "Inline script performs network access", scope="code"),
    _r("echo-to-shell", "caution", r"\b(?:echo|printf)\b[^|\n]*\|\s*" + _RUN + _SH + r"\b", "Pipes a string into a shell", scope="code"),
    _r("hex-escapes", "caution",
       r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:\\[0-7]{3}){6,}|(?:\\u[0-9a-fA-F]{4}){6,}", "Long run of escaped characters (obfuscation)", scope="code"),
    _r("ifs-evasion", "caution", r"\w\$\{IFS\}\w|\$IFS\$\d", "Uses $IFS to hide whitespace between command words", scope="code"),
    _r("rot13", "caution", r"n-za-m|N-ZA-M", "ROT13 decoding", scope="code"),
    _r("substring-obfuscation", "caution", r"(?:\$\{\w+:\d+:\d+\}.*?){4,}", "Builds strings from variable slices (obfuscation)", scope="code"),
    _r("background-exec", "caution", r"\b(?:nohup|setsid|disown)\b", "Starts processes that outlive the build or install", scope="code"),
    _r("delayed-exec", "caution",
       r"\bsleep\s+\d+\s*(?:;|&&)\s*(?:curl|wget|nc|ncat|bash|sh|python[\d.]*|\./)|\(\s*sleep\s+\d+\s*;[^\n]*\)\s*&"
       r"|\bat\s+(?:now|[0-9]{1,2}:[0-9]{2})\b|\bsystemd-run\b",
       "Schedules code to run later", scope="code"),
    _r("path-hijack", "caution", r"\b(?:export\s+)?PATH=[\"']?(?:\.:|:\.|/tmp|/dev/shm|/var/tmp)",
       "Puts the current or a temp directory in PATH", scope="code"),
    _r("command-hijack", "caution",
       r"\balias\s+(?:sudo|su|ssh|pacman|paru|yay|git|curl|wget|cat|ls|cd)=|^(?:function\s+)?(?:sudo|su|ssh|pacman|paru|yay)\s*\(\s*\)",
       "Shadows a common command", scope="code"),
    _r("ld-preload-env", "caution", r"\bLD_PRELOAD\b", "Uses LD_PRELOAD", scope="code"),
    _r("base64-decode", "caution", r"\bbase64\s+(?:-d|--decode|-D)\b", "Decodes base64 data", scope="code"),
    _r("long-encoded-blob", "caution", r"[A-Za-z0-9+/]{200,}={0,2}", "Contains a long encoded blob that cannot be reviewed", scope="code"),
    _r("miner-software", "caution",
       r"\b(?:xmrig|minerd|cpuminer(?:-multi)?|ethminer|nbminer|lolminer|phoenixminer|cgminer|bfgminer|t-rex|gminer|teamredminer)\b",
       "References cryptocurrency mining software", scope="code"),
    _r("offensive-tools", "caution",
       r"\b(?:meterpreter|msfvenom|mimikatz|lazagne|linpeas|cobaltstrike|pwncat)\b", "References an offensive-security tool", scope="code"),
    # ---- caution: system modification ----
    _r("sudo", "caution", r"(?:^|[;&|(]\s*)(?:sudo|su)\b", "Calls sudo/su; packaging scripts should not", scope="code"),
    _r("setuid", "caution", r"\bchmod\b\s+(?:-\w+\s+)*(?:[0-7]?[4-7][0-7]{3}|[ugoa]*\+s)\b", "Sets the setuid/setgid bit", scope="code"),
    _r("chattr-immutable", "caution", r"\bchattr\s+[^\n]*\+i\b", "Makes files immutable (hard to remove)", scope="code"),
    _r("priv-group", "caution",
       r"\busermod\b[^\n]*-\w*[aG]+\w*\s+\S*(?:wheel|sudo|root|adm|disk|docker|lxd|libvirt)\b"
       r"|\bgpasswd\b[^\n]*-a[^\n]*(?:wheel|sudo|root|docker)",
       "Adds a user to a privileged group", scope="code"),
    _r("kernel-module", "caution", r"\b(?:insmod|rmmod|modprobe)\b", "Loads or unloads kernel modules", scope="code"),
    _r("weaken-mitigations", "caution",
       r"ptrace_scope|randomize_va_space|mmap_min_addr|kptr_restrict\s*=\s*0|dmesg_restrict\s*=\s*0"
       r"|unprivileged_bpf_disabled\s*=\s*0|modules_disabled\s*=\s*0|\bmodule\.sig_enforce|lockdown=none|\bselinux=0|\bapparmor=0"
       r"|\bmitigations=off|\bnokaslr\b|\bpti=off|\bspectre_v2=off",
       "Weakens kernel hardening", scope="code"),
    _r("firewall-flush", "caution",
       r"\b(?:ip6?tables)\s+-F\b|\bnft\s+flush\s+ruleset\b|\biptables\s+-P\s+\w+\s+ACCEPT\b", "Flushes or opens the firewall", scope="code"),
    _r("pacman-key", "caution", r"\bpacman-key\b", "Changes the pacman trust keyring", scope="code"),
    _r("skip-integrity", "caution", r"--skip(?:pgpcheck|integ|checksums|pgp)\b", "Skips signature or checksum verification", scope="code"),
    _r("alpm-hook-network", "caution", r"^\s*Exec\s*=\s*[^\n]*\b(?:curl|wget|nc|ncat|base64)\b",
       "A pacman hook runs network or obfuscated commands on every transaction", scope="code"),
    _r("self-delete", "caution",
       r"\brm\s+(?:-\w+\s+)*(?:--\s+)?\"?\$\{?(?:0|BASH_SOURCE(?:\[0\])?)\}?\"?|\bshred\b[^\n]*\$0",
       "Script deletes itself", scope="code"),
    # ---- caution: build / install hooks ----
    _r("build-time-download", "caution", r"(?<!\$\()(?<!`)" + _FETCH + r"\s", "Downloads at build time, bypassing source checksums", scope="build"),
    _r("registry-install", "caution",
       r"\b(?:pip3?\s+install|npm\s+(?:install|i)|yarn\s+add|pnpm\s+(?:add|install)|gem\s+install|cargo\s+install|go\s+install)\b"
       r"(?![^\n]*(?:--root|--prefix|--target|--no-index|--path|\.tgz|\.tar|\.whl|\.gem\b|\$\{?srcdir|\$\{?pkgdir|\s\.(?:\s|$)|\s\./))"
       r"[^\n]*\s[@A-Za-z][\w@./-]*",
       "Installs a named package from a registry at build time; verify what it pulls in", scope="build"),
    _r("live-system-write", "caution",
       r"(?:^|[;&|(]\s*)(?:sudo\s+(?:-\S+\s+)*)?(?:cp|mv|install|ln|rsync|tee|sed\s+-i\S*|chmod|chown|touch|mkdir|rm)\b[^\n;&|]*\s\"?/"
       + _SYSDIRS + r"(?:/[^\s;&|\"']*)?\"?\s*(?:$|[;&|])"
       r"|(?<![\d&])>>?\s*\"?/(?:usr|etc|opt|bin|sbin|lib|lib64|boot|var/(?!tmp)|root|home|srv)/",
       "Writes to the live system instead of $pkgdir", scope="build"),
    _r("install-hook-network", "caution",
       _FETCH + r"|\bncat?\b|\bgit\s+clone\b|\b(?:pip3?\s+install|npm\s+(?:install|i)\b|gem\s+install|cargo\s+install)",
       "Install hook uses the network or a package registry", scope="install"),
    _r("install-hook-persistence", "caution",
       r"\bcrontab\b|/etc/cron|\bsystemctl\b[^\n]*\b(?:enable|start)\b|"
       r"(?:~|\$HOME|/home/[^/\s]+|/root)/\.(?:bashrc|zshrc|profile|bash_profile|zprofile|config/autostart)",
       "Install hook sets up persistence (cron, services, shell rc)", scope="install"),
    _r("install-system-files", "caution",
       _WRITE + r"[^\n]*" + _ABS + r"(?:/etc/(?:pam\.d|ssh|ld\.so\.conf|profile|bash\.bashrc|environment|rc\.local|init\.d|crontab"
       r"|cron\.\w+|hosts|resolv\.conf|nsswitch\.conf|fstab|modules-load\.d|modprobe\.d|udev|security|pacman\.d)|/boot/|/usr/lib/security|/lib/security)",
       "Install hook edits sensitive system files", scope="install"),
    # ---- info: weak hints ----
    _r("eval", "info", r"\beval\b", "Uses eval", scope="code"),
    _r("git-clone-build", "info", r"\bgit\s+clone\b", "Clones a repository at build time (unpinned source)", scope="build"),
    _r("curl-in-substitution", "info", _CS + r"(?:curl|wget)\b", "Network access inside a command substitution", scope="code"),
    _r("registry-deps", "info", r"\b(?:npm\s+(?:ci|install|i)|pnpm\s+install|yarn\s+install|bundle\s+install)\b",
       "Installs dependencies from a registry at build time", scope="build"),
    _r("setcap", "info", r"\bsetcap\b", "Grants file capabilities", scope="code"),
    _r("world-writable", "info", r"\bchmod\s+(?:-\w+\s+)*(?:0?777|a\+rwx|ugo\+rwx|o\+w)\b", "Makes files world-writable", scope="code"),
    _r("user-management", "info", r"\b(?:useradd|usermod|adduser|chpasswd|gpasswd)\b", "Creates or modifies system users", scope="code"),
)

_TOP_DANGER = re.compile(
    r"^(?:sudo\s+(?:-\S+\s+)*)?(?:curl|wget|aria2c|nc|ncat|netcat|socat|telnet|bash|sh|dash|zsh|python[\d.]*|perl|ruby|node|php|openssl)\b"
)
_TOP_CAUTION = re.compile(r"^(?:sudo|su|eval|nohup|setsid|dd|systemctl|crontab|git\s+clone|pip3?\s+install|npm\s+(?:i|install))\b")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_ZERO_WIDTH = re.compile("[​-‍⁠﻿]")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NON_ASCII_HOST = re.compile(r"https?://[^/\s'\"<>]*[^\x00-\x7f]")
_OMITTED_RE = re.compile(r"^(?P<name>.+) \((?P<why>binary or unreadable|total size limit|symlink)\)$")


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
        severities = {h.severity for h in hits}
        if "danger" in severities:
            hits = [h for h in hits if h.severity == "danger"]
        elif "caution" in severities:
            hits = [h for h in hits if h.severity != "info"]
        findings.extend(hits)
    return findings


def _scan_toplevel(name: str, text: str) -> list[Finding]:
    """Code outside any function runs when the file is merely sourced (e.g. by an AUR helper
    resolving dependencies), long before a build is approved."""
    findings: list[Finding] = []
    brace = paren = 0
    for number, line in _logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if brace == 0 and paren == 0:
            if _TOP_DANGER.match(stripped):
                findings.append(Finding("danger", f"Runs at parse time, outside any function: {stripped[:120]}", name, number, "toplevel-exec"))
            elif _TOP_CAUTION.match(stripped):
                findings.append(Finding("caution", f"Runs at parse time, outside any function: {stripped[:120]}", name, number, "toplevel-exec"))
        bare = re.sub(r"'[^']*'|\"[^\"]*\"", "", re.sub(r"\s#.*$", "", stripped))
        brace = max(0, brace + bare.count("{") - bare.count("}"))
        paren = max(0, paren + bare.count("(") - bare.count(")"))
    return findings


def _scan_anomalies(name: str, text: str) -> list[Finding]:
    checks = [(_BIDI, "danger", "Bidirectional control character (Trojan Source: code shown differently than it runs)", "bidi-control")]
    if not name.endswith((".patch", ".diff")):
        checks += [
            (_ZERO_WIDTH, "caution", "Invisible zero-width character in the file", "zero-width"),
            (_CONTROL, "caution", "Terminal control character in the file (can hide text from the reader)", "control-chars"),
            (_NON_ASCII_HOST, "caution", "URL host with non-ASCII characters (homograph)", "homograph-host"),
        ]
    findings: list[Finding] = []
    for pattern, severity, message, rule in checks:
        for match in pattern.finditer(text):
            if match.start() == 0 and match.group() == "﻿":
                continue  # a byte-order mark is not an attack
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding(severity, message, name, line, rule))
            break
    return findings


def _array_items(body: str) -> list[str]:
    body = re.sub(r"(?m)(^|\s)#.*$", "", body)
    return [t.strip("'\"") for t in re.findall(r"'[^']*'|\"[^\"]*\"|\S+", body)]


def _variables(text: str) -> dict[str, str]:
    """Literal one-line assignments (`url="https://..."`), used to expand $url in source arrays."""
    found: dict[str, str] = {}
    for match in re.finditer(r"^\s*(\w+)=([\"']?)([^\"'\n]*)\2\s*(?:#.*)?$", text, re.M):
        if "$(" not in match.group(3) and "`" not in match.group(3):
            found.setdefault(match.group(1), match.group(3))
    return found


def _expand(value: str, variables: dict[str, str]) -> str:
    for _ in range(5):
        expanded = re.sub(
            r"\$(?:\{(\w+)\}|(\w+))",
            lambda m: variables.get(m.group(1) or m.group(2), m.group(0)),
            value,
        )
        if expanded == value:
            break
        value = expanded
    return value


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 0


def _scan_pkgbuild(name: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    arrays: dict[str, tuple[list[str], int]] = {}
    sources: dict[str, list[str]] = {}
    sums: list[tuple[str, list[str], int]] = []
    for match in re.finditer(r"^\s*(\w+)=\(([^)]*)\)", text, re.M | re.S):
        key, items = match.group(1), _array_items(match.group(2))
        line = text.count("\n", 0, match.start()) + 1
        arrays[key] = (items, line)
        if key == "source" or key.startswith("source_"):
            sources[key[len("source"):]] = items
        elif SUMS_RE.match(key):
            sums.append((SUMS_RE.match(key).group(1) or "", items, line))

    variables = _variables(text)
    remote_non_vcs: list[str] = []
    for items in sources.values():
        for item in items:
            url = _expand(item, variables).split("::", 1)[-1]
            if "://" not in url:
                continue
            is_vcs = url.startswith(VCS_PREFIXES)
            target = url.split("+", 1)[1] if is_vcs else url
            parts = urlsplit(target)
            host = (parts.hostname or "").lower()
            line = _line_of(text, item)
            if target.startswith("file://"):
                if parts.path.startswith(("/etc", "/root", "/home")):
                    findings.append(Finding("caution", f"Source reads a local file: {url}", name, line, "file-source"))
                continue
            if not is_vcs:
                remote_non_vcs.append(item)
                if parts.path.lower().endswith(PREBUILT_EXT):
                    findings.append(Finding("info", f"Source is a prebuilt binary or installer: {url}", name, line, "prebuilt-source"))
            if target.startswith(("http://", "ftp://", "git://")):
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
            if "github" in host and not any(host == h or host.endswith("." + h) for h in GITHUB_HOSTS):
                findings.append(Finding("caution", f"Host imitates GitHub: {host}", name, line, "github-lookalike"))

    if remote_non_vcs and not sums:
        findings.append(Finding("caution", "Remote sources without any checksum array", name, _line_of(text, remote_non_vcs[0]), "no-checksums"))

    for suffix, items, line in sums:
        source_items = sources.get(suffix, [])
        for index, value in enumerate(items):
            if value != "SKIP" or index >= len(source_items):
                continue
            url = _expand(source_items[index], variables).split("::", 1)[-1]
            if "://" in url and not url.startswith(VCS_PREFIXES) and not url.startswith("file://"):
                findings.append(Finding("caution", f"Checksum SKIP for non-VCS source: {url}", name, line, "checksum-skip"))

    if "replaces" in arrays:
        items, line = arrays["replaces"]
        core = sorted({re.split(r"[<>=]", i)[0] for i in items} & CORE_PACKAGES)
        if core:
            findings.append(Finding("caution", f"Replaces core system package(s): {', '.join(core)}", name, line, "replaces-core"))

    for match in re.finditer(r"^\s*pkgname=\(?['\"]?([\w@.+-]+)", text, re.M):
        if re.search(r"-(?:fix|fixed|patch|patched|crack|cracked)(?:-bin|-git)?$", match.group(1)):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding("caution", f"Name suggests an unofficial patched/cracked variant: {match.group(1)}", name, line, "impersonation-name"))
    return findings


def _scan_omitted(text: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = 0
    for line in text.splitlines()[1:]:
        match = _OMITTED_RE.match(line)
        if not match:
            continue
        parsed += 1
        name, why = match.group("name"), match.group("why")
        base = name.rsplit("/", 1)[-1]
        if why == "symlink":
            severity = "danger" if base == "PKGBUILD" or base.endswith(".install") else "caution"
            findings.append(Finding(severity, f"Symlink in the package repository (not followed): {name}", name, None, "symlink"))
        elif why == "total size limit":
            findings.append(Finding("caution", f"Not reviewed (total size limit): {name}", name, None, "incomplete"))
        elif not name.lower().endswith(HARMLESS_BINARY_EXT):
            findings.append(Finding("caution", f"Binary or unreadable file in the repository, not reviewed: {name}", name, None, "binary-in-repo"))
    if not parsed:
        findings.append(Finding("caution", "Some files were not reviewed (too large or binary)", "(omitted-files)", None, "incomplete"))
    return findings


_DOWNLOAD_RULES = frozenset({"ip-download", "build-time-download", "install-hook-network", "registry-install"})


def _correlate(name: str, findings: list[Finding]) -> list[Finding]:
    """Escalate combinations that are each only suspicious: fetch something, then run it from /tmp."""
    rules = {f.rule for f in findings}
    if "exec-from-tmp" in rules and rules & _DOWNLOAD_RULES:
        return [Finding("danger", "Downloads something and runs it from a world-writable directory (dropper pattern)", name, None, "download-and-run")]
    return []


def scan(files: dict[str, str], package: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if package in KNOWN_BAD_PACKAGES:
        findings.append(Finding("danger", f"{package} was removed from the AUR as malware", "", None, "known-bad-package"))
    for name, text in files.items():
        if name == "(omitted-files)":
            findings.extend(_scan_omitted(text))
            continue
        found = _scan_lines(name, text) + _scan_anomalies(name, text)
        if name == "PKGBUILD":
            found += _scan_pkgbuild(name, text)
        if name == "PKGBUILD" or name.endswith(".install"):
            found += _scan_toplevel(name, text)
        findings.extend(found + _correlate(name, found))
    return findings


def level_of(findings: list[Finding]) -> str:
    """Verdict level of the findings; `info` hints never raise it."""
    level = "safe"
    for finding in findings:
        if finding.severity != "info":
            level = worst(level, finding.severity)
    return level
