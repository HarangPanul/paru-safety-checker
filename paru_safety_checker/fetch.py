from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

AUR_URL = "https://aur.archlinux.org/{}.git"
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+-]*$")
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024


class FetchError(Exception):
    pass


def valid_package_name(name: str) -> bool:
    return bool(PACKAGE_RE.match(name))


def _priority(path: Path) -> tuple[int, str]:
    if path.name == "PKGBUILD":
        return (0, path.name)
    if path.suffix == ".install":
        return (1, path.name)
    return (2, str(path))


def collect_files(root: Path) -> dict[str, str]:
    """Read the reviewable text files of a package checkout, PKGBUILD first.

    Oversized files are truncated and files beyond the total budget are listed as
    omitted, always with a marker, so the reviewer knows coverage is incomplete.
    """
    candidates = [
        p for p in root.rglob("*")
        if p.is_file() and ".git" not in p.relative_to(root).parts and not p.is_symlink()
    ]
    files: dict[str, str] = {}
    total = 0
    omitted: list[str] = []
    for path in sorted(candidates, key=_priority):
        name = str(path.relative_to(root))
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            omitted.append(f"{name} (binary or unreadable)")
            continue
        if total >= MAX_TOTAL_BYTES:
            omitted.append(f"{name} (total size limit)")
            continue
        if len(raw) > MAX_FILE_BYTES:
            text = text[:MAX_FILE_BYTES] + "\n[TRUNCATED: file exceeds size limit]"
        files[name] = text
        total += min(len(raw), MAX_FILE_BYTES)
    if omitted:
        files["(omitted-files)"] = "TRUNCATED: not reviewed:\n" + "\n".join(omitted)
    return files


def fetch_package_files(package: str) -> dict[str, str] | None:
    """Clone the AUR repo of `package`; return its files, or None if it has no PKGBUILD."""
    if not valid_package_name(package):
        raise FetchError(f"invalid package name: {package!r}")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    with tempfile.TemporaryDirectory(prefix="paru-safe-") as tmp:
        dest = Path(tmp) / "pkg"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", AUR_URL.format(package), str(dest)],
            capture_output=True, text=True, env=env, timeout=120,
        )
        if result.returncode != 0:
            raise FetchError(result.stderr.strip() or "git clone failed")
        if not (dest / "PKGBUILD").is_file():
            return None
        return collect_files(dest)
