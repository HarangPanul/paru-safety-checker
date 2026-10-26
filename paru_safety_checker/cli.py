from __future__ import annotations

import subprocess
import sys
from typing import Callable

from .fetch import FetchError, fetch_package_files
from .heuristics import level_of, scan
from .models import Verdict, worst
from .providers import Provider, ProviderError, make_provider
from .report import format_verdict

FORCE_FLAG = "--safe-force"
# -S sub-operations that do not build/install anything
NON_INSTALL_SYNC = set("sigclpw")


def split_args(argv: list[str]) -> tuple[list[str], bool]:
    """Strip our own flags; the rest is forwarded to paru unchanged."""
    return [a for a in argv if a != FORCE_FLAG], FORCE_FLAG in argv


def install_targets(args: list[str]) -> list[str]:
    """Package names of a `paru -S ...` install, or [] for any other command."""
    is_install = any(
        a.startswith("-S") and not a.startswith("--") and not (set(a[2:]) & NON_INSTALL_SYNC)
        for a in args
    )
    if not is_install:
        return []
    names = [a for a in args if not a.startswith("-")]
    return [n.split("/", 1)[1] if n.startswith("aur/") else n for n in names]


def pacman_has(package: str) -> bool:
    """True if the package is in the official repos (not an AUR build)."""
    return subprocess.run(["pacman", "-Si", package], capture_output=True).returncode == 0


def run_paru(args: list[str]) -> int:
    return subprocess.call(["paru", *args])


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def main(
    argv: list[str] | None = None,
    *,
    provider: Provider | None = None,
    fetcher: Callable[[str], dict[str, str] | None] = fetch_package_files,
    in_repo: Callable[[str], bool] = pacman_has,
    runner: Callable[[list[str]], int] = run_paru,
    ask: Callable[[str], str] = input,
) -> int:
    args, force = split_args(sys.argv[1:] if argv is None else argv)
    targets = install_targets(args)
    if not targets:
        return runner(args)

    level = "safe"
    unchecked: list[str] = []
    for package in targets:
        if "/" in package or in_repo(package):
            continue  # explicit repo/pkg or official repo package: not an AUR build
        try:
            files = fetcher(package)
        except FetchError as exc:
            _err(f"[paru-safe] cannot fetch {package}: {exc}")
            unchecked.append(package)
            continue
        if files is None:
            continue  # not an AUR package; paru will report it
        static = scan(files, package)
        static_level = level_of(static)
        if static_level == "danger":
            # No need to spend an AI call: the rules already block this package.
            verdict = Verdict("danger", "Rule-based scan found dangerous patterns (AI review skipped)", static)
        else:
            try:
                if provider is None:
                    provider = make_provider()
                ai = provider.analyze(package, files, static)
            except ProviderError as exc:
                _err(f"[paru-safe] analysis failed for {package}: {exc}")
                unchecked.append(package)
                continue
            verdict = Verdict(worst(static_level, ai.level), ai.summary, static + ai.findings)
        _err(format_verdict(package, verdict))
        level = worst(level, verdict.level)

    if level == "danger" and not force:
        _err(f"[paru-safe] refusing to install: dangerous package(s) found. Use {FORCE_FLAG} to override.")
        return 1
    if unchecked:
        _err(f"[paru-safe] NOT reviewed (fail-closed): {', '.join(unchecked)}")
        if not _confirm(ask, "Install without review? Type 'yes' to continue: ", exact="yes"):
            return 1
    elif level == "caution":
        if not _confirm(ask, "Review the findings above. Continue? [y/N] "):
            return 1
    elif level == "danger":
        if not _confirm(ask, "Package flagged DANGER. Type 'yes' to install anyway: ", exact="yes"):
            return 1
    return runner(args)


def _confirm(ask: Callable[[str], str], prompt: str, exact: str | None = None) -> bool:
    try:
        answer = ask(prompt).strip().lower()
    except EOFError:
        return False
    return answer == exact if exact else answer in ("y", "yes")


if __name__ == "__main__":
    sys.exit(main())
