from __future__ import annotations

import subprocess
import sys
from typing import Callable

from .activity import build_activity, format_activity, inventory_for_ai
from .fetch import FetchError, fetch_package_files
from .heuristics import dependencies, level_of, scan
from .models import Finding, Verdict, worst
from .preprocess import preprocess, render
from .providers import Provider, ProviderError, make_provider
from .report import format_verdict

VERBOSE_FLAG = "--safe-verbose"
# -S sub-operations that do not build/install anything
NON_INSTALL_SYNC = set("sigclpw")


def split_args(argv: list[str]) -> tuple[list[str], bool]:
    """Strip our own flags; the rest is forwarded to paru unchanged."""
    return [a for a in argv if a != VERBOSE_FLAG], VERBOSE_FLAG in argv


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


def _pacman_ok(*args: str) -> bool:
    try:
        return subprocess.run(["pacman", *args], capture_output=True, stdin=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        return False


def pacman_has(package: str) -> bool:
    """True if the package is in the official repos (not an AUR build)."""
    return _pacman_ok("-Si", package)


def dep_available(dep: str) -> bool:
    """True if a dependency is installed or resolvable from the official repos (incl. virtual provides)."""
    return _pacman_ok("-T", dep) or _pacman_ok("-Sp", "--noconfirm", "--", dep)


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
    dep_ok: Callable[[str], bool] = dep_available,
    runner: Callable[[list[str]], int] = run_paru,
    ask: Callable[[str], str] = input,
) -> int:
    args, verbose = split_args(sys.argv[1:] if argv is None else argv)
    targets = install_targets(args)
    if not targets:
        return runner(args)

    level = "clear"
    unchecked: list[str] = []
    reviewed = False
    for package in targets:
        if "/" in package or in_repo(package):
            continue  # explicit repo/pkg or official repo package: not an AUR build
        try:
            files = fetcher(package)
        except FetchError as exc:
            _err(f"[paru-analyzer] cannot fetch {package}: {exc}")
            unchecked.append(package)
            continue
        if files is None:
            continue  # not an AUR package; paru will report it

        reviewed = True
        static = scan(files, package) + _dependency_findings(package, files, targets, dep_ok)
        activities = build_activity(files)
        _err(format_activity(package, activities, verbose))
        verdict = Verdict(level_of(static), "Scanner findings only (AI review did not run)", static)
        try:
            if provider is None:
                provider = make_provider()
            # The AI looks for what the scanner could not anticipate. It runs even when the
            # scanner already found something, because nothing here blocks the install.
            ai = provider.analyze(package, files_for_ai(files), static, inventory=inventory_for_ai(activities))
            # it can only raise the level; findings it lists count even if its headline says "clear"
            level_now = worst(worst(verdict.level, ai.level), level_of(ai.findings))
            verdict = Verdict(level_now, ai.summary, static + ai.findings)
        except ProviderError as exc:
            _err(f"[paru-analyzer] AI analysis failed for {package}: {exc}")
            unchecked.append(package)
        _err(format_verdict(package, verdict))
        level = worst(level, verdict.level)

    # Nothing is ever refused: the user sees the report and chooses, even when nothing was marked (silence is
    # not a verdict). Riskier states need a typed "yes".
    if unchecked:
        _err(f"[paru-analyzer] NOT fully reviewed: {', '.join(unchecked)}")
    if unchecked or level == "warning":
        if level == "warning":
            _err("[paru-analyzer] WARNING: at least one package was flagged with a warning.")
        if not _confirm(ask, "Install anyway? Type 'yes' to continue: ", exact="yes"):
            return 1
    elif level == "info":
        if not _confirm(ask, "Review the findings above. Continue? [y/N] "):
            return 1
    elif reviewed and not _confirm(ask, "Nothing was marked, which does not mean the package is safe. Install? [y/N] "):
        return 1
    return runner(args)


def files_for_ai(files: dict[str, str]) -> dict[str, str]:
    """What the model reads: shell files preprocessed (comments removed, one command per line, every line
    prefixed with its original line number), everything else as it is. Comment text is still checked by the
    scanner, but it never reaches the model, so it cannot be used to talk to it."""
    shown: dict[str, str] = {}
    for name, text in files.items():
        if name == "PKGBUILD" or name.endswith(".install"):
            pre = preprocess(text)
            note = f"\n[{len(pre.comments)} comment line(s) removed]" if pre.comments else ""
            shown[name] = render(pre) + note
        else:
            shown[name] = text
    return shown


def _dependency_findings(package: str, files: dict[str, str], targets: list[str], dep_ok: Callable[[str], bool]) -> list[Finding]:
    """paru builds AUR dependencies too, and nothing here reviews them unless they are named."""
    return [
        Finding("info", f"Dependency {dep} is not in the official repositories; paru will fetch and build it "
                           f"from the AUR without paru-analyzer reviewing it (name it on the command line to review it)",
                "PKGBUILD", None, "unreviewed-dependency")
        for dep in dependencies(files)
        if dep != package and dep not in targets and not dep_ok(dep)
    ]


def _confirm(ask: Callable[[str], str], prompt: str, exact: str | None = None) -> bool:
    try:
        answer = ask(prompt).strip().lower()
    except EOFError:
        return False
    return answer == exact if exact else answer in ("y", "yes")


if __name__ == "__main__":
    sys.exit(main())
