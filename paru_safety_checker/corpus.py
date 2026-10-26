"""Build a corpus of presumed-benign AUR packages and measure scanner false positives.

    python -m paru_safety_checker.corpus collect --out data/corpus --count 500
    python -m paru_safety_checker.corpus measure --corpus data/corpus

The package list comes from the AUR's bulk metadata dump (one request), and each package is
then cloned sequentially with a delay, so the AUR is never hit with a burst. Progress is
appended per package, so an interrupted run resumes where it stopped.
"""
from __future__ import annotations

import argparse
import gzip
import json
import random
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .fetch import FetchError, clone_package, collect_files, valid_package_name
from .heuristics import level_of, scan

META_URL = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
META_NAME = "packages-meta-ext-v1.json.gz"
CORPUS_NAME = "pkgbuilds.jsonl"
USER_AGENT = "paru-safety-checker-corpus/0.1"
# HTTP 429/403 or wording that means "slow down"; anything else is an ordinary failure.
RATE_LIMIT_RE = re.compile(r"\b(?:429|403)\b|rate limit|too many", re.IGNORECASE)

Fetcher = Callable[[str], tuple[dict[str, str], str]]


def load_meta(source: str, cache: Path | None = None) -> list[dict]:
    """Load the AUR metadata dump from a local file or URL (downloaded once, then cached)."""
    if source.startswith(("http://", "https://")):
        if cache is not None and cache.is_file():
            raw = cache.read_bytes()
        else:
            request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read()
            if cache is not None:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_bytes(raw)
    else:
        raw = Path(source).read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw)


def select_packages(
    meta: list[dict], count: int, strategy: str = "top", min_votes: int = 0,
    include_orphans: bool = False, seed: int = 0,
) -> list[str]:
    """Pick `count` package bases. Orphaned/out-of-date ones are skipped by default: orphans are
    the hijack vector, so they do not belong in a presumed-benign baseline."""
    best: dict[str, dict] = {}
    for entry in meta:
        base = entry.get("PackageBase") or entry.get("Name", "")
        if not valid_package_name(base) or entry.get("NumVotes", 0) < min_votes:
            continue
        if not include_orphans and (entry.get("Maintainer") is None or entry.get("OutOfDate")):
            continue
        if base not in best or entry.get("Popularity", 0) > best[base].get("Popularity", 0):
            best[base] = entry
    bases = sorted(best, key=lambda b: (-best[b].get("Popularity", 0), b))
    if strategy == "random":
        random.Random(seed).shuffle(bases)
    elif strategy != "top":
        raise ValueError(f"unknown strategy: {strategy!r}")
    return bases[:count]


def fetch_snapshot(base: str) -> tuple[dict[str, str], str]:
    with tempfile.TemporaryDirectory(prefix="paru-corpus-") as tmp:
        dest = Path(tmp) / "pkg"
        clone_package(base, dest)
        if not (dest / "PKGBUILD").is_file():
            raise FetchError("no PKGBUILD in repository")
        rev = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        return collect_files(dest), rev


@dataclass
class Stats:
    fetched: int = 0
    failed: int = 0
    skipped: int = 0
    aborted: str = ""


def iter_records(path: Path) -> Iterator[dict]:
    if not path.is_file():
        return
    with path.open() as handle:
        for line in handle:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn last line from an interrupted run


def collect(
    bases: list[str], out_file: Path, fetcher: Fetcher = fetch_snapshot, *,
    delay: float = 2.0, jitter: float = 1.0, max_failures: int = 5, max_rate_retries: int = 4,
    sleep: Callable[[float], None] = time.sleep, rng: random.Random | None = None,
    log: Callable[[str], None] = print,
) -> Stats:
    """Fetch `bases` one at a time, appending one JSON line each. Stops early (instead of
    hammering the server) on repeated rate limiting or a run of consecutive failures."""
    rng = rng or random.Random()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    done = {record.get("name") for record in iter_records(out_file)}
    stats = Stats()
    consecutive = 0
    with out_file.open("a") as handle:
        for index, base in enumerate(bases, 1):
            if base in done:
                stats.skipped += 1
                continue
            rate_retries = 0
            while True:
                try:
                    files, rev = fetcher(base)
                    record = {"name": base, "rev": rev, "files": files}
                    break
                except FetchError as exc:
                    message = str(exc)
                    if not RATE_LIMIT_RE.search(message):
                        record = {"name": base, "error": message[:300]}
                        break
                    if rate_retries >= max_rate_retries:
                        stats.aborted = f"still rate limited at {base}: {message[:200]}"
                        return stats
                    wait = min(60 * 2 ** rate_retries, 900)
                    log(f"rate limited at {base}; waiting {wait}s")
                    sleep(wait)
                    rate_retries += 1
            if "error" in record:
                stats.failed += 1
                consecutive += 1
                log(f"[{index}/{len(bases)}] {base}: FAILED {record['error']}")
            else:
                stats.fetched += 1
                consecutive = 0
                log(f"[{index}/{len(bases)}] {base}")
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            if consecutive >= max_failures:
                stats.aborted = f"{consecutive} consecutive failures (blocked or offline?)"
                return stats
            sleep(delay + rng.uniform(0, jitter))
    return stats


def measure(path: Path, examples: int = 3) -> dict:
    """Run the scanner over the corpus; every finding is presumed to be a false positive."""
    levels = {"safe": 0, "caution": 0, "danger": 0}
    flagged: dict[str, list[str]] = {"caution": [], "danger": []}
    rules: dict[str, dict] = defaultdict(lambda: {"severity": "", "findings": 0, "packages": set(), "examples": []})
    total = 0
    for record in iter_records(path):
        if "files" not in record:
            continue
        total += 1
        findings = scan(record["files"], record["name"])
        level = level_of(findings)
        levels[level] += 1
        if level != "safe":
            flagged[level].append(record["name"])
        for finding in findings:
            entry = rules[finding.rule]
            entry["severity"] = finding.severity
            entry["findings"] += 1
            entry["packages"].add(record["name"])
            if len(entry["examples"]) < examples:
                entry["examples"].append(f"{record['name']} {finding.file}:{finding.line}: {finding.message}")
    return {
        "total": total, "levels": levels, "flagged": flagged,
        "rules": {k: {**v, "packages": sorted(v["packages"])} for k, v in rules.items()},
    }


def format_report(report: dict) -> str:
    total = report["total"] or 1
    lines = [f"packages scanned: {report['total']}"]
    for level in ("safe", "caution", "danger"):
        count = report["levels"][level]
        lines.append(f"  {level:8} {count:5}  ({100 * count / total:.1f}%)")
    lines.append("")
    lines.append("rules by affected packages (danger first; each hit is a presumed false positive):")
    ordered = sorted(report["rules"].items(), key=lambda kv: (kv[1]["severity"] != "danger", -len(kv[1]["packages"])))
    for rule, entry in ordered:
        lines.append(f"  [{entry['severity']}] {rule}: {len(entry['packages'])} packages, {entry['findings']} findings")
        lines.extend(f"      {example}" for example in entry["examples"])
    if report["flagged"]["danger"]:
        lines.append("")
        lines.append("danger packages (review first): " + ", ".join(report["flagged"]["danger"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m paru_safety_checker.corpus")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="download PKGBUILDs of popular AUR packages")
    c.add_argument("--out", type=Path, default=Path("data/corpus"))
    c.add_argument("--meta", default=META_URL, help="metadata dump: URL or local file (default: AUR dump)")
    c.add_argument("--count", type=int, default=500)
    c.add_argument("--strategy", choices=["top", "random"], default="top")
    c.add_argument("--min-votes", type=int, default=10)
    c.add_argument("--include-orphans", action="store_true")
    c.add_argument("--seed", type=int, default=0)
    c.add_argument("--delay", type=float, default=2.0, help="seconds between clones")
    c.add_argument("--jitter", type=float, default=1.0)

    m = sub.add_parser("measure", help="scan the corpus and report false positives")
    m.add_argument("--corpus", type=Path, default=Path("data/corpus"))
    m.add_argument("--examples", type=int, default=3)
    m.add_argument("--json", type=Path, help="also write the full report as JSON")

    args = parser.parse_args(argv)
    if args.command == "collect":
        meta = load_meta(args.meta, cache=args.out / META_NAME)
        bases = select_packages(meta, args.count, args.strategy, args.min_votes, args.include_orphans, args.seed)
        print(f"selected {len(bases)} package bases; ~{len(bases) * (args.delay + args.jitter / 2) / 60:.0f} min")
        stats = collect(bases, args.out / CORPUS_NAME, delay=args.delay, jitter=args.jitter)
        print(f"fetched={stats.fetched} failed={stats.failed} skipped(already done)={stats.skipped}")
        if stats.aborted:
            print(f"ABORTED: {stats.aborted}\nWait a while (hours if rate limited) and rerun; it resumes.", file=sys.stderr)
            return 1
        return 0
    report = measure(args.corpus / CORPUS_NAME, args.examples)
    print(format_report(report))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
