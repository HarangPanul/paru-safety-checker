"""Build a corpus of presumed-benign AUR packages and measure scanner false positives.

    python -m paru_analyzer.corpus collect --out data/corpus --count 500
    python -m paru_analyzer.corpus measure --corpus data/corpus
    python -m paru_analyzer.corpus export --corpus data/corpus --out data/targets --label benign

Other ways to pick targets: --strategy recent|newest, --max-votes 5, --since-days 30, --only orphan,
--names list.txt (one package per line).

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
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .fetch import FetchError, clone_package, collect_files, valid_package_name
from .heuristics import level_of, scan
from .parsed import ParsedFile

META_URL = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
META_NAME = "packages-meta-ext-v1.json.gz"
CORPUS_NAME = "pkgbuilds.jsonl"
USER_AGENT = "paru-analyzer-corpus/0.1"
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


STRATEGIES = ("top", "random", "recent", "newest")
ONLY = ("orphan", "out-of-date")


def select_packages(
    meta: list[dict], count: int, strategy: str = "top", min_votes: int = 0,
    include_orphans: bool = False, seed: int = 0, *, only: str | None = None,
    max_votes: int | None = None, since_days: float | None = None,
    names: list[str] | None = None, now: float | None = None,
) -> list[str]:
    """Pick `count` package bases. Orphaned/out-of-date ones are skipped by default: orphans are
    the hijack vector, so they do not belong in a presumed-benign baseline; `only` selects exactly
    those instead. `names` skips the selection and returns those packages in the given order.

    strategy: top (popularity), random, recent (last modified first), newest (first submitted first).
    max_votes / since_days narrow to the low-vote or freshly changed packages, where new malware sits."""
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy: {strategy!r}")
    if only is not None and only not in ONLY:
        raise ValueError(f"unknown filter: {only!r}")
    if names is not None:
        wanted = list(dict.fromkeys(n for n in names if valid_package_name(n)))
        return wanted[:count]
    now = time.time() if now is None else now
    best: dict[str, dict] = {}
    for entry in meta:
        base = entry.get("PackageBase") or entry.get("Name", "")
        votes = entry.get("NumVotes", 0)
        if not valid_package_name(base) or votes < min_votes or (max_votes is not None and votes > max_votes):
            continue
        orphan, stale = entry.get("Maintainer") is None, bool(entry.get("OutOfDate"))
        if only == "orphan" and not orphan:
            continue
        if only == "out-of-date" and not stale:
            continue
        if only is None and not include_orphans and (orphan or stale):
            continue
        if since_days is not None and entry.get("LastModified", 0) < now - since_days * 86400:
            continue
        if base not in best or entry.get("Popularity", 0) > best[base].get("Popularity", 0):
            best[base] = entry
    key = {
        "recent": lambda b: (-best[b].get("LastModified", 0), b),
        "newest": lambda b: (-best[b].get("FirstSubmitted", 0), b),
    }.get(strategy, lambda b: (-best[b].get("Popularity", 0), b))
    bases = sorted(best, key=key)
    if strategy == "random":
        random.Random(seed).shuffle(bases)
    return bases[:count]


def read_names(path: Path) -> list[str]:
    """One package name per line; blank lines and `#` comments are ignored."""
    lines = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    return [line for line in lines if line]


def export(corpus_file: Path, out_dir: Path, label: str) -> int:
    """Write each collected package as `out_dir/label/<name>/<files>`: the layout experiments/yesno_logprob.py
    reads (label `malicious` or `benign`), and an easy tree to browse or sort by hand."""
    written = 0
    for record in iter_records(corpus_file):
        if "files" not in record or not valid_package_name(record.get("name", "")):
            continue
        root = out_dir / label / record["name"]
        for name, text in record["files"].items():
            relative = Path(name)
            if name.startswith("(") or relative.is_absolute() or ".." in relative.parts:
                continue                    # the "(omitted-files)" note, or a path that would leave the folder
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        written += 1
    return written


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


def iter_records(path: Path | str) -> Iterator[dict]:
    path = Path(path)
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


# What to count inside the noisiest rules: which command is unknown, which file kind is unanalysed...
# The key is cut out of the finding's message so that the report says where the noise comes from.
DETAIL_KEYS = {
    "unknown-command": re.compile(r"\(default-deny\): ([^:]+):"),
    "dynamic-command": re.compile(r"\(([^)]*)\), so what runs"),
    "unanalyzed-file": re.compile(r"not understood: (\S+)"),
    "toplevel-code": re.compile(r"parsed: (\S+)"),
    "dependency-fetch": re.compile(r"reviewed files\): (\S+(?: \S+)?)"),
    "parse-time-command": re.compile(r"parse time \(([^)]*)\)"),
}


def _detail_key(rule: str, finding) -> str | None:
    match = DETAIL_KEYS[rule].search(finding.message)
    if not match:
        return None
    key = match.group(1)
    if rule == "unanalyzed-file":
        base = key.rsplit("/", 1)[-1]
        return "." + base.rsplit(".", 1)[-1] if "." in base.lstrip(".") else base
    return key


def measure(path: Path, examples: int = 3) -> dict:
    """Run the scanner over the corpus; every finding is presumed to be a false positive."""
    levels = {"safe": 0, "caution": 0, "danger": 0}
    flagged: dict[str, list[str]] = {"safe": [], "caution": [], "danger": []}
    rules: dict[str, dict] = defaultdict(lambda: {"severity": "", "findings": 0, "packages": set(), "examples": []})
    details: dict[str, Counter] = {rule: Counter() for rule in DETAIL_KEYS}
    total = 0
    for record in iter_records(path):
        if "files" not in record:
            continue
        total += 1
        findings = scan(record["files"], record["name"])
        level = level_of(findings)
        levels[level] += 1
        flagged[level].append(record["name"])
        for finding in findings:
            if finding.rule in details and (key := _detail_key(finding.rule, finding)):
                details[finding.rule][key] += 1
            entry = rules[finding.rule]
            entry["severity"] = finding.severity
            entry["findings"] += 1
            entry["packages"].add(record["name"])
            if len(entry["examples"]) < examples:
                entry["examples"].append(f"{record['name']} {finding.file}:{finding.line}: {finding.message}")
    return {
        "total": total, "levels": levels, "flagged": flagged,
        "rules": {k: {**v, "packages": sorted(v["packages"])} for k, v in rules.items()},
        "details": {rule: dict(counter.most_common(40)) for rule, counter in details.items() if counter},
    }


def format_report(report: dict) -> str:
    total = report["total"] or 1
    lines = [f"packages scanned: {report['total']}"]
    for level in ("safe", "caution", "danger"):
        count = report["levels"][level]
        lines.append(f"  {level:8} {count:5}  ({100 * count / total:.1f}%)")
    lines.append("")
    lines.append("rules by affected packages (danger first; each hit is a presumed false positive):")
    ordered = sorted(report["rules"].items(), key=lambda kv: (("danger", "caution").index(kv[1]["severity"]), -len(kv[1]["packages"])))
    for rule, entry in ordered:
        lines.append(f"  [{entry['severity']}] {rule}: {len(entry['packages'])} packages, {entry['findings']} findings")
        lines.extend(f"      {example}" for example in entry["examples"])
    for rule, counts in report.get("details", {}).items():
        lines.append("")
        lines.append(f"what the {rule} findings are about (top 10 of {len(counts)} shown in the JSON):")
        lines.extend(f"  {count:5}  {key}" for key, count in list(counts.items())[:10])
    if report["flagged"]["danger"]:
        lines.append("")
        lines.append("danger packages (review first): " + ", ".join(report["flagged"]["danger"]))
    if report["flagged"].get("safe"):
        lines.append("")
        lines.append("safe packages (no rule fired, which is not a verdict): " + ", ".join(report["flagged"]["safe"]))
    return "\n".join(lines)


def parse_report(path: Path, with_bash: bool = False, examples: int = 10) -> dict:
    """How well the shell parser reads the collected PKGBUILD and .install files: files whose tokenizer failed,
    files with statements it could not read (and why), and, with `with_bash`, where it disagrees with `bash -n`
    (that command only checks syntax; it never runs the file)."""
    report = {"files": 0, "tokenizer_failed": 0, "with_unread": 0, "unread_statements": 0, "reasons": Counter(),
              "examples": [], "bash": None}
    if with_bash:
        report["bash"] = {"agree": 0, "ours_too_lenient": [], "ours_too_strict": [], "unavailable": 0}
    for record in iter_records(path):
        if "files" not in record:
            continue
        for name, text in record["files"].items():
            if name != "PKGBUILD" and not name.endswith(".install"):
                continue
            parsed = ParsedFile(name, text)
            report["files"] += 1
            if not parsed.pre.ok:
                report["tokenizer_failed"] += 1
                report["reasons"]["tokenizer: " + parsed.pre.error] += 1
            if parsed.ast.errors:
                report["with_unread"] += 1
                report["unread_statements"] += len(parsed.ast.errors)
                for _, message in parsed.ast.errors:
                    report["reasons"][message] += 1
                if len(report["examples"]) < examples:
                    line, message = parsed.ast.errors[0]
                    report["examples"].append(f"{record['name']} {name}:{line}: {message}")
            if with_bash:
                try:
                    bash_ok = subprocess.run(["bash", "-n"], input=text.encode(), capture_output=True, timeout=20).returncode == 0
                except (OSError, subprocess.SubprocessError):
                    report["bash"]["unavailable"] += 1
                    continue
                if bash_ok == parsed.ast.ok:
                    report["bash"]["agree"] += 1
                else:
                    target = "ours_too_strict" if bash_ok else "ours_too_lenient"
                    if len(report["bash"][target]) < examples:
                        report["bash"][target].append(f"{record['name']} {name}")
                    else:
                        report["bash"][target].append(None)
    if report["bash"]:
        for key in ("ours_too_lenient", "ours_too_strict"):
            kept = [x for x in report["bash"][key] if x]
            report["bash"][key + "_count"] = len(report["bash"][key])
            report["bash"][key] = kept
    return report


def format_parse_report(report: dict) -> str:
    total = report["files"]
    pct = lambda n: f"{100 * n / total:.1f}%" if total else "-"
    lines = [f"shell files (PKGBUILD, *.install): {total}",
             f"  tokenizer failed:       {report['tokenizer_failed']:5} ({pct(report['tokenizer_failed'])})",
             f"  with unread statements: {report['with_unread']:5} ({pct(report['with_unread'])}), {report['unread_statements']} statements"]
    for message, count in report["reasons"].most_common(15):
        lines.append(f"    {count:5}  {message}")
    lines.extend(f"  example: {e}" for e in report["examples"])
    bash = report["bash"]
    if bash:
        lines.append("agreement with `bash -n` (syntax check only):")
        lines.append(f"  agree {bash['agree']}, bash unavailable {bash['unavailable']}")
        lines.append(f"  we accept, bash rejects (too lenient, can hide code): {bash['ours_too_lenient_count']}")
        lines.extend(f"      {x}" for x in bash["ours_too_lenient"])
        lines.append(f"  we reject, bash accepts (parser gap): {bash['ours_too_strict_count']}")
        lines.extend(f"      {x}" for x in bash["ours_too_strict"])
    return "\n".join(lines)


def corpus_file(folder: Path) -> Path:
    """The records file of a corpus folder (`--corpus data/corpus`); a path to the file itself also works."""
    return folder if folder.is_file() else folder / CORPUS_NAME


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m paru_analyzer.corpus")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="download PKGBUILDs of popular AUR packages")
    c.add_argument("--out", type=Path, default=Path("data/corpus"))
    c.add_argument("--meta", default=META_URL, help="metadata dump: URL or local file (default: AUR dump)")
    c.add_argument("--count", type=int, default=500)
    c.add_argument("--strategy", choices=STRATEGIES, default="top",
                   help="top=popularity, random, recent=last modified, newest=first submitted")
    c.add_argument("--min-votes", type=int, default=10)
    c.add_argument("--max-votes", type=int, help="only packages with at most this many votes (little-used ones)")
    c.add_argument("--since-days", type=float, help="only packages modified in the last N days")
    c.add_argument("--only", choices=ONLY, help="only orphaned / out-of-date packages (default: neither)")
    c.add_argument("--names", type=Path, help="file with one package name per line; skips the selection")
    c.add_argument("--include-orphans", action="store_true")
    c.add_argument("--seed", type=int, default=0)
    c.add_argument("--delay", type=float, default=2.0, help="seconds between clones")
    c.add_argument("--jitter", type=float, default=1.0)

    e = sub.add_parser("export", help="write the collected packages as one folder per package")
    e.add_argument("--corpus", type=Path, default=Path("data/corpus"))
    e.add_argument("--out", type=Path, default=Path("data/targets"))
    e.add_argument("--label", default="unlabeled", help="sub-folder name (malicious / benign for the logprob experiment)")

    m = sub.add_parser("measure", help="scan the corpus and report false positives")
    m.add_argument("--corpus", type=Path, default=Path("data/corpus"))
    m.add_argument("--examples", type=int, default=3)
    m.add_argument("--json", type=Path, help="also write the full report as JSON")

    q = sub.add_parser("parse", help="report how well the shell parser reads the collected files")
    q.add_argument("--corpus", type=Path, default=Path("data/corpus"))
    q.add_argument("--bash", action="store_true", help="also compare with `bash -n` (needs bash; never runs the files)")
    q.add_argument("--examples", type=int, default=10)

    args = parser.parse_args(argv)
    if args.command in ("measure", "export", "parse"):
        records = corpus_file(args.corpus)
        if not records.is_file():
            print(f"no corpus file at {records}: run `collect` first, or pass the folder that holds {CORPUS_NAME} with --corpus",
                  file=sys.stderr)
            return 2
        if args.command != "export" and not any("files" in r for r in iter_records(records)):
            print(f"{records} has no collected packages (every record is an error or the file is empty)", file=sys.stderr)
            return 2
    if args.command == "parse":
        print(format_parse_report(parse_report(corpus_file(args.corpus), args.bash, args.examples)))
        return 0
    if args.command == "collect":
        meta = load_meta(args.meta, cache=args.out / META_NAME)
        names = read_names(args.names) if args.names else None
        bases = select_packages(meta, args.count, args.strategy, args.min_votes, args.include_orphans, args.seed,
                                only=args.only, max_votes=args.max_votes, since_days=args.since_days, names=names)
        print(f"selected {len(bases)} package bases; ~{len(bases) * (args.delay + args.jitter / 2) / 60:.0f} min")
        stats = collect(bases, args.out / CORPUS_NAME, fetch_snapshot, delay=args.delay, jitter=args.jitter, sleep=time.sleep)
        print(f"fetched={stats.fetched} failed={stats.failed} skipped(already done)={stats.skipped}")
        if stats.aborted:
            print(f"ABORTED: {stats.aborted}\nWait a while (hours if rate limited) and rerun; it resumes.", file=sys.stderr)
            return 1
        return 0
    if args.command == "export":
        print(f"wrote {export(corpus_file(args.corpus), args.out, args.label)} packages to {args.out / args.label}")
        return 0
    report = measure(corpus_file(args.corpus), args.examples)
    print(format_report(report))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
