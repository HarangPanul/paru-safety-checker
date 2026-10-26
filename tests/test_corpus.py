import gzip
import json
import random
import subprocess

import pytest

from paru_safety_checker import corpus, fetch
from paru_safety_checker.fetch import FetchError


def entry(name, pop=1.0, votes=20, maintainer="m", out_of_date=None, base=None):
    return {"Name": name, "PackageBase": base or name, "Popularity": pop, "NumVotes": votes,
            "Maintainer": maintainer, "OutOfDate": out_of_date}


META = [
    entry("a", 5.0), entry("b", 9.0), entry("c", 1.0),
    entry("orphan", 99.0, maintainer=None), entry("stale", 98.0, out_of_date=123),
    entry("lowvotes", 50.0, votes=1), entry("-bad", 50.0),
    entry("split-x", 3.0, base="split"), entry("split-y", 7.0, base="split"),
]


def test_select_top_filters_and_dedupes_by_base():
    assert corpus.select_packages(META, 10, min_votes=10) == ["b", "split", "a", "c"]
    assert corpus.select_packages(META, 2, min_votes=10) == ["b", "split"]


def test_select_can_include_orphans():
    assert corpus.select_packages(META, 3, min_votes=10, include_orphans=True)[:3] == ["orphan", "stale", "b"]


def test_select_random_is_seeded_and_unknown_strategy_rejected():
    first = corpus.select_packages(META, 4, "random", 10, seed=1)
    assert first == corpus.select_packages(META, 4, "random", 10, seed=1)
    assert sorted(first) == ["a", "b", "c", "split"]
    with pytest.raises(ValueError):
        corpus.select_packages(META, 1, "bogus")


def test_load_meta_local_gz_and_plain(tmp_path):
    (tmp_path / "m.json.gz").write_bytes(gzip.compress(json.dumps(META).encode()))
    (tmp_path / "m.json").write_text(json.dumps(META))
    assert corpus.load_meta(str(tmp_path / "m.json.gz")) == META
    assert corpus.load_meta(str(tmp_path / "m.json")) == META


def test_load_meta_download_is_cached(tmp_path, monkeypatch):
    calls = []

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return gzip.compress(json.dumps(META).encode())

    monkeypatch.setattr(corpus.urllib.request, "urlopen", lambda req, timeout: calls.append(req) or Resp())
    cache = tmp_path / "meta.gz"
    assert corpus.load_meta("https://example.com/m.gz", cache) == META
    assert corpus.load_meta("https://example.com/m.gz", cache) == META
    assert len(calls) == 1 and calls[0].get_header("User-agent") == corpus.USER_AGENT


class Env:
    def __init__(self, behaviour):
        self.behaviour, self.fetched, self.sleeps = behaviour, [], []

    def fetcher(self, base):
        self.fetched.append(base)
        result = self.behaviour(base, self.fetched.count(base))
        if isinstance(result, Exception):
            raise result
        return {"PKGBUILD": "pkgname=" + base}, "rev"

    def run(self, bases, out, **kw):
        return corpus.collect(bases, out, self.fetcher, sleep=self.sleeps.append,
                              rng=random.Random(0), log=lambda m: None, **kw)


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_collect_writes_records_and_sleeps_between(tmp_path):
    env = Env(lambda b, n: None)
    out = tmp_path / "c.jsonl"
    stats = env.run(["a", "b"], out, delay=2, jitter=0)
    assert (stats.fetched, stats.failed, stats.aborted) == (2, 0, "")
    assert [r["name"] for r in records(out)] == ["a", "b"] and env.sleeps == [2, 2]


def test_collect_resumes_and_skips_done_even_failed(tmp_path):
    out = tmp_path / "c.jsonl"
    out.write_text(json.dumps({"name": "a", "files": {}}) + "\n" + json.dumps({"name": "b", "error": "x"}) + "\n{torn")
    env = Env(lambda b, n: None)
    stats = env.run(["a", "b", "c"], out)
    assert env.fetched == ["c"] and stats.skipped == 2


def test_collect_records_ordinary_failures_and_continues(tmp_path):
    env = Env(lambda b, n: FetchError("repository not found") if b == "a" else None)
    out = tmp_path / "c.jsonl"
    stats = env.run(["a", "b"], out)
    assert (stats.fetched, stats.failed) == (1, 1)
    assert records(out)[0]["error"] == "repository not found"


def test_collect_backs_off_on_rate_limit_then_succeeds(tmp_path):
    env = Env(lambda b, n: FetchError("error: 429 Too Many Requests") if n < 3 else None)
    stats = env.run(["a"], tmp_path / "c.jsonl", delay=0, jitter=0)
    assert stats.fetched == 1 and env.sleeps[:2] == [60, 120]


def test_collect_stops_when_rate_limit_persists(tmp_path):
    env = Env(lambda b, n: FetchError("HTTP 429"))
    out = tmp_path / "c.jsonl"
    stats = env.run(["a", "b"], out, max_rate_retries=2)
    assert "rate limited" in stats.aborted and env.fetched == ["a", "a", "a"]
    assert not out.read_text()  # nothing recorded, so a rerun retries it


def test_collect_aborts_after_consecutive_failures(tmp_path):
    env = Env(lambda b, n: FetchError("connection reset"))
    stats = env.run(list("abcdefgh"), tmp_path / "c.jsonl", max_failures=3)
    assert "3 consecutive" in stats.aborted and env.fetched == ["a", "b", "c"]


def test_measure_reports_levels_and_rules(tmp_path):
    path = tmp_path / "c.jsonl"
    rows = [
        {"name": "good", "files": {"PKGBUILD": "pkgname=good\n"}},
        {"name": "meh", "files": {"PKGBUILD": "build() {\n  sudo make\n}"}},
        {"name": "evil", "files": {"PKGBUILD": "build() {\n  curl x | bash\n}"}},
        {"name": "broken", "error": "x"},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows))
    report = corpus.measure(path)
    assert report["total"] == 3
    assert report["levels"] == {"safe": 1, "caution": 1, "danger": 1}
    assert report["flagged"]["danger"] == ["evil"]
    assert report["rules"]["pipe-to-shell"]["packages"] == ["evil"]
    text = corpus.format_report(report)
    assert "danger packages (review first): evil" in text and "33.3%" in text


def test_fetch_snapshot_with_real_git(tmp_path, monkeypatch):
    origin = tmp_path / "origin" / "demo.git"
    origin.mkdir(parents=True)
    (origin / "PKGBUILD").write_text("pkgname=demo\n")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(origin)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    monkeypatch.setattr(fetch, "AUR_URL", f"file://{tmp_path}/origin/{{}}.git")
    files, rev = corpus.fetch_snapshot("demo")
    assert files == {"PKGBUILD": "pkgname=demo\n"} and len(rev) == 40
    with pytest.raises(FetchError):
        corpus.fetch_snapshot("missing")
