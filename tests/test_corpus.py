import gzip
import json
import random
import subprocess

import pytest

from paru_analyzer import corpus, fetch
from paru_analyzer.fetch import FetchError


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


# ---- choosing targets by other criteria ----

DAY = 86400
NOW = 1_000_000_000
META2 = [
    {**entry("old", 9.0, votes=40), "LastModified": NOW - 400 * DAY, "FirstSubmitted": NOW - 900 * DAY},
    {**entry("fresh", 1.0, votes=2), "LastModified": NOW - 2 * DAY, "FirstSubmitted": NOW - 3 * DAY},
    {**entry("mid", 5.0, votes=6), "LastModified": NOW - 30 * DAY, "FirstSubmitted": NOW - 100 * DAY},
    {**entry("gone", 3.0, votes=1, maintainer=None), "LastModified": NOW - 10 * DAY, "FirstSubmitted": NOW - 50 * DAY},
    {**entry("late", 2.0, votes=3, out_of_date=1), "LastModified": NOW - 5 * DAY, "FirstSubmitted": NOW - 60 * DAY},
]


def pick(**kwargs):
    kwargs.setdefault("min_votes", 0)
    return corpus.select_packages(META2, 10, now=NOW, **kwargs)


def test_recent_and_newest_orders():
    assert pick(strategy="recent") == ["fresh", "mid", "old"]
    assert pick(strategy="newest") == ["fresh", "mid", "old"]
    assert pick(strategy="recent", include_orphans=True)[:3] == ["fresh", "late", "gone"]


def test_low_votes_and_recently_modified_narrow_the_pick():
    assert pick(max_votes=6) == ["mid", "fresh"]
    assert pick(since_days=45) == ["mid", "fresh"]
    assert pick(since_days=45, max_votes=2) == ["fresh"]


def test_only_orphans_or_only_out_of_date():
    assert pick(only="orphan") == ["gone"]
    assert pick(only="out-of-date") == ["late"]
    with pytest.raises(ValueError):
        pick(only="bogus")


def test_names_override_the_selection_and_keep_order(tmp_path):
    names = tmp_path / "n.txt"
    names.write_text("zeta  # last\n\n# a comment\nalpha\n-bad\nzeta\n")
    listed = corpus.read_names(names)
    assert listed == ["zeta", "alpha", "-bad", "zeta"]
    assert corpus.select_packages([], 10, names=listed) == ["zeta", "alpha"]
    assert corpus.select_packages([], 1, names=listed) == ["zeta"]


def test_export_writes_one_folder_per_package_and_skips_unsafe_paths(tmp_path):
    corpus_file = tmp_path / "pkgbuilds.jsonl"
    records = [
        {"name": "good", "rev": "1", "files": {"PKGBUILD": "x", "sub/a.patch": "p", "(omitted-files)": "n", "../evil": "e", "/abs": "e"}},
        {"name": "broken", "error": "boom"},
        {"name": "-bad", "files": {"PKGBUILD": "x"}},
    ]
    corpus_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    out = tmp_path / "targets"
    assert corpus.export(corpus_file, out, "benign") == 1
    assert (out / "benign" / "good" / "PKGBUILD").read_text() == "x"
    assert (out / "benign" / "good" / "sub" / "a.patch").read_text() == "p"
    assert sorted(p.name for p in (out / "benign" / "good").iterdir()) == ["PKGBUILD", "sub"]
    assert not (out / "evil").exists() and not (tmp_path / "evil").exists()


def test_export_layout_loads_in_the_logprob_experiment(tmp_path):
    from experiments import yesno_logprob as yn
    corpus_file = tmp_path / "pkgbuilds.jsonl"
    corpus_file.write_text(json.dumps({"name": "p", "files": {"PKGBUILD": "build() { make; }"}}) + "\n")
    corpus.export(corpus_file, tmp_path / "t", "benign")
    packages = yn.load_packages(tmp_path / "t", 10000, None)
    assert [p["id"] for p in packages] == ["benign/p"]


def test_cli_export_and_collect_with_names(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(corpus, "fetch_snapshot", lambda base: ({"PKGBUILD": f"# {base}\n"}, "rev"))
    monkeypatch.setattr(corpus.time, "sleep", lambda s: None)
    names = tmp_path / "n.txt"
    names.write_text("one\ntwo\n")
    meta = tmp_path / "meta.json"
    meta.write_text("[]")
    assert corpus.main(["collect", "--out", str(tmp_path / "c"), "--meta", str(meta), "--names", str(names)]) == 0
    assert corpus.main(["export", "--corpus", str(tmp_path / "c"), "--out", str(tmp_path / "t"), "--label", "benign"]) == 0
    assert (tmp_path / "t" / "benign" / "two" / "PKGBUILD").read_text() == "# two\n"
    assert "wrote 2 packages" in capsys.readouterr().out


def test_measure_counts_what_the_noisy_rules_are_about(tmp_path):
    corpus_file = tmp_path / "pkgbuilds.jsonl"
    bodies = [
        "build() {\n  arch-meson . build\n  arch-meson b\n  frobnicate x\n}\n",
        "build() {\n  arch-meson . build\n}\n",
    ]
    corpus_file.write_text("".join(json.dumps({"name": f"p{i}", "files": {"PKGBUILD": b, "tool.py": "print(1)\n"}}) + "\n"
                                   for i, b in enumerate(bodies)))
    report = corpus.measure(corpus_file)
    assert report["details"]["unknown-command"] == {"arch-meson": 2, "frobnicate": 1}
    assert report["details"]["unanalyzed-file"] == {".py": 2}
    assert "arch-meson" in corpus.format_report(report)
