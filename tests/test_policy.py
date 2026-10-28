"""Step 5 of docs/COMMANDS.md: what the effects and the role of the function decide."""
import pytest

from paru_analyzer.heuristics import level_of, scan
from paru_analyzer.ir import build_ir
from paru_analyzer.strict import scan_strict


def strict(text, name="PKGBUILD"):
    return scan_strict(name, text)


def rules(text, name="PKGBUILD"):
    return sorted({f.rule for f in strict(text, name)})


def build(body):
    return f"pkgname=x\npkgver=1\nbuild() {{\n{body}\n}}\n"


# ---- a program from the source tree ----

@pytest.mark.parametrize("command", ["./scripts/mkmo locale/", "../tools/gen", "target/release/aur-scan completions",
                                     "test-env/bin/python x.py", '"$srcdir/helper" --go', "${srcdir}/helper", "./${_appimage} --appimage-extract"])
def test_a_program_of_the_source_tree_is_expected_while_building(command):
    found = strict(build(f"  {command}"))
    assert [(f.rule, f.severity) for f in found] == [("source-tree-program", "expected")]


def test_an_expected_program_does_not_raise_the_level():
    assert level_of(scan({"PKGBUILD": build("  ./configure\n  ./scripts/gen out")})) == "clear"


def test_the_same_program_is_a_concern_in_a_package_function_that_may_run_anywhere_or_in_a_hook():
    package = "pkgname=x\npkgver=1\npackage() {\n  ./tools/gen\n}\n"
    assert [f.severity for f in strict(package)] == ["expected"]
    orphan = "pkgname=x\npkgver=1\n_helper() {\n  ./tools/gen\n}\nbuild() { :; }\n"
    assert rules(orphan) == ["unknown-command"]
    assert rules("post_install() {\n  ./tools/gen\n}\n", "x.install") == ["unknown-command"]
    assert "source-tree-program" not in rules("pkgname=x\npkgver=1\nversion=$(./tools/gen)\n")


def test_a_helper_called_by_build_counts_as_build():
    text = "pkgname=x\npkgver=1\n_helper() {\n  ./tools/gen\n}\nbuild() { _helper; }\n"
    assert [f.severity for f in strict(text)] == ["expected"]
    text = text.replace("build() { _helper; }", "build() { eval _helper; }")
    assert rules(text) == ["unknown-command"]


def test_other_paths_are_not_the_source_tree():
    assert rules(build("  /tmp/x --go")) == ["unknown-command"]
    assert rules(build("  ~/bin/x")) == ["unknown-command"]
    assert rules(build("  $HOME/bin/x")) == ["dynamic-command"]
    assert rules(build("  ./configure --prefix=/usr")) == []


# ---- a function that may run anywhere has to be ordinary everywhere ----

def test_a_function_nobody_calls_must_be_ordinary_in_every_role():
    orphan = "pkgname=x\npkgver=1\n_helper() {\n  %s\n}\nbuild() { :; }\n"
    assert rules(orphan % "make") == ["unknown-command"]        # build only
    assert rules(orphan % "cp a b") == []                        # fine in a build and in a hook
    called = orphan.replace("build() { :; }", "build() { _helper; }")
    assert rules(called % "make") == []
    hook = "_helper() {\n  %s\n}\npost_install() { :; }\n"
    assert rules(hook % "systemctl enable x", "x.install") == ["unknown-command"]
    assert rules((hook + "post_install() { _helper; }\n").replace("post_install() { :; }\n", "") % "systemctl enable x", "x.install") == []


# ---- the network ----

@pytest.mark.parametrize("command", ["curl -o f https://x/y", "wget -q https://x/y", "curl -T f https://x/y",
                                     "rsync -a host:dir out", "rsync -a out rsync://x/y"])
def test_a_command_that_reaches_the_network_is_reported_as_such(command):
    assert "network-command" in rules(build(f"  {command}"))
    assert "unknown-command" not in rules(build(f"  {command}"))


def test_a_local_rsync_and_build_tools_that_may_fetch_are_not_network_commands():
    assert rules(build("  rsync -a src/ dst/")) == []
    assert rules(build("  cargo build --release")) == []
    assert rules(build("  rsync -e 'ssh -i k' -a a b")) == ["inline-code"]


# ---- system changes belong to the hooks ----

@pytest.mark.parametrize("command", ["groupadd foo", "useradd -r foo", "userdel foo", "modprobe foo", "apparmor_parser -r p"])
def test_user_and_module_changes_are_understood_in_a_hook_and_unknown_in_a_build(command):
    assert rules(f"post_install() {{\n  {command}\n}}\n", "x.install") == []
    assert rules(build(f"  {command}")) == ["unknown-command"]


def test_read_only_helpers_are_fine_in_a_hook():
    assert rules("post_upgrade() {\n  vercmp 1 2\n  tput bold\n  mktemp -d\n}\n", "x.install") == []


# ---- the intermediate representation uses the same table ----

def test_the_ir_keeps_knowing_the_commands_after_a_step_with_operations():
    ir = build_ir({"PKGBUILD": build("  cp a b\n  make\n  mkdir -p c")})
    assert [s["known"] for s in ir["steps"]] == [True, True, True]
    assert not [g for g in ir["gaps"] if g["reason"] != "parse-failed"]
