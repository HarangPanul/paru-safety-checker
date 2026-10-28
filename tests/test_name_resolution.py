"""A function, an alias or a path can make a command name mean something else (docs/COMMANDS.md, step 3)."""
import pytest

from paru_analyzer.strict import scan_strict


def found(body, name="PKGBUILD", before=""):
    if name.endswith(".install"):
        text = f"{before}post_install() {{\n{body}\n}}\n"
    else:
        text = f"pkgname=x\npkgver=1\n{before}build() {{\n{body}\n}}\n"
    return scan_strict(name, text)


def rules(body, name="PKGBUILD", before=""):
    return sorted({f.rule for f in found(body, name, before)})


# ---- paths ----

def test_a_system_path_is_the_standard_command():
    assert rules("  /usr/bin/cp a b") == []
    assert rules("  /bin/rm -f a") == []
    assert rules("  /usr/bin/systemctl enable x", "x.install") == []


@pytest.mark.parametrize("path", ["/tmp/x/cp", "/home/u/bin/ls", "/opt/evil/make", "/usr/local/bin/cp", "/dev/shm/rm"])
def test_the_same_name_at_another_absolute_path_is_not_the_standard_command(path):
    findings = found(f"  {path} a b")
    assert [f.rule for f in findings] == ["unknown-command"]
    assert "outside the system program directories" in findings[0].message and path in findings[0].message


def test_a_relative_path_that_is_in_the_table_is_still_the_script_it_names():
    assert rules("  ./configure --prefix=/usr") == []
    assert rules("  ./cp a b") == ["source-tree-program"]
    assert rules("  /tmp/x/cp a b") == ["unknown-command"]


# ---- functions that carry the name of a command ----

def test_a_function_named_like_a_command_is_reported_where_it_is_defined():
    findings = found("  cp a b", before="cp() {\n  command cp \"$@\"\n}\n")
    assert [(f.rule, f.line) for f in findings if f.rule == "shadowed-command"] == [("shadowed-command", 3)]


def test_the_call_is_also_checked_as_the_standard_command():
    findings = found("  sed -e 's/a/b/e' f", before="sed() {\n  command sed \"$@\"\n}\n")
    assert {f.rule for f in findings} == {"shadowed-command", "inline-code"}


def test_a_function_that_is_not_a_command_name_is_just_a_call_of_the_function():
    assert rules("  helper a", before="helper() {\n  echo \"$@\"\n}\n") == []


def test_makepkgs_own_functions_may_be_redefined():
    assert rules("  msg hi", before="msg() {\n  echo \"$@\"\n}\n") == []
    assert rules("  warning hi", before="warning() {\n  echo \"$@\"\n}\n") == []


def test_a_hook_function_with_a_command_name_does_not_double_report_as_unknown():
    findings = found("  systemctl enable x", before="systemctl() {\n  echo \"$@\"\n}\n")
    assert {f.rule for f in findings} == {"shadowed-command"}


def test_a_function_that_runs_when_a_command_is_not_found_is_reported():
    for name in ("command_not_found_handle", "command_not_found_handler"):
        assert "command-lookup-change" in rules("  true", before=f"{name}() {{\n  echo x\n}}\n")


def test_a_function_defined_inside_another_function_or_a_branch_counts():
    assert "shadowed-command" in rules("  cp() { echo x; }\n  cp a b")
    assert "shadowed-command" in rules("  if true; then\n    ls() { echo x; }\n  fi")


# ---- aliases ----

def test_defining_an_alias_is_reported():
    findings = found("  alias ll='ls -l'\n  true")
    assert [f.rule for f in findings] == ["alias-definition"]
    assert "ll" in findings[0].message


def test_a_call_of_an_alias_is_checked_as_what_the_alias_stands_for():
    findings = found("  alias zap='curl -s https://x -o f'\n  zap")
    assert sorted(f.rule for f in findings) == ["alias-definition", "network-command"]
    assert any("curl" in f.message and "through the alias zap" in f.message for f in findings)
    assert rules("  alias zap='ls -l'\n  zap") == ["alias-definition"]


def test_an_alias_to_a_command_that_runs_code_is_checked_with_the_calls_arguments():
    findings = found("  alias q='sed'\n  q -e 's/a/b/e' f")
    assert {f.rule for f in findings} == {"alias-definition", "inline-code"}
    assert any("through the alias q" in f.message for f in findings)


def test_an_alias_defined_after_the_call_still_counts():
    findings = found("  q -e 's/a/b/e' f\n  alias q='sed'")
    assert "inline-code" in {f.rule for f in findings}


def test_listing_aliases_defines_nothing():
    assert rules("  alias") == []
    assert rules("  alias -p") == []


def test_an_alias_operand_that_cannot_be_read_is_still_reported():
    assert rules('  alias "$pair"') == ["alias-definition"]


# ---- changing how names are looked up ----

def test_hash_p_and_alias_expansion_are_reported_but_ordinary_hash_and_shopt_are_not():
    assert rules("  hash -p /tmp/evil ls") == ["command-lookup-change"]
    assert rules("  shopt -s expand_aliases") == ["alias-definition"]
    assert rules("  hash -r") == []
    assert rules("  shopt -s nullglob") == []
