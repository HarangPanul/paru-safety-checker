from paru_analyzer.parsed import ParsedFile
from paru_analyzer import roles


def pkg(body, name="PKGBUILD"):
    return ParsedFile(name, body)


def of(body, name="PKGBUILD"):
    return {k: set(v) for k, v in pkg(body, name).function_roles.items()}


def test_the_makepkg_functions_have_their_own_roles():
    r = of("pkgver() { :; }\nprepare() { :; }\nbuild() { :; }\ncheck() { :; }\npackage() { :; }\npackage_foo() { :; }\npackage_foo-bar() { :; }\n")
    assert r == {"pkgver": {"parse"}, "prepare": {"build"}, "build": {"build"}, "check": {"build"},
                 "package": {"package"}, "package_foo": {"package"}, "package_foo-bar": {"package"}}


def test_install_hooks_are_hooks_and_pkgbuild_names_do_not_apply_there():
    r = of("post_install() { :; }\nbuild() { :; }\n", "x.install")
    assert r == {"post_install": {"hook"}, "build": {"unknown"}}
    assert of("post_install() { :; }\n") == {"post_install": {"unknown"}}


def test_a_helper_gets_the_union_of_its_callers():
    r = of("_setup() { :; }\nbuild() { _setup; }\npackage() { _setup; }\n")
    assert r["_setup"] == {"build", "package"}


def test_roles_pass_on_through_a_chain_of_helpers():
    r = of("_a() { _b; }\n_b() { :; }\nbuild() { _a; }\n")
    assert r["_a"] == {"build"} and r["_b"] == {"build"}


def test_a_helper_called_from_the_top_level_or_a_substitution_runs_at_parse():
    assert of("_v() { :; }\nx=$(_v)\n")["_v"] == {"parse"}
    assert of("_v() { :; }\nbuild() { x=$(_v); }\n")["_v"] == {"build"}
    assert of("_v() { :; }\n_v\n", "a.install")["_v"] == {"hook"}


def test_a_function_nobody_calls_is_unknown_and_so_are_its_callees():
    r = of("_orphan() { _inner; }\n_inner() { :; }\nbuild() { :; }\n")
    assert r["_orphan"] == {"unknown"} and r["_inner"] == {"unknown"}


def test_a_call_through_eval_or_sh_c_is_not_followed():
    r = of("_h() { :; }\n_g() { :; }\nbuild() { eval _h; sh -c _g; }\n")
    assert r["_h"] == {"unknown"} and r["_g"] == {"unknown"}
    r = of("_h() { :; }\nbuild() { _h; eval _h; }\n")
    assert r["_h"] == {"build", "unknown"}


def test_a_call_through_a_variable_is_not_followed():
    assert of('_h() { :; }\nbuild() { f=_h; "$f"; }\n')["_h"] == {"unknown"}


def test_recursion_terminates():
    r = of("_a() { _b; }\n_b() { _a; }\nbuild() { _a; }\n")
    assert r["_a"] == {"build"} and r["_b"] == {"build"}


def test_roles_of_a_command_by_the_function_it_is_in():
    p = pkg("build() { cp a b; }\nrm x\n")
    by_name = {c.command.name: c.function for c in p.commands}
    assert by_name == {"cp": "build", "rm": None}
    assert p.roles_of("build") == {"build"} and p.roles_of(None) == {"parse"}
    assert pkg("", "a.install").roles_of(None) == {"hook"}
    assert p.roles_of("nonesuch") == {"unknown"}


def test_a_file_that_is_not_shell_has_no_roles():
    assert pkg("x", "notes.txt").function_roles == {} and roles.ROLES[-1] == "unknown"
