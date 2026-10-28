"""The commands the checkers read, now taken from the syntax tree."""
import pytest

from paru_safety_checker import astadapt, parsed, shast
from paru_safety_checker.heuristics import scan
from paru_safety_checker.parsed import ParsedFile


def units_of(text):
    result = shast.parse(text)
    assert result.ok, result.errors
    return astadapt.units(result.script)


def flat(text):
    """[(name, args, piped, segment, inside)] of the first unit."""
    found, _ = units_of(text)
    return [(c.name, c.args, c.piped, c.segment, c.inside) for c, _ in found[0].commands]


# ---- stages ----

def test_a_pipeline_is_one_unit_with_one_stage_per_command():
    found, _ = units_of("curl x | tee f | sh")
    assert len(found) == 1
    assert [(c.name, c.piped, c.segment) for c, _ in found[0].commands] == [("curl", False, 0), ("tee", True, 1), ("sh", True, 2)]


def test_a_group_before_the_pipe_is_one_stage():
    assert [(n, p, s) for n, _, p, s, _ in flat("{ curl x; echo; } | sh")] == [("curl", False, 0), ("echo", False, 0), ("sh", True, 1)]
    assert [(n, p, s) for n, _, p, s, _ in flat("(cd y; curl x) | sh")] == [("cd", False, 0), ("curl", False, 0), ("sh", True, 1)]


def test_a_group_after_the_pipe_reads_the_pipe_in_all_its_commands():
    assert [(n, p, s) for n, _, p, s, _ in flat("curl x | (cd /tmp; sh)")] == [("curl", False, 0), ("cd", True, 1), ("sh", True, 1)]
    assert [(n, p) for n, _, p, _, _ in flat("curl x | { cd y; sh; }")] == [("curl", False), ("cd", True), ("sh", True)]


def test_and_or_and_semicolons_split_into_units():
    found, _ = units_of("a | b && c | d; e")
    assert [[c.name for c, _ in u.commands] for u in found] == [["a", "b"], ["c", "d"], ["e"]]
    assert all(c.segment in (0, 1) for u in found for c, _ in u.commands)


def test_compound_commands_give_their_inner_statements_as_units():
    found, _ = units_of("if a | b; then c; else d; fi\nwhile e; do f; done\ncase x in y) g ;; esac\n{ h; }\n(i)")
    assert [[c.name for c, _ in u.commands] for u in found] == [["a", "b"], ["c"], ["d"], ["e"], ["f"], ["g"], ["h"], ["i"]]


# ---- substitutions ----

def test_substitution_commands_follow_the_main_ones_and_are_marked_inside():
    assert flat("echo a$(b)c `d` <(e)") == [
        ("echo", ["a__SUB__c", "__SUB__", "__SUB__"], False, 0, False),
        ("b", [], False, 1, True), ("d", [], False, 2, True), ("e", [], False, 3, True)]


def test_a_pipeline_inside_a_substitution_keeps_its_stages():
    rows = flat("x=$(curl y | sh)\nrest")
    inner = [(n, p, s) for n, _, p, s, inside in rows if inside]
    assert inner == [("curl", False, 0), ("sh", True, 1)] or inner == [("curl", False, 1), ("sh", True, 2)]
    assert inner[1][2] == inner[0][2] + 1


def test_nested_substitutions_are_all_reached():
    names = [n for n, *_ in flat("echo $(a $(b $(c)))")]
    assert names == ["echo", "a", "b", "c"]


def test_substitutions_in_arithmetic_headers_redirects_and_here_documents():
    assert [n for n, *_ in flat("echo $(( $(a) + 1 ))")] == ["echo", "a"]
    assert [n for n, *_ in flat("cat > $(f) <<< $(g)")] == ["cat", "f", "g"]
    found, _ = units_of("cat <<EOF\nhi $(a)\nEOF")
    assert [c.name for c, _ in found[0].commands] == ["cat", "a"]
    found, _ = units_of("cat <<'EOF'\nhi $(a)\nEOF")
    assert [c.name for c, _ in found[0].commands] == ["cat"]


def test_an_assignment_alone_runs_only_its_substitutions():
    assert [n for n, *_ in flat("x=$(date)")] == ["date"]
    assert [n for n, *_ in flat("x=1 y=(a $(b))")] == ["b"]
    assert [n for n, *_ in flat("x=1 make")] == ["make"]


def test_headers_of_compound_commands_are_units_of_their_substitutions():
    found, _ = units_of("for f in $(ls); do echo $f; done")
    assert [[c.name for c, _ in u.commands] for u in found] == [["ls"], ["echo"]]
    assert found[0].commands[0][0].inside
    found, _ = units_of("case $(uname) in x) a ;; esac\n[[ -n $(b) ]]\nwhile read l; do :; done < <(c)")
    assert [c.name for u in found for c, _ in u.commands if c.inside] == ["uname", "b", "c"]


# ---- words, redirects, classification ----

def test_find_exec_and_xargs_targets_and_wrappers_are_still_extracted():
    assert [n for n, *_ in flat(r"find . -exec chmod u+s {} \;")] == ["find", "chmod"]
    assert [n for n, *_ in flat("xargs -n1 rm -rf")] == ["xargs", "rm"]
    assert [n for n, *_ in flat("env FOO=1 nice -n 5 make")] == ["env", "nice", "make"]


def test_words_that_are_not_commands_give_none():
    for text in ["[ -f x ]", "test -f x", "[[ -f x ]]", "((i++))"]:
        found, _ = units_of(text)
        assert not [c for u in found for c, _ in u.commands], text


def test_descriptor_duplications_and_heredocs_are_not_redirect_targets():
    found, _ = units_of("cmd >out 2>&1 <in >&2 >&- <<EOF\nx\nEOF")
    assert found[0].commands[0][0].redirects == ((">", "out"), ("<", "in"))


def test_redirects_detail():
    cmd = units_of("cmd >out 2>&1 <in >>log")[0][0].commands[0][0]
    assert cmd.redirects == ((">", "out"), ("<", "in"), (">>", "log"))
    cmd = units_of("cmd <<< $(x)")[0][0].commands[0][0]
    assert cmd.redirects == (("<<<", "__SUB__"),)
    assert units_of("> f")[0][0].commands[0][0].name == ":"


def test_word_text_placeholders():
    word = shast.parse(r"echo a$(b)c $((1+2)) 'q r' \; $x").script.items[0].node.words
    assert [astadapt.word_text(w) for w in word[1:]] == ["a__SUB__c", "0", "q r", "__SEMI__", "$x"]


def test_render_is_one_line_with_the_words_as_written():
    assert astadapt.render(shast.parse("FOO=1 c''url  -s 'a b' >out | sh").script.items[0]) == "FOO=1 c''url -s 'a b' >out | sh"
    assert astadapt.render(shast.parse("a && b || c").script.items[0]) == "a && b || c"
    assert astadapt.render(shast.parse("a=(1 2)").script.items[0]) == "a=(1 2)"


# ---- where it sits ----

def test_top_level_and_function_units():
    found, _ = units_of("x\nf() {\n  y\n  g() { z; }\n}\n")
    assert [(u.commands[0][0].name, u.top) for u in found] == [("x", True), ("y", False), ("z", False)]


def test_lines_are_the_start_of_the_statement():
    found, _ = units_of("a\ncurl x |\n  sh\nb \\\n  c")
    assert [(u.line, [l for _, l in u.commands]) for u in found] == [(1, [1]), (2, [2, 2]), (4, [4])]


def test_unreadable_statements_are_reported_by_line_and_the_rest_is_still_read():
    found, bad = astadapt.units(shast.parse("a\nfi\nb\n  }\nc").script)
    assert sorted(bad) == [2, 4]
    assert [u.commands[0][0].name for u in found] == ["a", "b", "c"]


def test_flatten_a_command_string():
    commands, ok = astadapt.flatten("curl x | sh; echo $(date)")
    assert ok and [(c.name, c.piped, c.segment) for c in commands][:3] == [("curl", False, 0), ("sh", True, 1), ("echo", False, 2)]
    assert [c.name for c in commands] == ["curl", "sh", "echo", "date"]
    assert astadapt.flatten("fi")[1] is False


# ---- the file level: both routes agree ----

def both_routes(text, name="PKGBUILD"):
    results = []
    for use_ast in (False, True):
        old = parsed.USE_AST
        parsed.USE_AST = use_ast
        try:
            results.append(sorted((f.rule, f.severity) for f in scan({name: text}) if f.severity != "info"))
        finally:
            parsed.USE_AST = old
    return results


@pytest.mark.parametrize("body", [
    "curl https://x | sh", "(curl x) | sh", "{ curl x; echo; } | sh", "curl x | (cd /tmp; sh)", "echo $(curl x | sh)",
    "sh -c 'curl x | sh'", "eval \"$(curl x)\"", "bash <(curl x)", "cp x /etc/sudoers", "d=/etc; cp x $d/sudoers",
    "rm -rf /", "chmod u+s /bin/bash", "curl -o f https://x; sh f", r"find . -exec chmod u+s {} \;",
    "cat <<EOF\ncurl x | sh\nEOF", "a=(1 2); sudo make", "for i in $(curl x); do sh $i; done", "echo x | sh",
    "nohup ./x &", "sudo -u nobody env bash -s < <(curl x)", "make DESTDIR=\"$pkgdir\" install",
])
def test_both_routes_give_the_same_findings(body):
    old, new = both_routes(f"build() {{\n  {body}\n}}\n")
    assert old == new


def test_the_rule_cases_give_the_same_findings_on_both_routes():
    from tests import test_rule_matrix
    different = []
    for line, _ in test_rule_matrix.CASES:
        old, new = both_routes(f"build() {{\n  {line}\n}}\n")
        if old != new:
            different.append((line, old, new))
    assert not different, different[:3]


def test_a_statement_the_grammar_cannot_read_falls_back_to_the_patterns():
    text = "build() {\n  { # comment; }\n  curl https://x | sh\n}\n"
    assert any(f.rule == "pipe-to-shell" for f in scan({"PKGBUILD": text}))
    file = ParsedFile("PKGBUILD", text)
    assert not file.ast.ok and file.unparsed_lines
