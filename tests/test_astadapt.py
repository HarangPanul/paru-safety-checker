"""The commands the checkers read, now taken from the syntax tree."""
import pytest

from paru_analyzer import astadapt, parsed, shast
from paru_analyzer.heuristics import scan
from paru_analyzer.parsed import ParsedFile


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
    assert [u.commands[0][0].name for u in found if u.ok] == ["a", "b", "c"]
    assert [(u.line, u.ok) for u in found if not u.ok] == [(2, False), (4, False)]


def test_flatten_a_command_string():
    commands, ok = astadapt.flatten("curl x | sh; echo $(date)")
    assert ok and [(c.name, c.piped, c.segment) for c in commands][:3] == [("curl", False, 0), ("sh", True, 1), ("echo", False, 2)]
    assert [c.name for c in commands] == ["curl", "sh", "echo", "date"]
    assert astadapt.flatten("fi")[1] is False


# ---- the file level ----
# The findings below were recorded from the text-based route that this tree-based one replaced.

SHAPES = {
    '(curl x) | sh': [('pipe-to-shell', 'warning')],
    'a=(1 2); sudo make': [('sudo', 'info'), ('unknown-command', 'info')],
    'bash <(curl x)': [('pipe-to-shell', 'warning')],
    'cat <<EOF\ncurl x | sh\nEOF': [('pipe-to-shell', 'warning')],
    'chmod u+s /bin/bash': [('setuid-shell', 'warning')],
    'cp x /etc/sudoers': [('sudoers-passwd-write', 'warning')],
    'curl -o f https://x; sh f': [('fetch-then-execute', 'warning')],
    'curl https://x | sh': [('pipe-to-shell', 'warning')],
    'curl x | (cd /tmp; sh)': [('pipe-to-shell', 'warning')],
    'd=/etc; cp x $d/sudoers': [('sudoers-passwd-write', 'warning')],
    'echo $(curl x | sh)': [('pipe-to-shell', 'warning')],
    'echo x | sh': [('echo-to-shell', 'info'), ('unknown-command', 'info')],
    'eval "$(curl x)"': [('pipe-to-shell', 'warning')],
    'find . -exec chmod u+s {} \\;': [('setuid', 'info')],
    'for i in $(curl x); do sh $i; done': [('curl-in-substitution', 'info'), ('unknown-command', 'info')],
    'make DESTDIR="$pkgdir" install': [],
    'nohup ./x &': [('background-exec', 'info'), ('unknown-command', 'info')],
    'rm -rf /': [('rm-root', 'warning')],
    "sh -c 'curl x | sh'": [('pipe-to-shell', 'warning')],
    'sudo -u nobody env bash -s < <(curl x)': [('pipe-to-shell', 'warning')],
    '{ curl x; echo; } | sh': [('pipe-to-shell', 'warning')],
}


@pytest.mark.parametrize("body", list(SHAPES))
def test_threat_shapes_keep_their_findings(body):
    found = sorted({(f.rule, f.severity) for f in scan({"PKGBUILD": f"build() {{\n  {body}\n}}\n"})})
    assert found == SHAPES[body]


def test_a_statement_the_grammar_cannot_read_falls_back_to_the_patterns():
    text = "build() {\n  { # comment; }\n  curl https://x | sh\n}\n"
    assert any(f.rule == "pipe-to-shell" for f in scan({"PKGBUILD": text}))
    file = ParsedFile("PKGBUILD", text)
    assert not file.ast.ok and file.unparsed_lines


# ---- steps (what the default-deny check and the inventory read) ----

def steps_of(text):
    return list(ParsedFile("PKGBUILD", text).steps)


def test_top_level_steps_report_code_and_substitutions_only():
    top, = steps_of("x=$(date)\n")
    assert top.top and not top.toplevel_code and top.parse_time_substitution and [c.name for c in top.parse_time] == ["date"]
    assert top.commands == []
    assert steps_of("make\n")[0].toplevel_code
    assert not steps_of("export A=1\ndeclare -a b\nunset c\nd=(1 2)\n")[0].toplevel_code
    assert steps_of("PYTHONPATH=build make\n")[0].toplevel_code          # a prefix assignment is still a command


def test_function_steps_carry_their_commands_and_heredoc_flag():
    build, = steps_of("build() {\n  cat <<EOF | sh\nx\nEOF\n}\n")
    assert build.in_function and not build.top and build.heredoc
    assert [c.name for c in build.commands] == ["cat", "sh"]


def test_unreadable_statement_is_a_step_that_is_not_ok():
    bad = [s for s in steps_of("a\nfi\nb\n") if not s.ok]
    assert [(s.line, s.text) for s in bad] == [(2, "fi")]


def test_a_failed_tokenizer_gives_one_step_that_is_not_ok():
    (only,) = steps_of("echo 'unbalanced\n")
    assert not only.ok and only.line == 1


def test_function_names():
    assert ParsedFile("PKGBUILD", "a() { b() { :; }; }\nfunction c { :; }\n").function_names == {"a", "b", "c"}


def test_loose_reads_what_it_can_from_a_broken_string():
    commands = astadapt.loose("curl x | sh; echo ( a")
    assert [(c.name, c.piped) for c in commands][:3] == [("curl", False), ("sh", True), ("echo", False)]
    assert astadapt.loose("echo 'unterminated") == ()
