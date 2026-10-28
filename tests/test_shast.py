"""The shell syntax tree: structure, positions, words, here-documents, errors, and agreement with bash."""
import random
import shutil
import subprocess
import time

import pytest

from paru_safety_checker import shast
from paru_safety_checker.shast import (
    AndOr, ArithCommand, Assign, Case, CmdSub, Conditional, For, FunctionDef, Group, HereDoc, If, Lit, Param,
    Pipeline, ProcSub, Redirect, Simple, Statement, Subshell, Unparsed, While, Word, decode_ansi_c, dump, parse,
    simple_commands, walk,
)


def tree(text):
    result = parse(text)
    assert result.ok, result.errors
    return dump(result.script)


def first(text):
    result = parse(text)
    assert result.ok, result.errors
    return result.script.items[0].node


def word(text):
    return first(f"echo {text}").words[1]


# ---- structure ----

STRUCTURE = [
    ("ls", "(cmd ls)"),
    ("ls -la /tmp", "(cmd ls -la /tmp)"),
    ("a; b", "(cmd a) (cmd b)"),
    ("a\nb", "(cmd a) (cmd b)"),
    ("a;\n\nb;", "(cmd a) (cmd b)"),
    ("a | b", "(| (cmd a) (cmd b))"),
    ("a | b | c", "(| (cmd a) (cmd b) (cmd c))"),
    ("a |& b", "(| (cmd a) (cmd b))"),
    ("a |\n  b", "(| (cmd a) (cmd b))"),
    ("a \\\n | b", "(| (cmd a) (cmd b))"),
    ("! a | b", "(!| (cmd a) (cmd b))"),
    ("a && b", "(list (cmd a) && (cmd b))"),
    ("a && b || c", "(list (cmd a) && (cmd b) || (cmd c))"),
    ("a &&\n  b", "(list (cmd a) && (cmd b))"),
    ("a | b && c | d", "(list (| (cmd a) (cmd b)) && (| (cmd c) (cmd d)))"),
    ("a &", "(& (cmd a))"),
    ("a & b", "(& (cmd a)) (cmd b)"),
    ("a | b &", "(& (| (cmd a) (cmd b)))"),
    ("(a; b)", "(subshell (cmd a) (cmd b))"),
    ("(a) | b", "(| (subshell (cmd a)) (cmd b))"),
    ("{ a; b; }", "(group (cmd a) (cmd b))"),
    ("{ a; } | b", "(| (group (cmd a)) (cmd b))"),
    ("a | { b; }", "(| (cmd a) (group (cmd b)))"),
    ("a | (cd x; b)", "(| (cmd a) (subshell (cmd cd x) (cmd b)))"),
    ("{\n  a\n  b\n}", "(group (cmd a) (cmd b))"),
    ("if a; then b; fi", "((if (cmd a) (then (cmd b))))"),
    ("if a; then b; else c; fi", "((if (cmd a) (then (cmd b))) (else (cmd c)))"),
    ("if a; then b; elif c; then d; else e; fi",
     "((if (cmd a) (then (cmd b))) (elif (cmd c) (then (cmd d))) (else (cmd e)))"),
    ("if a\nthen\n  b\nfi", "((if (cmd a) (then (cmd b))))"),
    ("if a && b; then c; fi", "((if (list (cmd a) && (cmd b)) (then (cmd c))))"),
    ("if ! a; then b; fi", "((if (!| (cmd a)) (then (cmd b))))"),
    ("while a; do b; done", "(while ((cmd a)) (do (cmd b)))"),
    ("until a; do b; done", "(until ((cmd a)) (do (cmd b)))"),
    ("while a\ndo\n  b\ndone", "(while ((cmd a)) (do (cmd b)))"),
    ("for i in 1 2 3; do echo $i; done", "(for i (in 1 2 3) (do (cmd echo $i)))"),
    ("for i in a b\ndo\n  c\ndone", "(for i (in a b) (do (cmd c)))"),
    ("for i; do c; done", "(for i (do (cmd c)))"),
    ("for i in; do c; done", "(for i (in ) (do (cmd c)))"),
    ("for ((i=0;i<3;i++)); do c; done", "(for (((i=0;i<3;i++))) (do (cmd c)))"),
    ("select x in a b; do c; done", "(select x (in a b) (do (cmd c)))"),
    ("case $x in a) b ;; esac", "(case $x (clause (a) (cmd b) ;;))"),
    ("case $x in a|b) c ;; *) d ;; esac", "(case $x (clause (a b) (cmd c) ;;) (clause (*) (cmd d) ;;))"),
    ("case $x in (a) b ;; esac", "(case $x (clause (a) (cmd b) ;;))"),
    ("case $x in\n  a)\n    b\n    c\n    ;;\n  *) ;;\nesac", "(case $x (clause (a) (cmd b) (cmd c) ;;) (clause (*)  ;;))"),
    ("case $x in a) b ;& c) d ;;& esac", "(case $x (clause (a) (cmd b) ;&) (clause (c) (cmd d) ;;&))"),
    ("case $x in a) b; esac", "(case $x (clause (a) (cmd b) ;;))"),
    ("f() { a; }", "(function f (group (cmd a)))"),
    ("f () { a; }", "(function f (group (cmd a)))"),
    ("f()\n{\n  a\n}", "(function f (group (cmd a)))"),
    ("function f { a; }", "(function f (group (cmd a)))"),
    ("function f() { a; }", "(function f (group (cmd a)))"),
    ("f() ( a )", "(function f (subshell (cmd a)))"),
    ("f() if a; then b; fi", "(function f ((if (cmd a) (then (cmd b)))))"),
    ("[[ -f x ]]", "(dbracket -f x)"),
    ("[[ $a == b && -n c ]] && d", "(list (dbracket $a == b && -n c) && (cmd d))"),
    ("((i++))", "(arith 'i++')"),
    ("(( x = 1 + 2 ))", "(arith ' x = 1 + 2 ')"),
    ("a > f", "(cmd a >f)"),
    ("> f", "(cmd >f)"),
    ("a 2>&1", "(cmd a 2>&1)"),
    ("a &> f", "(cmd a &>f)"),
    ("a >> f 2> g < h", "(cmd a >>f 2>g <h)"),
    ("a <<< word", "(cmd a <<<word)"),
    ("a >&2", "(cmd a >&2)"),
    ("{ a; } > f", "(group (cmd a) >f)"),
    ("(a) 2>&1", "(subshell (cmd a) 2>&1)"),
    ("while a; do b; done < f", "(while ((cmd a)) (do (cmd b)) <f)"),
    ("if a; then b; fi | c", "(| ((if (cmd a) (then (cmd b)))) (cmd c))"),
    ("a=1", "(cmd a=1)"),
    ("a=1 b=2 c", "(cmd a=1 b=2 c)"),
    ("a+=x", "(cmd a+=x)"),
    ("a[3]=x", "(cmd a[3]=x)"),
    ("a=1 c d=3", "(cmd a=1 c d=3)"),
    ("a=(1 2 3)", "(cmd a=(1 2 3))"),
    ("a+=(x y)", "(cmd a+=(x y))"),
    ("a=()", "(cmd a=())"),
    ("a=(\n  x\n  y # note\n)", "(cmd a=(x y))"),
    ("a[0]=(x)", "(cmd a[0]=(x))"),
    ("local a=(1 2); b", "(cmd local a=(1 2)) (cmd b)"),
    ("# only a comment\n", ""),
    ("", ""),
    ("a # trailing\nb", "(cmd a) (cmd b)"),
]


@pytest.mark.parametrize("text,expected", STRUCTURE, ids=[t.replace("\n", "\\n")[:50] for t, _ in STRUCTURE])
def test_structure(text, expected):
    assert tree(text) == expected


def test_node_types():
    assert isinstance(first("a | b"), Pipeline)
    assert isinstance(first("a && b"), AndOr)
    assert isinstance(first("(a)"), Subshell)
    assert isinstance(first("{ a; }"), Group)
    assert isinstance(first("if a; then b; fi"), If)
    assert isinstance(first("while a; do b; done"), While)
    assert isinstance(first("for i in a; do b; done"), For)
    assert isinstance(first("case x in a) b;; esac"), Case)
    assert isinstance(first("f() { a; }"), FunctionDef)
    assert isinstance(first("[[ a ]]"), Conditional)
    assert isinstance(first("((a))"), ArithCommand)
    assert isinstance(parse("a &").script.items[0], Statement) and parse("a &").script.items[0].background


def test_a_single_command_is_not_wrapped():
    assert isinstance(first("a"), Simple)
    assert isinstance(first("a && b").first, Simple)


def test_pipeline_details():
    node = first("! a |& b | c")
    assert node.negated and node.stderr == (True, False)
    assert [c.name for c in node.commands] == ["a", "b", "c"]


def test_simple_command_accessors():
    node = first("FOO=1 sudo -u root make 'a b' >out")
    assert node.name == "sudo" and node.args == ("-u", "root", "make", "a b")
    assert [a.name for a in node.assigns] == ["FOO"]
    assert [(r.op, r.target.value) for r in node.redirects] == [(">", "out")]


def test_an_assignment_after_the_command_word_is_an_argument():
    node = first("env a=1 b")
    assert node.assigns == () and node.args == ("a=1", "b")


def test_assignment_details():
    node = first("a[i]+=x b=(1 'two words' $(c))")
    one, two = node.assigns
    assert (one.name, one.index, one.append, one.value.value) == ("a", "i", True, "x")
    assert two.array is not None and [w.value for w in two.array] == ["1", "two words", "$(c)"]
    assert isinstance(two.array[2].parts[0], CmdSub)


# ---- positions ----

def test_lines_of_statements():
    script = parse("a\n\nb c\n  d\n").script
    assert [(s.line, s.end) for s in script.items] == [(1, 1), (3, 3), (4, 4)]


def test_a_command_continued_over_lines_spans_them():
    node = first("curl \\\n  -o f \\\n  https://x")
    assert (node.line, node.end) == (1, 3)
    assert [w.line for w in node.words] == [1, 2, 2, 3]


def test_compound_commands_span_their_body():
    node = first("if a; then\n  b\n  c\nfi")
    assert (node.line, node.end) == (1, 4)
    func = first("f() {\n  a\n  b\n}")
    assert (func.line, func.end) == (1, 4)
    assert (func.body.line, func.body.end) == (1, 4)


def test_lines_inside_a_function():
    script = parse("pkgver=1\nbuild() {\n  cd x\n  make\n}\n").script
    body = script.items[1].node.body.body
    assert [(s.line, s.node.name) for s in body.items] == [(3, "cd"), (4, "make")]


def test_command_substitution_keeps_its_own_lines():
    node = first('echo "line one\n$(date\n  uname)"')
    sub = node.words[1].parts[1]
    assert isinstance(sub, CmdSub)
    assert [(s.line, s.node.name) for s in sub.script.items] == [(2, "date"), (3, "uname")]


def test_array_items_have_their_own_lines():
    node = first("source=(\n  'a'\n  'b'\n)")
    assert [w.line for w in node.assigns[0].array] == [2, 3]


def test_comments_are_collected_with_lines():
    result = parse("a # one\n# two\nb\n")
    assert result.comments == ((1, "# one"), (2, "# two"))


# ---- words ----

@pytest.mark.parametrize("raw,value", [
    ("plain", "plain"),
    ("'single quoted'", "single quoted"),
    ('"double quoted"', "double quoted"),
    ("a'b'\"c\"d", "abcd"),
    ("c''url", "curl"),
    ('"c"u\\rl', "curl"),
    ("\\$HOME", "$HOME"),
    ("a\\ b", "a b"),
    ("'it'\\''s'", "it's"),
    ('"a\\"b"', 'a"b'),
    ('"a\\$b"', "a$b"),
    ('"a\\nb"', "a\\nb"),
    ("'a\\nb'", "a\\nb"),
    ("a\\\nb", "ab"),
    ("$'\\x63url'", "curl"),
    ("$'c\\165rl'", "curl"),
    ("$'a\\tb'", "a\tb"),
    ("$'\\u0041'", "A"),
    ("$HOME/bin", "$HOME/bin"),
    ("${HOME}/bin", "${HOME}/bin"),
    ("~/.bashrc", "~/.bashrc"),
    ('"$x"', "$x"),
    ('"${x:-d}"', "${x:-d}"),
    ("a=b", "a=b"),
    ("--opt=\"v w\"", "--opt=v w"),
    ('""', ""),
    ("''", ""),
])
def test_word_value(raw, value):
    assert word(raw).value == value


def test_ansi_c_decoding():
    assert decode_ansi_c(r"\x63\165rl") == "curl"
    assert decode_ansi_c(r"a\nb\\c\'d") == "a\nb\\c'd"
    assert decode_ansi_c(r"\e[0m") == "\x1b[0m"
    assert decode_ansi_c(r"\q") == "\\q"
    assert decode_ansi_c(r"\cA") == "\x01"


def test_literal_and_quoted_parts():
    parts = word("a'b'\"c\"").parts
    assert [(p.text, p.quoted) for p in parts] == [("a", False), ("b", True), ("c", True)]
    assert word("a").literal and word("'$x'").literal
    assert not word("$x").literal and not word("$(x)").literal and not word('"$x"').literal


def test_parameters():
    p = word("${name:-default}").parts[0]
    assert isinstance(p, Param) and p.name == "name" and p.raw == "${name:-default}"
    assert word("$1").parts[0].name == "1"
    assert word("$@").parts[0].name == "@"
    assert word("${#arr[@]}").parts[0].name == "arr"
    assert word('"$x"').parts[0].quoted


def test_command_substitution_parts():
    parts = word("pre$(a | b)post").parts
    assert [type(p).__name__ for p in parts] == ["Lit", "CmdSub", "Lit"]
    assert dump(parts[1].script) == "(| (cmd a) (cmd b))"
    assert word("pre$(a | b)post").value == "pre$(a | b)post"


def test_nested_substitutions():
    outer = word("$(echo $(date +%s))").parts[0]
    inner = outer.script.items[0].node.words[1].parts[0]
    assert isinstance(inner, CmdSub) and inner.script.items[0].node.name == "date"


def test_backticks():
    sub = word("`echo hi`").parts[0]
    assert isinstance(sub, CmdSub) and sub.backtick and sub.script.items[0].node.args == ("hi",)
    escaped = word("`echo \\`date\\``").parts[0]
    assert escaped.script.items[0].node.words[1].parts[0].script.items[0].node.name == "date"


def test_substitution_inside_double_quotes_and_parameters():
    quoted = word('"a $(b) c"').parts
    assert [type(p).__name__ for p in quoted] == [("Lit"), "CmdSub", "Lit"] and quoted[1].quoted
    default = word("${x:-$(cmd)}").parts[0]
    assert isinstance(default.subs[0], CmdSub) and default.subs[0].script.items[0].node.name == "cmd"


def test_process_substitution():
    node = first("diff <(sort a) >(tee b)")
    left, right = node.words[1].parts[0], node.words[2].parts[0]
    assert isinstance(left, ProcSub) and left.direction == "<" and left.script.items[0].node.name == "sort"
    assert isinstance(right, ProcSub) and right.direction == ">"


def test_arithmetic_expansion():
    part = word("$((1 + $(x)))").parts[0]
    assert part.raw == "$((1 + $(x)))" and type(part).__name__ == "Arith"


def test_substitutions_property_lists_them_all():
    w = word('"$(a)"$(b)${c:-$(d)}`e`')
    assert [s.script.items[0].node.name for s in w.substitutions] == ["a", "b", "d", "e"]


def test_a_dollar_that_is_not_an_expansion():
    assert word("a$").value == "a$"
    assert word("$/x").value == "$/x"


# ---- here-documents ----

def test_heredoc_body_and_following_commands():
    node = first("cat <<EOF\nhello $x\nworld\nEOF\nnext")
    here = node.redirects[0].target
    assert isinstance(here, HereDoc)
    assert (here.delimiter, here.body, here.quoted, here.strip_tabs) == ("EOF", ("hello $x", "world"), False, False)
    assert here.body_line == 2
    assert tree("cat <<EOF\nhello\nEOF\nnext") == "(cmd cat <<EOF[hello]) (cmd next)"


def test_quoted_and_dash_heredocs():
    assert first("cat <<'EOF'\n$x\nEOF").redirects[0].target.quoted
    assert first('cat <<"EOF"\n$x\nEOF').redirects[0].target.quoted
    dash = first("cat <<-EOF\n\tbody\n\tEOF").redirects[0].target
    assert dash.strip_tabs and dash.body == ("\tbody",)


def test_two_heredocs_on_one_line_are_filled_in_order():
    node = first("cmd <<A <<B\none\nA\ntwo\nB")
    a, b = (r.target for r in node.redirects)
    assert (a.delimiter, a.body, b.delimiter, b.body) == ("A", ("one",), "B", ("two",))


def test_heredoc_in_a_pipeline_and_a_function():
    script = parse("f() {\n  cat <<EOF | sh\ncurl x | sh\nEOF\n  after\n}\n").script
    body = script.items[0].node.body.body.items
    assert isinstance(body[0].node, Pipeline) and body[0].node.commands[0].redirects[0].target.body == ("curl x | sh",)
    assert body[1].node.name == "after"


def test_an_empty_and_an_unterminated_heredoc():
    assert first("cat <<EOF\nEOF").redirects[0].target.body == ()
    node = first("cat <<EOF\nnever ends\nstill")
    assert node.redirects[0].target.body == ("never ends", "still")


def test_heredoc_body_is_not_parsed_as_commands():
    assert tree("cat <<EOF\nif then fi ( ; ))\nEOF") == "(cmd cat <<EOF[if then fi ( ; ))])"


def test_heredoc_delimiter_inside_a_substitution_does_not_break_the_outer_parse():
    result = parse("x=$(cat <<EOF\nbody\nEOF\n)\nnext\n")
    assert [s.node.name for s in simple_commands(result.script) if s.node.name] == ["cat", "next"] or result.ok


# ---- errors and recovery ----

INVALID = [
    "fi", "done", "esac", "}", ")", "then", "else", ";;",
    "if a; then b", "if a; b; fi", "if; then b; fi", "if a; then fi", "while a; do done",
    "for; do a; done", "for i in a b", "for 1x in a; do b; done",
    "case x in a) b", "case x in a) b esac", "case x a) b ;; esac", "case x in a b ;; esac",
    "{ a", "{ }", "( a", "( )", "a )", "a | ", "| a", "a && ", "&& a", "a ||", "a &;", "a ; ;",
    "echo \"unterminated", "echo 'unterminated", "echo $(unterminated", "echo ${unterminated", "echo `unterminated",
    "a > ", "a <", "f() ", "function", "[[ a", "a ( b",
    "echo $((1 + ",
]


@pytest.mark.parametrize("text", INVALID)
def test_invalid_scripts_are_reported(text):
    result = parse(text)
    assert not result.ok and result.errors
    assert any(isinstance(n, Unparsed) for n in walk(result.script))


def test_parsing_resumes_after_a_bad_line():
    result = parse("a\nfi\nb | c\n")
    assert not result.ok and result.errors[0][0] == 2
    assert dump(result.script) == "(cmd a) (unparsed 'fi') (| (cmd b) (cmd c))"


def test_a_bad_line_inside_a_function_does_not_lose_the_rest():
    result = parse("f() {\n  a\n  fi\n  b\n}\nc\n")
    names = [s.node.name for s in simple_commands(result.script) if s.node.name]
    assert not result.ok and names == ["a", "b", "c"]


def test_errors_carry_the_line_of_the_problem():
    result = parse("a\nb\nc | \n")
    assert result.errors and result.errors[0][0] in (3, 4)
    assert parse("a\n  }\n").errors[0][0] == 2


def test_an_unterminated_quote_makes_the_whole_file_unparsed():
    result = parse("a\n'never closed\nb\n")
    assert not result.ok and isinstance(result.script.items[0].node, Unparsed)
    assert (result.script.line, result.script.end) == (1, 4)


def test_parse_never_raises_on_odd_input():
    for text in ["\x00", "\\", "$", "${", "$(", "`", "<<", "<<EOF", "a <<", "(((", ")))", "{{{", "&&&", "a=(", "‮", "é", " \t\n"]:
        result = parse(text)
        assert isinstance(result.script, shast.Script)


def test_nesting_depth_is_bounded():
    result = parse("echo " + "$(" * 60 + "x" + ")" * 60)
    assert not result.ok
    deep_groups = parse("{ " * 500 + "a" + "; }" * 500)
    assert isinstance(deep_groups.script, shast.Script)


# ---- walking ----

def test_walk_visits_parents_before_children_in_source_order():
    names = [n.name for n in walk(parse("a | b\nc $(d)").script) if isinstance(n, Simple)]
    assert names == ["a", "b", "c", "d"]


def test_simple_commands_report_where_they_sit():
    script = parse("top\nf() {\n  in_f | next\n  x=$(sub)\n}\ncat <(proc)\n").script
    found = {s.node.name: s for s in simple_commands(script)}
    assert found["top"].function is None and found["top"].stages == 1 and found["top"].stage is None
    assert found["in_f"].function == "f" and (found["in_f"].stage, found["in_f"].stages) == (0, 2)
    assert (found["next"].stage, found["next"].stages) == (1, 2)
    assert found["sub"].function == "f" and found["sub"].substitution
    assert found["proc"].substitution and found["proc"].function is None
    assert not found["cat"].substitution


def test_simple_commands_find_commands_in_every_compound():
    text = "if a; then b; elif c; then d; else e; fi\nwhile f; do g; done\nfor i in $(h); do j; done\ncase $(k) in l) m ;; esac\n{ n; } 2>$(o)\n"
    names = [s.node.name for s in simple_commands(parse(text).script) if s.node.name]
    assert sorted(names) == list("abcdefghjkmno")


def test_simple_commands_see_substitutions_in_assignments_and_redirects():
    names = [s.node.name for s in simple_commands(parse("x=$(a) y=(`b`) c >$(d) <<<$(e)\n").script) if s.node.name]
    assert sorted(names) == ["a", "b", "c", "d", "e"]


def test_the_shapes_the_checkers_care_about():
    pipe = first("curl -fsSL https://x | sudo -E bash -s --")
    assert isinstance(pipe, Pipeline)
    assert [c.name for c in pipe.commands] == ["curl", "sudo"]
    grouped = first("{ curl x; echo; } | sh")
    assert isinstance(grouped.commands[0], Group) and grouped.commands[1].name == "sh"
    fed = first("curl x | (cd /tmp; sh)")
    assert isinstance(fed.commands[1], Subshell)
    assert [s.node.name for s in simple_commands(fed) if s.stage == 1] == []     # the group is the stage, not a simple command


# ---- real PKGBUILD shapes ----

PKGBUILD = """\
# Maintainer: Someone <a@b.c>
pkgname=foo
pkgver=1.2.3
pkgrel=1
arch=('x86_64')
depends=('glibc' "bar>=1")
source=("https://example.com/$pkgname-$pkgver.tar.gz"
        'local.patch')
sha256sums=('SKIP'
            'abc')

prepare() {
  cd "$srcdir/$pkgname-$pkgver"
  patch -p1 < "$srcdir/local.patch"
}

build() {
  cd "$srcdir/$pkgname-$pkgver"
  ./configure --prefix=/usr
  make -j"$(nproc)"
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  make DESTDIR="$pkgdir" install
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  for f in "$pkgdir"/usr/bin/*; do
    [[ -x $f ]] || chmod +x "$f"
  done
}
"""


def test_a_typical_pkgbuild():
    result = parse(PKGBUILD)
    assert result.ok and result.comments == ((1, "# Maintainer: Someone <a@b.c>"),)
    items = result.script.items
    declared = [(s.node.assigns[0].name, s.line) for s in items if isinstance(s.node, Simple) and s.node.assigns]
    assert declared == [("pkgname", 2), ("pkgver", 3), ("pkgrel", 4), ("arch", 5), ("depends", 6), ("source", 7), ("sha256sums", 9)]
    functions = {s.node.name: (s.line, s.end) for s in items if isinstance(s.node, FunctionDef)}
    assert functions == {"prepare": (12, 15), "build": (17, 21), "package": (23, 30)}
    source = items[5].node.assigns[0].array
    assert [(w.value, w.line) for w in source] == [("https://example.com/$pkgname-$pkgver.tar.gz", 7), ("local.patch", 8)]
    in_package = [s.node.name for s in simple_commands(result.script) if s.function == "package" and s.node.name]
    assert in_package == ["cd", "make", "install", "chmod"]


def test_install_script_shapes():
    text = "post_install() {\n  echo \"==> run: sudo systemctl enable x\"\n  systemctl daemon-reload\n}\npost_upgrade() {\n  post_install\n}\n"
    names = [s.node.name for s in simple_commands(parse(text).script) if s.node.name]
    assert names == ["echo", "systemctl", "post_install"]


# ---- performance and robustness ----

@pytest.mark.parametrize("unit", ["echo >a ", "curl x | ", "a; ", "a && ", "(a) | ", "{ a; } | ", "$(a) ", "'x' ", "a=(1) "])
def test_long_lines_are_parsed_in_reasonable_time(unit):
    text = "build() {\n  " + unit * (60000 // len(unit)) + "\n}\n"
    start = time.time()
    result = parse(text)
    assert time.time() - start < 10, unit
    assert isinstance(result.script, shast.Script)


def test_many_lines_are_linear():
    text = "build() {\n" + "  make -j4 && echo done\n" * 20000 + "}\n"
    start = time.time()
    assert parse(text).ok
    assert time.time() - start < 10


def test_fuzzed_input_always_returns():
    random.seed(7)
    pieces = ["a", "|", "&&", "||", ";", "&", "(", ")", "{", "}", "if", "then", "fi", "do", "done", "for", "in", "case", "esac",
              ";;", "<<EOF", "EOF", "\n", " ", "'", '"', "$(", "`", "${", "}", "#", "\\", "=(", "[[", "]]", "<", ">", "2>&1", "!", "function f"]
    for _ in range(3000):
        text = "".join(random.choice(pieces) + random.choice(["", " ", " "]) for _ in range(random.randint(1, 25)))
        result = parse(text)
        assert isinstance(result.script, shast.Script)
        assert result.ok or result.errors
        for node in walk(result.script):          # the tree is always walkable, and every node has a sane position
            assert node.line >= 0 and node.end >= node.line - 1 or isinstance(node, (Lit, Param, CmdSub, ProcSub, shast.Arith))


# ---- agreement with bash ----

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")


def bash_accepts(text):
    return subprocess.run(["bash", "-n"], input=text, text=True, capture_output=True, timeout=20).returncode == 0


VALID = [
    "a", "a | b", "a && b || c", "a &", "a & b", "(a; b)", "{ a; b; }", "if a; then b; fi", "if a; then b; else c; fi",
    "while a; do b; done", "until a; do b; done", "for i in 1 2; do a; done", "for ((i=0;i<2;i++)); do a; done",
    "case x in a) b ;; *) c ;; esac", "case x in a) ;; esac", "f() { a; }", "function f { a; }", "a=1 b", "a=(1 2 3)",
    "a=(\n 1\n 2\n)", "cat <<EOF\nx\nEOF", "cat <<'EOF'\n$x\nEOF", "cat <<-EOF\n\tx\n\tEOF", "a > f 2>&1", "a <<< b",
    "[[ -f x && y == z ]]", "((i++))", "! a", "a | b |& c", "a \\\n  b", "echo $(a $(b))", "echo `a`", "echo <(a)",
    "a=$(b)", "x=1; y=2", "f() { a; }; f", "{ a; } | b", "(a) | b", "a | (b; c)", "if a; then (b) | c; fi",
    "case $x in\n  a)\n    b\n    ;;\nesac", "while read l; do echo $l; done < f", "a;", "a;;" if False else "a",
    "select x in a b; do c; done", "echo ${a:-b} ${#c} ${d//e/f}", "echo $((1+2))", "echo $'a\\tb'", "# comment\na",
    "a # c\nb", "if a\nthen\n  b\nfi", "f()\n{\n  a\n}", "a &&\n  b", "a |\n  b", "for i; do a; done",
    "case x in (a) b ;; esac", "case x in a) b ;& c) d ;;& esac",
]

INVALID_FOR_BASH = [t for t in INVALID if t not in ("a ( b",)]


@needs_bash
@pytest.mark.parametrize("text", VALID)
def test_valid_scripts_are_accepted_like_bash(text):
    assert bash_accepts(text), "the test case itself is not valid bash"
    assert parse(text).ok


@needs_bash
@pytest.mark.parametrize("text", INVALID_FOR_BASH)
def test_invalid_scripts_are_rejected_like_bash(text):
    if bash_accepts(text):
        pytest.skip("bash accepts this form")
    assert not parse(text).ok


@needs_bash
def test_agrees_with_bash_on_the_rule_test_cases():
    from tests import test_rule_matrix, test_rule_matrix_files
    texts = [f"build() {{\n  {line}\n}}\n" for line, _ in test_rule_matrix.CASES]
    for case in test_rule_matrix_files.CASES:
        texts.append(case[1] if len(case) == 3 else case[0][1])
    disagree = [t for t in texts if parse(t).ok != bash_accepts(t)]
    assert not disagree, disagree[:3]
