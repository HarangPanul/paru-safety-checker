"""Arrays and variables read from the syntax tree, checked against the older text route."""
import pytest

from paru_analyzer import parsed
from paru_analyzer.parsed import ParsedFile

CASES = {
    "plain": "pkgname=x\npkgver=1.0\nsource=(\"https://e.com/$pkgname-$pkgver.tar.gz\" 'b.patch' c)\n",
    "multi-line array": "source=(\n  'a'\n  \"b $c\"\n  d::e\n)\n",
    "append": "source=(a)\nsource+=(b c)\n",
    "replaced": "source=(a)\nsource=(b)\n",
    "two assignments": "d=/etc\nd=$pkgdir/etc\nu=/usr\n",
    "in function": "build() {\n  x=1\n  y=\"$x/y\"\n}\n",
    "one line": "a=1 b=2\n",
    "command value": "a=$(date)\nb=`id`\nc=ok\n",
    "append string": "a=1\na+=2\n",
    "indexed": "a[1]=x\nb=y\n",
    "depends": "depends=('glibc>=2.3' \"gtk3\")\nmakedepends+=(git)\n",
    "if block": "if true; then\n  v=1\nfi\n",
    "escaped": "a='it'\\''s'\nb=\"q\\\"r\"\n",
}


def snapshot(text):
    p = ParsedFile("PKGBUILD", text)
    return (
        p.definitions,
        dict(p.variables),
        dict(p.stable_variables),
        {k: (v.items, v.line, v.item_lines) for k, v in p.arrays.items()},
        p.assignment_line("d"),
        p.assignment_line("source"),
    )


@pytest.fixture
def routes(monkeypatch):
    def both(text):
        monkeypatch.setattr(parsed, "USE_AST", True)
        new = snapshot(text)
        monkeypatch.setattr(parsed, "USE_AST", False)
        return new, snapshot(text)
    return both


@pytest.mark.parametrize("name", CASES)
def test_same_as_text_route(routes, name):
    new, old = routes(CASES[name])
    assert new == old


def test_array_items_and_lines():
    p = ParsedFile("PKGBUILD", "source=(\n  'a'\n  \"b $c\"\n  d::e\n)\n")
    (d,) = p.definitions
    assert d.items == ["a", "b $c", "d::e"]
    assert d.item_lines == [2, 3, 4]
    assert d.line == 1


def test_identical_items_keep_their_own_lines():
    p = ParsedFile("PKGBUILD", "source=(a\n  a)\n")
    assert p.definitions[0].item_lines == [1, 2]


def test_variables_are_literal_and_first_wins():
    p = ParsedFile("PKGBUILD", "a=1\na=2\nb=$(x)\nc=\"$a/y\"\n")
    assert p.variables == {"a": "1", "c": "$a/y"}


def test_stable_variables_exclude_reassigned_and_declared_twice():
    p = ParsedFile("PKGBUILD", "d=/etc\nd=/tmp\ne=1\nf() {\n  local e=2\n}\ng=3\n")
    assert p.stable_variables == {"g": "3"}


def test_assignment_in_a_pipeline_is_not_an_assignment():
    p = ParsedFile("PKGBUILD", "x=1 | tee log\ny=2\n")
    assert "x" not in p.variables
    assert p.variables == {"y": "2"}


def test_assignment_line_is_the_first_one():
    p = ParsedFile("PKGBUILD", "a=1\nsource=(x)\nsource+=(y)\n")
    assert p.assignment_line("source") == 2
    assert p.assignment_line("nothing") is None


def test_unread_statement_falls_back_to_the_text_route(monkeypatch):
    text = "a=1\nfi\nb=2\n"
    p = ParsedFile("PKGBUILD", text)
    assert p.ast.errors
    assert p._tree is None
    assert p.variables == {"a": "1", "b": "2"}


def test_a_clean_file_uses_the_tree():
    assert ParsedFile("PKGBUILD", "a=1\n")._tree is not None


def test_local_counts_as_another_assignment(routes):
    """Deliberately stricter than the text route, which ignored `local d=...`: either value may apply."""
    new, old = routes("f() {\n  local d=/etc\n  d=/tmp\n}\n")
    assert new[2] == {} and old[2] == {"d": "/tmp"}


def test_assignment_with_a_redirect_still_assigns(routes):
    """The text route took `x=1 2>/dev/null` for a command; the shell does assign."""
    new, old = routes("x=1 2>/dev/null\n")
    assert new[1] == {"x": "1"} and old[1] == {}
