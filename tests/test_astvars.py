"""Arrays and variables read from the syntax tree."""
import pytest

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


# What the text-based route gave for the same files, recorded before it was removed.
EXPECTED = {'plain': {'definitions': [('source', False, ['https://e.com/$pkgname-$pkgver.tar.gz', 'b.patch', 'c'], 3, [3, 3, 3])],
           'variables': {'pkgname': 'x', 'pkgver': '1.0'},
           'stable': {'pkgname': 'x', 'pkgver': '1.0'},
           'arrays': {'source': (['https://e.com/$pkgname-$pkgver.tar.gz', 'b.patch', 'c'], 3, [3, 3, 3])},
           'd': None,
           'source': 3},
 'multi-line array': {'definitions': [('source', False, ['a', 'b $c', 'd::e'], 1, [2, 3, 4])],
                      'variables': {},
                      'stable': {},
                      'arrays': {'source': (['a', 'b $c', 'd::e'], 1, [2, 3, 4])},
                      'd': None,
                      'source': 1},
 'append': {'definitions': [('source', False, ['a'], 1, [1]), ('source', True, ['b', 'c'], 2, [2, 2])],
            'variables': {},
            'stable': {},
            'arrays': {'source': (['a', 'b', 'c'], 1, [1, 2, 2])},
            'd': None,
            'source': 1},
 'replaced': {'definitions': [('source', False, ['a'], 1, [1]), ('source', False, ['b'], 2, [2])],
              'variables': {},
              'stable': {},
              'arrays': {'source': (['b'], 2, [2])},
              'd': None,
              'source': 1},
 'two assignments': {'definitions': [],
                     'variables': {'d': '/etc', 'u': '/usr'},
                     'stable': {'u': '/usr'},
                     'arrays': {},
                     'd': 1,
                     'source': None},
 'in function': {'definitions': [],
                 'variables': {'x': '1', 'y': '$x/y'},
                 'stable': {'x': '1', 'y': '$x/y'},
                 'arrays': {},
                 'd': None,
                 'source': None},
 'one line': {'definitions': [],
              'variables': {'a': '1', 'b': '2'},
              'stable': {'a': '1', 'b': '2'},
              'arrays': {},
              'd': None,
              'source': None},
 'command value': {'definitions': [], 'variables': {'c': 'ok'}, 'stable': {'c': 'ok'}, 'arrays': {}, 'd': None, 'source': None},
 'append string': {'definitions': [], 'variables': {'a': '1'}, 'stable': {}, 'arrays': {}, 'd': None, 'source': None},
 'indexed': {'definitions': [], 'variables': {'b': 'y'}, 'stable': {'b': 'y'}, 'arrays': {}, 'd': None, 'source': None},
 'depends': {'definitions': [('depends', False, ['glibc>=2.3', 'gtk3'], 1, [1, 1]), ('makedepends', True, ['git'], 2, [2])],
             'variables': {},
             'stable': {},
             'arrays': {'depends': (['glibc>=2.3', 'gtk3'], 1, [1, 1]), 'makedepends': (['git'], 2, [2])},
             'd': None,
             'source': None},
 'if block': {'definitions': [], 'variables': {'v': '1'}, 'stable': {'v': '1'}, 'arrays': {}, 'd': None, 'source': None},
 'escaped': {'definitions': [],
             'variables': {'a': "it's", 'b': 'q"r'},
             'stable': {'a': "it's", 'b': 'q"r'},
             'arrays': {},
             'd': None,
             'source': None}}


def snapshot(text):
    p = ParsedFile("PKGBUILD", text)
    return {
        "definitions": [tuple(d) for d in p.definitions],
        "variables": dict(p.variables),
        "stable": dict(p.stable_variables),
        "arrays": {k: (v.items, v.line, v.item_lines) for k, v in p.arrays.items()},
        "d": p.assignment_line("d"),
        "source": p.assignment_line("source"),
    }


@pytest.mark.parametrize("name", CASES)
def test_same_as_the_recorded_text_route(name):
    assert snapshot(CASES[name]) == EXPECTED[name]


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


def test_an_unread_statement_is_reported_and_the_rest_is_still_read():
    p = ParsedFile("PKGBUILD", "a=1\nfi\nb=2\n")
    assert p.ast.errors and 2 in p.unparsed_lines
    assert p.variables == {"a": "1", "b": "2"}


def test_local_counts_as_another_assignment():
    """Stricter than the text route, which ignored `local d=...`: either value may apply."""
    assert ParsedFile("PKGBUILD", "f() {\n  local d=/etc\n  d=/tmp\n}\n").stable_variables == {}


def test_assignment_with_a_redirect_still_assigns():
    """The text route took `x=1 2>/dev/null` for a command; the shell does assign."""
    assert ParsedFile("PKGBUILD", "x=1 2>/dev/null\n").variables == {"x": "1"}
