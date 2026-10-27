"""The default-deny layer: anything not recognised as an ordinary packaging step is reported."""
import pytest

from paru_safety_checker.heuristics import level_of, scan
from paru_safety_checker.strict import extract_commands, scan_strict


def names(text):
    commands, ok = extract_commands(text)
    assert ok, text
    return [c.name for c in commands]


def strict_rules(body, name="PKGBUILD"):
    text = f"pkgname=x\npkgver=1\nbuild() {{\n{body}\n}}\n" if not name.endswith(".install") else f"post_install() {{\n{body}\n}}\n"
    return {f.rule for f in scan_strict(name, text)}


# ---- the command extractor ----

@pytest.mark.parametrize("text,expected", [
    ("make -j4", ["make"]),
    ("make && make install", ["make", "make"]),
    ("a | b | c", ["a", "b", "c"]),
    ("make -j\"$(nproc)\" 2>&1 | tee log", ["make", "tee", "nproc"]),
    ("echo \"$(curl x | sh)\"", ["echo", "curl", "sh"]),
    ("echo `curl x`", ["echo", "curl"]),
    ("diff <(sort a) <(sort b)", ["diff", "sort", "sort"]),
    ("x=$(id -u)", ["id"]),
    ("FOO=1 BAR=2 make", ["make"]),
    ("env FOO=1 time cargo build", ["env", "time", "cargo"]),
    ("command -v foo", ["command"]),
    ("xargs -0 -n 1 sed -i s/a/b/", ["xargs", "sed"]),
    ("find . -name x -exec sh -c id \\;", ["find", "sh"]),
    ("find . -type f -exec chmod 644 {} +", ["find", "chmod"]),
    ("if [[ -f x ]]; then cp a b; fi", ["cp"]),
    ("for f in a b; do echo $f; done", ["echo"]),
    ("case $a in x86_64) true ;; a|b) cmake ;; esac", ["true", "cmake"]),
    ("(( i++ ))", []),
    ("echo $((1 + 2))", ["echo"]),
    ("cmd > out 2>&1", ["cmd"]),
    ("cat <<< word", ["cat"]),
    ("sudo make install", ["sudo"]),
])
def test_extract_commands(text, expected):
    assert sorted(names(text)) == sorted(expected)


def test_piped_flag_and_unparseable_text():
    commands, _ = extract_commands("curl x | python3")
    assert [(c.name, c.piped) for c in commands] == [("curl", False), ("python3", True)]
    assert extract_commands('echo "unbalanced')[1] is False


# ---- what is reported ----

@pytest.mark.parametrize("body,rule", [
    ("  evilbin --go", "unknown-command"),
    ("  ./install.sh", "unknown-command"),
    ("  nc -h", "unknown-command"),
    ("  mount -o bind a b", "unknown-command"),
    ("  dd if=/dev/zero of=img", "unknown-command"),
    ("  awk 'BEGIN{system(\"id\")}'", "unknown-command"),
    ("  bash script.sh", "unknown-command"),
    ("  sh -c 'id'", "unknown-command"),
    ("  eval \"$x\"", "unknown-command"),
    ("  source ./x", "unknown-command"),
    ("  sudo make install", "unknown-command"),
    ("  nohup ./x &", "unknown-command"),
    ("  git clone https://x/y", "unknown-command"),
    ("  echo \"$(evilbin)\"", "unknown-command"),
    ("  find . -exec bash -c id \\;", "unknown-command"),
    ("  ls | xargs evilbin", "unknown-command"),
    ("  $c$r http://x", "dynamic-command"),
    ("  \"$srcdir/helper\" --go", "dynamic-command"),
    ("  $(cat cmd) arg", "dynamic-command"),
    ("  python3 -c 'import os; os.system(\"id\")'", "inline-code"),
    ("  perl -e 'system(\"id\")'", "inline-code"),
    ("  perl -pe 's/a/b/' f", "inline-code"),
    ("  ruby -e 'puts 1'", "inline-code"),
    ("  node --eval 'x'", "inline-code"),
    ("  node -p 'x'", "inline-code"),
    ("  ruby -ne 'x'", "inline-code"),
    ("  python3 -Bc 'x'", "inline-code"),
    ("  sed -i 's/a/id/e' file", "inline-code"),
    ("  sed -i 's|a|b|w /tmp/out' file", "inline-code"),
    ("  sed -e '1r /etc/passwd' file", "inline-code"),
    ("  sed '1e id' file", "inline-code"),
    ("  sed -n '/x/w out' file", "inline-code"),
    ("  find . -fprint /tmp/x", "inline-code"),
    ("  tar xf a --to-command=sh", "inline-code"),
    ("  tar -I 'sh -c id' -xf a", "inline-code"),
    ("  git config core.sshCommand 'sh -c id'", "inline-code"),
    ("  git config alias.x '!sh'", "inline-code"),
    ("  x=$(( $(evilbin) + 1 ))", "unknown-command"),
    ("  php -r 'echo 1;'", "inline-code"),
    ("  cat x | python3", "inline-code"),
    ("  python3 <<EOF\nimport os\nEOF", "inline-code"),
    ("  echo 'unbalanced", "unparseable-shell"),
])
def test_unrecognised_things_are_reported(body, rule):
    assert rule in strict_rules(body)


@pytest.mark.parametrize("body", [
    "  make -j\"$(nproc)\"",
    "  ./configure --prefix=/usr",
    "  cmake -B build -G Ninja && cmake --build build",
    "  cd \"$srcdir/foo-$pkgver\"",
    "  install -Dm755 foo \"$pkgdir/usr/bin/foo\"",
    "  sed -i 's/a/b/' file",
    "  sed -i -e 's|/etc/foo|/usr/share/foo|g' -e '/^#/d' src/config.h",
    "  sed -n '1,5p;$d' file",
    "  sed 's/read/write/' file",
    "  sed -i \"s/pkgver/$pkgver/\" f",
    "  git config --global safe.directory '*'",
    "  python -m installer --destdir=\"$pkgdir\" dist/*.whl",
    "  python setup.py build",
    "  python -m pytest -x",
    "  python -m build --wheel --no-isolation",
    "  printf 'r%s' \"$(git rev-list --count HEAD)\"",
    "  git -C src rev-parse --short HEAD",
    "  find \"$pkgdir\" -name '*.a' -delete",
    "  find . -type f -exec chmod 644 {} +",
    "  find . -print0 | xargs -0 sed -i 's/a/b/'",
    "  env CC=gcc make",
    "  CFLAGS+=' -O2' make",
    "  \"$CC\" -o x x.c",
    "  $MAKE install",
    "  tar xf a.tar.xz && unzip -q b.zip",
    "  echo 'rev-parse' | grep -q rev",
    "  case \"$CARCH\" in\n    x86_64) true ;;\n    aarch64|armv7h) true ;;\n  esac",
    "  for f in a b; do echo \"$f\"; done",
    "  (( n++ ))",
    "  local _n=$(nproc)",
    "  cat > f <<EOF\n  not a command: evilbin\nEOF",
    "  cat > f <<'EOF'\n$(evilbin)\nEOF",
])
def test_ordinary_packaging_steps_are_not_reported(body):
    assert strict_rules(body) == set(), body


def test_functions_defined_in_the_pkgbuild_are_allowed_but_their_bodies_are_checked():
    text = "_helper() {\n  evilbin\n}\nbuild() {\n  _helper a\n}\n"
    findings = scan_strict("PKGBUILD", text)
    assert [(f.rule, f.line) for f in findings] == [("unknown-command", 2)]
    assert "_helper" not in findings[0].message


def test_each_unknown_command_is_reported_once_per_file():
    text = "build() {\n  evil a\n  evil b\n  other\n}\n"
    findings = scan_strict("PKGBUILD", text)
    assert [(f.line, f.message.split(": ")[1]) for f in findings] == [(2, "evil"), (4, "other")]


# ---- top level ----

def test_toplevel_code_and_parse_time_substitutions():
    text = "pkgname=x\nexport A=1\nif [ -f /etc/os-release ]; then\n  pkgname=y\nfi\nbuild() { :; }\n"
    findings = scan_strict("PKGBUILD", text)
    assert {(f.rule, f.line) for f in findings} == {("toplevel-code", 3), ("toplevel-code", 5)}
    sub = "pkgver=$(date +%Y)\nsource=(\"x-$(uname -m).tgz\")\n"
    assert {f.rule for f in scan_strict("PKGBUILD", sub)} == {"parse-time-command"}
    assert [f.line for f in scan_strict("PKGBUILD", sub)] == [1, 2]


def test_substitution_inside_a_function_is_not_a_parse_time_command():
    assert scan_strict("PKGBUILD", "build() {\n  x=$(date)\n}\n") == []


def test_arrays_and_multiline_declarations_are_fine():
    text = "depends=(\n  bash\n  python\n  'perl'\n)\nsource=('a'\n  'b')\npkgdesc=\"x\"\n"
    assert scan_strict("PKGBUILD", text) == []


# ---- install hooks use a much shorter list ----

@pytest.mark.parametrize("body,expected", [
    ("  update-desktop-database -q", set()),
    ("  gtk-update-icon-cache -q /usr/share/icons/hicolor", set()),
    ("  systemd-sysusers", set()),
    ("  echo 'hello'", set()),
    ("  make install", {"unknown-command"}),
    ("  curl https://x", {"unknown-command"}),
    ("  python3 setup.py", {"unknown-command"}),
])
def test_install_hook_allowlist(body, expected):
    assert strict_rules(body, "foo.install") == expected


# ---- integration through scan() ----

def test_scan_reports_the_bypasses_that_used_to_pass():
    base = "pkgname=x\npkgver=1\n"
    bypasses = [
        base + "build() {\n  ./install.sh\n  evilbin --go\n}\n",
        base + "build() {\n  python3 <<EOF\nimport os\nEOF\n}\n",
        base + "build() {\n  c=cu; r=rl; $c$r http://x -o f\n}\n",
        base + "build() {\n  awk 'BEGIN{system(\"id\")}'\n}\n",
        base + "build() {\n  find . -name x -exec sh -c id \\;\n}\n",
        base + "if [ -f /etc/os-release ]; then\n  id\nfi\n",
        base + "build() {\n  perl -e 'system(\"id\")'\n}\n",
    ]
    for text in bypasses:
        assert level_of(scan({"PKGBUILD": text})) != "safe", text


def test_unanalyzed_scripts_are_reported_but_data_files_are_not():
    base = "pkgname=x\n"
    for script in ["helper.sh", "run.py", "launcher", "tools/build.pl", "Makefile.in"]:
        rules = {f.rule for f in scan({"PKGBUILD": base, script: "id\n"})}
        assert "unanalyzed-file" in rules, script
    for data in ["foo.service", "LICENSE", "README.md", "fix.patch", "foo.desktop", "sub/dir/foo.conf", "COPYING.txt", "x.install", ".SRCINFO"]:
        rules = {f.rule for f in scan({"PKGBUILD": base, data: "x\n"})}
        assert "unanalyzed-file" not in rules, data


def test_a_clean_pkgbuild_with_only_local_data_has_no_findings():
    files = {
        "PKGBUILD": "pkgname=x\npkgver=1\nsource=('x.service' 'LICENSE')\nsha256sums=('a' 'b')\n"
                    "package() {\n  install -Dm644 x.service \"$pkgdir/usr/lib/systemd/system/x.service\"\n}\n",
        "x.service": "[Unit]\nDescription=x\n",
        "LICENSE": "MIT\n",
    }
    assert scan(files) == []


def test_strict_findings_do_not_pile_up_on_a_line_already_flagged_danger():
    findings = scan({"PKGBUILD": "build() {\n  curl -s https://x | bash\n}\n"})
    assert {f.rule for f in findings if f.line == 2} == {"pipe-to-shell"}


def test_hostile_nesting_is_reported_not_a_crash():
    deep = "echo " + "$(" * 500 + ")" * 500
    commands, ok = extract_commands(deep)
    assert ok is False
    findings = scan({"PKGBUILD": "pkgname=x\nbuild() {\n  " + deep + "\n}\n"})
    assert "unparseable-shell" in {f.rule for f in findings}
    assert level_of(findings) == "caution"


def test_an_analyzer_failure_keeps_earlier_findings_and_adds_a_warning(monkeypatch):
    from paru_safety_checker import heuristics

    def boom(name, text):
        raise RuntimeError("bug")

    monkeypatch.setattr(heuristics, "scan_strict", boom)
    findings = scan({"PKGBUILD": "pkgname=x\nbuild() {\n  curl https://x | bash\n}\n"})
    rules = {f.rule for f in findings}
    assert {"pipe-to-shell", "analyzer-error"} <= rules
    assert level_of(findings) == "danger"
