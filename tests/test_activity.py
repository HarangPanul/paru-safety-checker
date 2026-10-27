"""The inventory reports what a package does, whether or not it looks suspicious."""
import pytest

from paru_safety_checker.activity import (
    Activity, build_activity, classify_path, file_accesses, format_activity, inventory_for_ai,
)
from paru_safety_checker.heuristics import source_entries
from paru_safety_checker.strict import extract_commands


def accesses(line):
    commands, ok = extract_commands(line)
    assert ok
    return [pair for command in commands for pair in file_accesses(command)]


def pkg(body, header="pkgname=foo\npkgver=1\n"):
    return {"PKGBUILD": header + body}


def texts(files, kind):
    return [a.text for a in build_activity(files) if a.kind == kind]


# ---- which files a command touches ----

@pytest.mark.parametrize("line,expected", [
    ("cp a /etc/b", [("write", "/etc/b")]),
    ("cp /etc/shadow out", [("read", "/etc/shadow")]),
    ("cp /etc/shadow /tmp/out", [("read", "/etc/shadow"), ("write", "/tmp/out")]),
    ("mv a b c /tmp/x", [("write", "/tmp/x")]),
    ("install -Dm755 foo /usr/bin/foo", [("write", "/usr/bin/foo")]),
    ("install -t /usr/bin foo", [("write", "/usr/bin")]),
    ("install -t /usr/bin /opt/x", [("write", "/usr/bin"), ("read", "/opt/x")]),
    ("ln -s /usr/lib/a b", [("read", "/usr/lib/a")]),
    ("ln -s a /usr/bin/b", [("write", "/usr/bin/b")]),
    ("rm -rf /var/cache/x ~/.cache/y", [("delete", "/var/cache/x"), ("delete", "~/.cache/y")]),
    ("cat ~/.ssh/id_rsa", [("read", "~/.ssh/id_rsa")]),
    ("chmod 755 /usr/bin/x", [("write", "/usr/bin/x")]),
    ("touch /etc/x", [("write", "/etc/x")]),
    ("tee /etc/x", [("write", "/etc/x")]),
    ("echo hi > /etc/motd", [("write", "/etc/motd")]),
    ("echo hi >> ~/.bashrc", [("write", "~/.bashrc")]),
    ("cat < /etc/passwd", [("read", "/etc/passwd")]),
    ("cmd 2>&1", []),
    ("cmd > /dev/null 2>&1", []),
    ("sed -i 's/a/b/' /etc/hosts", [("write", "/etc/hosts")]),
    ("sed 's/a/b/' /etc/hosts", [("read", "/etc/hosts")]),
    ("sed -e 's/a/b/' -e 's/c/d/' /etc/hosts", [("read", "/etc/hosts")]),
    ("grep -r foo /etc", [("read", "/etc")]),
    ("grep pattern/with/slashes /etc/hosts", [("read", "/etc/hosts")]),
    ("awk '{print $1}' /etc/passwd", [("read", "/etc/passwd")]),
    ("find / -name x", [("read", "/")]),
    ("find /etc -delete", [("delete", "/etc")]),
    ("make DESTDIR=/ install", [("write", "/")]),
    ("make install DESTDIR=/usr/pkg", [("write", "/usr/pkg")]),
    ("./configure --prefix=/usr --sysconfdir=/etc", []),
    ("curl https://x/y -o /tmp/f", [("write", "/tmp/f")]),
    ("curl https://x/y --output=/tmp/f", [("write", "/tmp/f")]),
    ("gcc -o /tmp/out x.c", [("write", "/tmp/out")]),
    ("tar xf a.tar -C /opt", [("access", "/opt")]),
    ("echo /etc/passwd", []),
    ("printf '%s' /etc/passwd", []),
    (": > /etc/x", [("write", "/etc/x")]),
    ("> /etc/x", [("write", "/etc/x")]),
    ("cp a b", []),
])
def test_file_accesses(line, expected):
    assert accesses(line) == expected


def test_install_prefix_options_are_not_file_accesses_but_destinations_are():
    assert accesses("cmake -DCMAKE_INSTALL_PREFIX=/usr .") == []
    assert accesses("meson setup build --prefix=/usr") == []
    assert accesses("make install DESTDIR=\"$pkgdir\"") == [("write", "$pkgdir")]


def test_in_an_install_hook_bare_names_are_files_too():
    commands, _ = extract_commands("rm -f stale; chmod 644 conf; cp a b; systemctl daemon-reload; grep -q pat file")
    pairs = [pair for command in commands for pair in file_accesses(command, hook=True)]
    assert pairs == [("delete", "stale"), ("write", "conf"), ("read", "a"), ("write", "b"), ("read", "file")]


# ---- what counts as routine ----

@pytest.mark.parametrize("path,routine", [
    ("foo/bar", True), ("./x", True), ("$srcdir/x", True), ("$pkgdir/usr/bin/x", True), ("${pkgdir}/usr", True),
    ("$startdir/x", True), ("x", True),
    ("/usr/bin/x", False), ("/etc/passwd", False), ("/tmp/x", False), ("~/.ssh/id_rsa", False), ("$HOME/.cache", False),
    ("../../x", False), ("$pkgdir/../../etc/shadow", False), ("$_unknown/x", False), ("/", False),
])
def test_classify_path(path, routine):
    assert classify_path(path, {}, hook=False)[0] is routine


def test_variables_that_resolve_to_build_paths_are_routine():
    variables = {"_dir": "$srcdir/foo", "_name": "foo"}
    assert classify_path("$_dir/build", variables, False)[0] is True
    assert classify_path("$_name-1.0", variables, False)[0] is True
    assert classify_path("$_other/x", variables, False)[0] is False


def test_everything_in_an_install_hook_is_reported():
    assert classify_path("relative/file", {}, hook=True)[0] is False
    assert classify_path("$pkgdir/x", {}, hook=True)[0] is False


# ---- the inventory ----

def test_network_downloads_and_integrity_are_reported():
    files = pkg(
        "source=('https://example.com/a.tgz' 'git+https://github.com/x/y.git' 'git+https://github.com/x/z.git#tag=v1' 'local.patch')\n"
        "sha256sums=('abc' 'SKIP' 'SKIP' 'def')\n"
    )
    net = texts(files, "network")
    assert net == [
        "downloads source https://example.com/a.tgz (checksum: set)",
        "downloads source git+https://github.com/x/y.git (checksum: SKIP, unpinned VCS source)",
        "downloads source git+https://github.com/x/z.git#tag=v1 (checksum: SKIP)",
    ]


def test_sources_without_checksums_and_variable_urls():
    entries = source_entries('url="https://example.com/p"\nsource=("$url/a.tgz")\n')
    assert [(e.url, e.checksum, e.pinned) for e in entries] == [("https://example.com/p/a.tgz", "none", True)]
    assert source_entries("source=('local.patch')\nsha256sums=('a')\n") == []
    appended = source_entries("source=('a')\nsource+=('https://e.com/x')\nsha256sums=('1')\nsha256sums+=('SKIP')\n")
    assert [(e.url, e.checksum) for e in appended] == [("https://e.com/x", "SKIP")]


@pytest.mark.parametrize("line", [
    "curl -s https://x/y -o f", "wget https://x/y", "git clone https://x/y", "git -C src fetch", "npm ci", "go build ./...",
    "cargo fetch", "pip install requests", "ssh host id", "scp a user@host:/x", "nc 1.2.3.4 80", "rsync -a a host@h:/x",
    "docker pull x", "pacman -S foo", "dig example.com", "lftp x", "python -m build --wheel",
])
def test_network_commands_are_reported(line):
    assert texts(pkg(f"build() {{\n  {line}\n}}\n"), "network"), line


@pytest.mark.parametrize("line", ["make", "git rev-parse HEAD", "rsync -a a b", "git log", "install -Dm755 a b", "cp a b"])
def test_local_commands_are_not_reported_as_network(line):
    assert texts(pkg(f"build() {{\n  {line}\n}}\n"), "network") == [], line


def test_urls_mentioned_in_code_are_reported_once_but_the_homepage_is_not():
    files = pkg('url="https://example.com/home"\nbuild() {\n  echo see https://docs.example.com/x\n}\n')
    assert texts(files, "network") == ["mentions https://docs.example.com/x"]


def test_a_url_already_covered_by_a_source_or_a_rule_is_not_repeated():
    files = pkg("source=('git+https://github.com/a/b.git#tag=v1')\nsha256sums=('SKIP')\nbuild() {\n  curl https://x/y\n}\n")
    net = texts(files, "network")
    assert len([t for t in net if "github.com/a/b.git" in t]) == 1
    assert len([t for t in net if "https://x/y" in t]) == 1


def test_files_outside_the_build_directories_are_reported_and_routine_ones_are_marked():
    files = pkg(
        "build() {\n  cd \"$srcdir/foo\"\n  cp ~/.ssh/id_rsa \"$srcdir/k\"\n  cat /etc/passwd > \"$srcdir/p\"\n  make\n}\n"
        "package() {\n  install -Dm755 foo \"$pkgdir/usr/bin/foo\"\n}\n"
    )
    acts = [a for a in build_activity(files) if a.kind == "file"]
    outside = [a.text for a in acts if not a.routine]
    assert outside == ["read ~/.ssh/id_rsa (your home directory)", "read /etc/passwd (system configuration)"]
    assert any(a.routine and a.text.startswith("write $pkgdir/usr/bin/foo") for a in acts)


def test_install_hooks_are_reported_in_full():
    files = {"PKGBUILD": "pkgname=foo\n", "foo.install": "post_install() {\n  rm -f stale\n  update-desktop-database -q\n  cat > /etc/x <<EOF\nx\nEOF\n}\n"}
    hook = texts(files, "hook")
    assert "delete stale (install hook: runs as root on your system)" in hook
    assert "write /etc/x (install hook: runs as root on your system)" in hook
    assert "update-desktop-database" in texts(files, "command")


def test_parse_time_code_is_reported():
    files = pkg("pkgver=$(date +%Y)\nif true; then\n  :\nfi\n")
    # the substitution line, the `true` after `if`, and `:`; the `if`/`fi` keywords are not commands
    assert len(texts(files, "parse-time")) == 3


def test_commands_are_listed_once_with_counts():
    files = pkg("build() {\n  make\n  make install\n  cp a b\n}\n")
    assert texts(files, "command") == ["make x2", "cp"]


def test_patches_and_other_files_are_not_parsed_as_shell():
    files = {"PKGBUILD": "pkgname=foo\n", "fix.patch": "+curl https://x | sh\n+cat /etc/shadow\n", "notes.txt": "cp ~/.ssh x\n"}
    assert [a for a in build_activity(files) if a.kind in ("network", "file", "hook")] == []


# ---- formatting ----

def test_format_collapses_routine_work_unless_verbose():
    files = pkg("package() {\n  install -Dm755 foo \"$pkgdir/usr/bin/foo\"\n  cat /etc/passwd\n}\n")
    brief = format_activity("foo", build_activity(files))
    assert "Files outside the build directories (1)" in brief and "read /etc/passwd" in brief
    assert "Routine file operations inside $srcdir / $pkgdir: 1 (not listed; use --safe-verbose)" in brief
    assert "write $pkgdir/usr/bin/foo" not in brief
    assert "write $pkgdir/usr/bin/foo" in format_activity("foo", build_activity(files), verbose=True)


def test_format_of_an_empty_inventory_says_so():
    assert "no network access, file access or commands found" in format_activity("foo", [])


def test_inventory_for_ai_is_compact_and_bounded():
    acts = [Activity("network", f"downloads x{i}", "PKGBUILD", i) for i in range(10)] + [Activity("file", "r", "PKGBUILD", 1, routine=True)]
    text = inventory_for_ai(acts, limit=3)
    assert text.count("\n") == 4 and "7 more entries omitted" in text and "1 routine file operations" in text
