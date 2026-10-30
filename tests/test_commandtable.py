import pytest

from paru_analyzer import commandtable as ct

# the allowlists that strict.py had before it read the table, kept so the table cannot lose a command unnoticed
OLD_BUILD_ALLOWED = frozenset("""
./autogen.sh ./b2 ./bjam ./bootstrap ./bootstrap.sh ./buildconf ./configure ./waf 7z 7za : aclocal ant
appstreamcli ar arch-meson as asciidoctor autoconf autoheader automake autoreconf awk b2sum basename bison
break bsdtar builtin bundle bunzip2 bzip2 c++ cabal cargo cat cc cd chgrp chmod chown chrpath cksum clang
clang++ cmake cmp command composer configure continue convert cp cpack cpio cpp crystal ctest cut dart date
declare desktop-file-install desktop-file-validate df diff dirname dmd dotnet doxygen du dub dune echo egrep
elixir env erl error exit export fakeroot false fc-cache fgrep find flex flutter g++ gawk gcc gem gettextize
ghc glib-compile-resources glib-compile-schemas glib-gettextize gmake go gofmt gpg gpgv gradle grep
gtk-update-icon-cache gunzip gzip hash head help2man id install install-info intltoolize ionice java javac ld
ldc2 let lex libtoolize ln local ls lua luajit luarocks m4 magick make makeinfo mawk md5sum meson mix mkdir
mkfontdir mkfontscale msg msg2 msgfmt msgmerge mv mvn nasm nice nim nimble ninja nm node npm nproc objcopy
objdump ocaml ocamlfind opam patch patchelf pdm perl php pip pip3 pkg-config pkgconf plain plainerr pnpm
poetry popd printf protoc pushd pwd pypy pypy3 python qmake qmake-qt5 qmake6 ranlib read readelf readlink
readonly realpath rebar3 return rm rmdir rsvg-convert ruby rustc sass sbt scons sed set setcap sha1sum
sha256sum sha512sum shards shift shopt sort sphinx-build stack stat stdbuf strip swift tail tar tee test
texi2any time timeout touch tr true type uname uniq unset unxz unzip update-desktop-database uv vala valac
vercmp wait warning wc which xargs xdg-icon-resource xgettext xmkmf xz yacc yarn yasm zig zip zstd
""".split())

OLD_HOOK_ALLOWED = frozenset("""
: aa-enabled cat chmod chown command cp declare depmod echo exit export false fc-cache
gdk-pixbuf-query-loaders getent gio glib-compile-schemas grep gtk-update-icon-cache gtk4-update-icon-cache id
ldconfig ln local mkdir mv printf read readonly return rm rmdir set setcap shift systemctl systemd-sysusers
systemd-tmpfiles test touch true type udevadm unset update-desktop-database update-mime-database
xdg-desktop-menu xdg-icon-resource xdg-mime
""".split())

# in the table but not in the old allowlists: git and pacman were special cases in the code, python2/3 stood for a pattern
BUILD_ONLY_IN_TABLE = {"git", "pacman", "python2", "python3"} | set(
    "asar bzcat curl desktop-file-edit file gendesk jq mktemp rsync strings tput wget xzcat zcat".split()) | set("""
alias arch base64 bc chattr column comm diff3 expand expr factor fmt fold free getconf getfacl getopts groups
hexdump join less locale logname lsattr lsb_release lsblk lscpu lsmod lspci lsusb lz4 lz4cat lzcat lzma mkfifo
more nl numfmt od paste pgrep pidof printenv ps rev sdiff seq sha224sum sha384sum shasum shred sleep split sum
sync tac truncate tsort tty ulimit umask unalias unexpand unlink unlzma unzstd uptime whoami yes zstdcat
""".split())
HOOK_ONLY_IN_TABLE = {"git", "pacman"} | set("""
cd pushd popd pwd let wait continue break apparmor_parser b2sum basename bzcat cksum cmp curl cut df diff dirname du file gpasswd groupadd groupdel groupmod head insmod jq ls
md5sum mktemp modprobe nm nproc objdump readelf readlink realpath rmmod rsync sha1sum sha256sum sha512sum stat strings tail tput tr
uname useradd userdel usermod vercmp wc which wget xzcat zcat
""".split()) | set("""
alias arch awk base64 bc chattr chgrp column comm date diff3 egrep env expand expr factor fgrep find fmt fold
free gawk getconf getfacl getopts groups grub-install grub-mkconfig hexdump install install-info ionice join
kill killall less locale locale-gen logname lsattr lsb_release lsblk lscpu lsmod lspci lsusb lz4cat lzcat mawk
mkfifo mkfontdir mkfontscale mkinitcpio more nice nl numfmt od paste pgrep pidof pkill printenv ps rev sdiff
sed seq sha224sum sha384sum shasum shred sleep sort split stdbuf sum sync sysctl systemd-hwdb tac tee time
timeout truncate tsort tty ulimit umask unalias unexpand uniq unlink update-ca-certificates update-ca-trust
uptime whoami xargs yes zstdcat
""".split())


def effects(name, *args, piped=False):
    return sorted(str(e) for e in ct.load().effects_of(name, list(args), piped) or [])


def table(text):
    return ct.Table(ct.parse(text))


# ---- the shipped table ----

def test_the_shipped_table_has_no_problems_and_every_example_holds():
    assert ct.check() == []


def test_the_table_covers_every_allowlisted_command():
    t = ct.load()
    assert OLD_BUILD_ALLOWED <= t.names("build") and OLD_HOOK_ALLOWED <= t.names("hook")
    assert t.names("build") - OLD_BUILD_ALLOWED == BUILD_ONLY_IN_TABLE
    assert t.names("hook") - OLD_HOOK_ALLOWED == HOOK_ONLY_IN_TABLE


def test_every_entry_has_a_note_an_example_and_a_covers_line():
    for entry in ct.load().entries:
        assert entry.note, entry.names
        if not entry.template:
            assert entry.examples and entry.covers is not None, entry.names


def test_a_command_that_is_not_in_the_table_has_no_effects_at_all():
    assert ct.load().effects_of("nonesuch", ["x"]) is None
    assert not ct.load().known("nonesuch") and ct.load().known("cp")


# ---- arguments decide the effect ----

def test_in_place_sed_writes_and_plain_sed_only_reads():
    assert effects("sed", "-i", "s/a/b/", "f") == ["read f", "write f"]
    assert effects("sed", "s/a/b/", "f") == ["read f"]
    assert effects("sed", "-e", "s/a/b/", "-e", "s/c/d/", "f") == ["read f"]


def test_a_sed_script_that_runs_commands_is_exec():
    assert "exec s/a/b/e" in effects("sed", "s/a/b/e", "f")
    assert "exec" not in " ".join(effects("sed", "s/a/b/", "f"))


def test_command_v_only_looks_a_name_up():
    assert effects("command", "-v", "curl") == []
    assert effects("command", "curl", "x") == ["exec curl"]


def test_the_mode_of_chmod_may_start_with_a_dash():
    assert effects("chmod", "-x", "a") == ["perm a"]
    assert effects("chmod", "755", "a", "b") == ["perm a", "perm b"]


def test_old_style_tar_and_ar_letters_work_without_a_dash():
    assert effects("tar", "xf", "a.tar") == ["read a.tar", "write tree"]
    assert effects("ar", "rcs", "lib.a", "a.o") == ["read a.o", "write lib.a"]


def test_find_reads_its_paths_and_an_exec_or_delete_is_named():
    assert effects("find", ".", "-name", "x") == ["read ."]
    assert effects("find", "src", "-delete") == ["delete src", "read src"]
    assert "exec rm" in effects("find", ".", "-exec", "rm", "{}", "+")
    assert "write out" in effects("find", ".", "-fprint", "out")


def test_subcommands_the_entry_does_not_list_are_unknown():
    assert effects("git", "log") == ["read tree", "write tree"]
    assert "unknown subcommand clone" in effects("git", "clone", "https://x")
    assert "unknown subcommand" in effects("git")
    assert "exec" in effects("git", "-c", "core.sshCommand=x", "log")


def test_an_option_the_entry_does_not_cover_is_unknown_not_ignored():
    assert effects("cp", "a", "b") == ["read a", "write b"]
    assert "unknown -t" in effects("cp", "-t", "d", "a")
    assert "unknown --no-preserve-root" in effects("rm", "--no-preserve-root", "-rf", "/")


def test_interpreters_depend_on_where_the_program_comes_from():
    assert "exec tree" in effects("python", "setup.py")
    assert any(e.startswith("exec print") for e in effects("python", "-c", "print(1)"))
    assert "exec stdin" in effects("python", piped=True)


def test_system_effects_depend_on_the_arguments():
    assert effects("pacman", "-Q", "foo") == []
    assert effects("pacman", "-S", "foo") == ["system packages"]
    assert effects("hash", "-r") == []
    assert effects("hash", "-p", "/tmp/x", "ls") == ["system command-lookup"]
    assert effects("date", "+%s") == [] and effects("date", "-s", "x") == ["system clock"]
    assert effects("shopt", "-s", "expand_aliases") == ["system shell-options"]
    assert effects("shopt", "-s", "nullglob") == []


def test_hook_only_commands_are_not_ordinary_in_a_pkgbuild():
    t = ct.load()
    assert t.known("systemctl", "hook") and not t.known("systemctl", "build")
    assert t.known("cp", "build") and t.known("cp", "hook")
    assert effects("systemctl", "enable", "x") == ["system services"]
    assert effects("systemctl", "status", "x") == []


def test_wrappers_run_the_rest_of_the_line():
    assert effects("env", "X=1", "make") == ["exec make"]
    assert effects("nice", "-n", "10", "make") == ["exec make"]
    assert effects("xargs", "-0", "rm") == ["exec rm"]


# ---- the format and its checks ----

GOOD = """
cat
    covers: *
    read = @args
    ex: cat a => read a
    note: reads
"""


def test_a_minimal_entry_checks_clean():
    assert ct.check(table(GOOD)) == []


@pytest.mark.parametrize("text,fragment", [
    (GOOD.replace("    covers: *\n", ""), "no 'covers:'"),
    (GOOD.replace("    note: reads\n", ""), "no note"),
    (GOOD.replace("    ex: cat a => read a\n", ""), "no example"),
    (GOOD.replace("read a\n    note", "read b\n    note"), "gives read a"),
    (GOOD.replace("    read = @args\n", ""), "no effects"),
    (GOOD + "\ncat\n    covers: *\n    read = @args\n    ex: cat a => read a\n    note: again\n", "defined twice"),
    (GOOD.replace("cat\n", "cat\n    like: nothing\n", 1), "not an entry"),
    (GOOD.replace("ex: cat a", "ex: dog a"), "does not start with"),
    (GOOD.replace("    covers: *\n", "    covers: *\n    where: kitchen\n"), "unknown context"),
])
def test_the_check_names_what_is_wrong(text, fragment):
    assert any(fragment in problem for problem in ct.check(table(text)))


@pytest.mark.parametrize("text,fragment", [
    ("cat\n    cover: *\n", "unknown field"),
    ("cat\n    read = @nowhere\n", "cannot read"),
    ("cat\n    system = @args\n", "takes a word"),
    ("cat\n    read = @url\n", "cannot take"),
    ("cat\n    read = @args [?magic]\n", "unknown predicate"),
    ("cat\n    read = @opt()\n", "needs option names"),
    ("    read = @args\n", "outside an entry"),
    ("cat\n    ex: cat a\n", "command => effects"),
    ("cat\n    effects: some\n", "only says"),
])
def test_unreadable_lines_are_refused_with_a_line_number(text, fragment):
    with pytest.raises(ct.TableError) as error:
        ct.parse(text)
    assert fragment in str(error.value) and "line" in str(error.value)


def test_like_copies_the_effects_and_the_options_it_understands():
    t = table("@base\n    covers: -a\n    read = @args\n    note: n\n\nfoo\n    like: base\n    ex: foo -a x => read x\n    note: n\n")
    assert [str(e) for e in t.effects_of("foo", ["-a", "x"])] == ["read x"]
    assert [str(e) for e in t.effects_of("foo", ["-b", "x"])] == ["unknown -b", "read x"]


def test_short_options_in_a_cluster_and_values_attached_or_separate():
    parsed = ct.split_args(["-xzf", "a.tgz", "-Cout", "--file=b", "x"], {"-f", "-C", "--file"})
    assert parsed.flags == {"-x", "-z", "-f", "-C", "--file"}
    assert parsed.options == {"-f": ["a.tgz"], "-C": ["out"], "--file": ["b"]}
    assert parsed.positional == ["x"]
    assert ct.split_args(["-a", "--", "-b"], set()).positional == ["-b"]


def test_the_command_line_tool(capsys):
    assert ct.main(["--check"]) == 0
    assert "0 problem(s)" in capsys.readouterr().out
    assert ct.main(["--show", "sed"]) == 0 and "exec = @script [?sed-active]" in capsys.readouterr().out
    assert ct.main(["--show", "nonesuch"]) == 1
