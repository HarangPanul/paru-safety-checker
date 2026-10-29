"""The command table (format and rules: docs/COMMANDS.md, reader: commandtable.py).

An entry is a block of lines; blank lines end it. `@name` entries are templates other entries copy with `like:`.
Each entry says what the command does (`kind = target [conditions]`), which options it understands (`covers:`),
and carries examples (`ex: command => effects`) that `python -m paru_analyzer.commandtable --check` runs.
`where:` says in which scripts the command is an ordinary packaging step (default: build, i.e. the PKGBUILD).
"""

TABLE = r"""
# ---- templates ----

@build-tool
    covers: *
    read = @tree
    write = @tree
    exec = @tree
    note: Runs the project's own build files and scripts; what it reads and writes is the source and build tree, which the command line does not name.

@fetching-build-tool
    like: build-tool
    fetch = @deps
    note: A build tool that may download the project's dependencies; whether it does depends on the subcommand and its configuration, so this is the "may" case.

@interpreter
    covers: *
    read = @tree
    write = @tree
    exec = @script [?inline-code]
    exec = @stdin [?piped]
    exec = @tree [!?inline-code !?piped]
    note: Runs a script from the tree, code given on the command line, or a program piped to it.

@file-tool
    covers: *
    read = @args
    write = @args
    note: Reads the files it is given and writes the results next to them or in place; the command line does not say which of the arguments is the output.

@wrapper
    covers: *
    exec = @cmd
    note: Runs the rest of the command line; the rest is what matters.

@pure
    covers: *
    effects: none
    note: Works on its arguments and standard input only and touches no file.

@reader
    covers: *
    read = @args
    note: Reads the files named on the command line and prints.

# ---- shell builtins and messages ----

echo, printf, true, false, :, test, export, unset, local, declare, readonly, set, shift, return, exit, id
    like: pure
    where: build hook
    ex: echo hi => none
    ex: export PATH=/x => none
    note: Builtins with no effect on files (the effect on PATH and the environment is the job of the path-modification rule).

cd, pushd, popd, pwd, let, wait, continue, break
    like: pure
    where: build hook
    ex: cd src => none
    ex: pushd src => none
    note: Shell builtins that change the shell's own state (directory, counters, waiting for jobs) and touch no file.

msg, msg2, warning, error, plain, plainerr
    like: pure
    ex: msg2 hi => none
    note: makepkg's message functions.

vercmp, basename, dirname, nproc, uname, which, tput
    like: pure
    where: build hook
    ex: vercmp 1 2 => none
    ex: tput bold => none
    note: Commands that only compute or print on their arguments.

type
    like: pure
    where: build hook
    ex: type foo => none
    note: Only looks a name up.

read
    covers: *
    where: build hook
    read = @stdin
    ex: read line => read stdin
    note: Reads a line from standard input.

shopt
    covers: *
    system = shell-options [?shopt-expand-aliases]
    ex: shopt -s nullglob => none
    ex: shopt -s expand_aliases => system shell-options
    note: Shell options are harmless except expand_aliases, which makes aliases rewrite later commands.

hash
    covers: -r -l -d -t -p
    system = command-lookup [-p]
    ex: hash -r => none
    ex: hash -p /tmp/x ls => system command-lookup
    note: hash -p changes which program a name runs.

date
    covers: *
    system = clock [-s|--set]
    ex: date +%s => none
    ex: date -s tomorrow => system clock
    note: Prints the time; with -s it sets the system clock.

# ---- reading ----

cat
    like: reader
    where: build hook
    ex: cat a b => read a; read b
    note: Prints the files it is given.

grep
    covers: *
    where: build hook
    valued: -e -f -m -A -B -C --regexp --file --max-count
    read = @args[1:] [!-e !-f !--regexp !--file]
    read = @args [-e|-f|--regexp|--file]
    read = @opt(-f|--file)
    ex: grep foo f g => read f; read g
    ex: grep -e foo f => read f
    note: The first word is the pattern unless -e or -f gives it; -f also reads a pattern file.

ls, head, tail, wc, stat, du, df, diff, cmp, sha256sum, sha512sum, sha1sum, md5sum, b2sum, cksum, realpath, readlink, readelf, objdump, nm, file, strings, xzcat, zcat, bzcat, jq
    like: reader
    where: build hook
    valued: -n -c -d -B -s -j -b -m -p -x -R --lines --bytes --format --max-depth
    ex: ls -l dir => read dir
    ex: head -n 5 f => read f
    note: Prints information about the files it is given.

egrep, fgrep
    like: grep
    where: build
    ex: egrep foo f => read f
    note: grep with a fixed pattern syntax.

tr
    like: pure
    where: build hook
    ex: tr a b => none
    note: Translates standard input to standard output.

cut
    like: reader
    where: build hook
    valued: -b -c -d -f
    ex: cut -d: -f1 /etc/passwd => read /etc/passwd
    note: Prints parts of the lines of the files it is given.

sort
    covers: *
    valued: -o -k -t -S -T --output
    read = @args
    write = @opt(-o|--output)
    ex: sort -o out in => read in; write out
    note: -o writes the sorted result to a file.

uniq
    covers: *
    valued: -f -s -w
    read = @args[:1]
    write = @args[1:2]
    ex: uniq in out => read in; write out
    note: The second file operand is an output file.

tee
    covers: -a -i -p --append --ignore-interrupts
    read = @stdin
    write = @args
    ex: tee log => read stdin; write log
    note: Copies standard input into every file named.

# ---- writing ----

cp
    covers: -r -R -a -p -f -v -u -n -i -l -s -d -L -P -H -T -x --recursive --archive --preserve* --force --verbose --update --no-clobber --interactive --link --symbolic-link --dereference --no-dereference --reflink* --remove-destination
    where: build hook
    read = @args[:-1]
    write = @args[-1]
    ex: cp a b c => read a; read b; write c
    ex: cp -t dir a => read dir; unknown -t; write a
    note: The last word is the destination; -t (destination first) is not covered, so it is reported as unknown.

mv
    covers: -f -i -n -u -v -T --force --verbose --no-clobber --update --interactive
    where: build hook
    read = @args[:-1]
    delete = @args[:-1]
    write = @args[-1]
    ex: mv a b => delete a; read a; write b
    note: Moves the sources, so they are read and removed, to the last word.

install
    covers: -D -d -m -o -g -p -v -s -C -c -b -T --mode* --owner* --group* --preserve-timestamps --verbose
    valued: -m -o -g -S --mode --owner --group --suffix
    read = @args[:-1] [!-d]
    write = @args[-1] [!-d]
    write = @args [-d]
    perm = @args[-1] [-m|-o|-g|--mode|--owner|--group]
    ex: install -Dm755 a b => perm b; read a; write b
    ex: install -d x y => write x; write y
    note: Copies to the last word, or with -d only creates the directories; -m, -o and -g set the permissions there.

ln
    covers: -s -f -n -r -v -T -i -L -P --symbolic --force --no-dereference --relative --verbose
    where: build hook
    write = @args[-1]
    ex: ln -sf a b => write b
    note: Creates the link named by the last word; the target is only text.

touch
    covers: *
    valued: -d -r -t --date --reference
    where: build hook
    write = @args
    ex: touch a b => write a; write b
    note: Creates files or changes their times.

mkdir
    covers: -p -m -v --parents --mode --verbose
    valued: -m --mode
    where: build hook
    write = @args
    ex: mkdir -p a => write a
    note: Creates directories.

rmdir
    covers: -p -v --parents --verbose --ignore-fail-on-non-empty
    where: build hook
    delete = @args
    ex: rmdir a => delete a
    note: Removes empty directories.

rm
    covers: -r -R -f -i -I -v -d --recursive --force --verbose --dir --one-file-system --preserve-root
    where: build hook
    delete = @args
    ex: rm -rf a b => delete a; delete b
    ex: rm --no-preserve-root -rf / => delete /; unknown --no-preserve-root
    note: Deletes what it is given; --no-preserve-root is not covered on purpose.

chmod
    covers: -R -f -v -c --recursive --silent --quiet --verbose --changes
    where: build hook
    mode-first: yes
    perm = @args[1:]
    ex: chmod 755 a => perm a
    ex: chmod -x a => perm a
    note: The first word is the mode (it may start with "-"), the rest are files.

chown
    covers: -R -f -v -c -h -L -H -P --recursive --silent --quiet --verbose --changes
    where: build hook
    perm = @args[1:]
    ex: chown root:root a => perm a
    note: The first word is the owner, the rest are files.

chgrp
    like: chown
    where: build
    ex: chgrp wheel a => perm a
    note: The first word is the group, the rest are files.

setcap
    covers: -r -q -v -n
    where: build hook
    perm = @args[1:] [!-r !-q !-v]
    perm = @args [-r]
    ex: setcap cap_net_raw+ep f => perm f
    note: Sets file capabilities: the first word is the capability string.

patch
    covers: *
    valued: -p -i -d -F --input --strip --directory
    read = @stdin [!-i !--input]
    read = @opt(-i|--input)
    write = @tree
    ex: patch -p1 -i x.patch => read x.patch; write tree
    note: Applies a patch to files in the tree.

find
    covers: *
    single-dash-long: yes
    valued: -fprint -fprint0 -fprintf -fls -name -iname -path -ipath -regex -type -maxdepth -mindepth -newer -size -perm -user -group -mtime -atime -ctime -mmin
    read = @find-paths
    exec = @find-exec
    delete = @find-paths [-delete]
    write = @opt(-fprint|-fprint0|-fprintf|-fls) [?find-writes]
    ex: find . -name x => read .
    ex: find src -delete => delete src; read src
    ex: find . -exec chmod +x {} + => exec chmod; read .
    ex: find . -fprint out => read .; write out
    note: Searches the directories before the expression; -exec runs a command, -delete removes, -fprint writes a file.

xargs
    like: wrapper
    valued: -n -I -P -L -d -E -s -a
    ex: xargs -0 rm => exec rm
    note: Runs the command it is given with arguments read from standard input.

sed
    covers: *
    valued: -e -f --expression --file
    read = @args[1:] [!-e !-f !--expression !--file]
    read = @args [-e|-f|--expression|--file]
    write = @args[1:] [-i|--in-place*]
    exec = @script [?sed-active]
    exec = @opt(-f|--file)
    ex: sed -i s/a/b/ f => read f; write f
    ex: sed -e s/a/b/ f => read f
    ex: sed s/a/b/e f => exec s/a/b/e; read f
    note: -i edits in place; the e, w and r commands of the script run programs or touch other files, which a predicate looks for.

awk, gawk, mawk
    covers: *
    valued: -F -v -f --file
    read = @args[1:] [!-f !--file]
    read = @args [-f|--file]
    exec = @script [?awk-active]
    exec = @opt(-f|--file)
    read = @opt(-f|--file)
    ex: awk '{print $1}' f => read f
    ex: awk 'BEGIN{system("x")}' => exec BEGIN{system("x")}
    note: A program that calls system, getline from a pipe or prints to a pipe runs commands; a program read from a file cannot be seen.

# ---- archives and compression ----

tar, bsdtar
    covers: *
    bundled-first: yes
    valued: -f -C -T -X -I --file --directory --files-from --exclude --exclude-from --to-command --checkpoint-action --use-compress-program --rsh-command --info-script --new-volume-script
    read = @opt(-f|--file) [-x|-t|--extract|--get|--list]
    write = @opt(-f|--file) [-c|-r|-u|--create|--append|--update]
    read = @args [-c|-r|-u|--create|--append|--update]
    write = @opt(-C|--directory)
    write = @tree [-x|--extract|--get]
    exec = @none [?tar-exec]
    ex: tar -xzf a.tgz -C out => read a.tgz; write out; write tree
    ex: tar xf a.tar => read a.tar; write tree
    ex: tar -cf a.tar dir => read dir; write a.tar
    ex: tar --to-command=sh -xf a => exec; read a; write tree
    note: Extracting writes into the tree (or -C); the options that run a program are found by a predicate.

unzip
    covers: *
    valued: -d -x -P
    read = @args[:1]
    write = @opt(-d)
    write = @tree [!-l !-p !-t]
    ex: unzip -d out a.zip => read a.zip; write out; write tree
    note: Extracts into the tree, or into -d.

zip
    covers: *
    valued: -x -b -n
    write = @args[:1]
    read = @args[1:]
    ex: zip a.zip x y => read x; read y; write a.zip
    note: The first word is the archive that is written.

gzip, gunzip, bzip2, bunzip2, xz, unxz, zstd
    covers: *
    valued: -T -o -S --output --threads
    read = @args
    write = @args [!-c !--stdout !-t !--test !-l !--list]
    write = @opt(-o|--output)
    ex: gzip -9 a => read a; write a
    ex: gzip -c a => read a
    note: Compresses or decompresses the named files in place unless writing to standard output.

7z, 7za
    covers: *
    read = @args[1:]
    write = @tree [sub:x|e]
    write = @args[1:2] [sub:a|u]
    ex: 7z x a.7z => read a.7z; write tree
    ex: 7z a out.7z dir => read out.7z; read dir; write out.7z
    note: The first word is the 7-Zip command; x and e extract into the tree, a and u write the archive named next.

cpio
    covers: *
    valued: -O -F -D --file
    read = @stdin
    write = @tree [-i|--extract]
    write = @opt(-O|-F|--file)
    ex: cpio -idm => read stdin; write tree
    note: Extracts from standard input into the tree, or writes the archive named by -O.

ar
    covers: *
    bundled-first: yes
    write = @args[:1] [!-x !-t !-p]
    read = @args[1:]
    write = @tree [-x]
    ex: ar rcs lib.a a.o => read a.o; write lib.a
    note: The first word after the operation is the archive.

strip, objcopy
    like: file-tool
    valued: -o -R -j -K -N --output-target
    ex: strip a => read a; write a
    note: Rewrites binaries in place, or into the second file for objcopy.

mktemp
    covers: *
    where: build hook
    valued: -p --tmpdir
    write = @args
    ex: mktemp /tmp/x.XXXX => write /tmp/x.XXXX
    note: Creates a temporary file or directory.

gendesk, desktop-file-edit, asar
    like: file-tool
    ex: gendesk a => read a; write a
    note: Generate or edit a desktop entry, or pack an archive, in the files they are given.

# ---- network ----

curl, wget
    covers: *
    where: build hook
    valued: -o -O -T -d -F -H -X -u -A -e -x --output --output-document --upload-file --data --form --header --request --user
    fetch = @url
    write = @opt(-o|--output|-O|--output-document)
    upload = @url [-T|--upload-file|-d|--data|--data-binary|--data-raw|-F|--form|--post-data|--post-file]
    ex: curl -o out https://x/y => fetch https://x/y; write out
    ex: curl -T f https://x/y => fetch https://x/y; upload https://x/y
    note: Downloads from a URL; with an upload or data option it also sends something.

rsync
    covers: *
    where: build hook
    valued: -e --rsh --rsync-path --exclude --include --filter
    read = @args
    write = @args
    fetch = @none [?remote-argument]
    upload = @none [?remote-argument]
    exec = @none [-e|--rsh|--rsync-path]
    ex: rsync -a a b => read a; read b; write a; write b
    ex: rsync -a host:a b => fetch; read b; read host:a; upload; write b; write host:a
    note: Copies files; a remote operand (host:path, rsync://) reaches the network, and -e or --rsync-path names a program to run.

# ---- integrity and signatures ----

gpg
    covers: *
    valued: --keyserver --recv-keys --receive-keys --search-keys --fetch-keys --locate-keys --send-keys --output -o --homedir
    read = @args
    write = @opt(-o|--output)
    fetch = @none [--recv-keys|--receive-keys|--search-keys|--refresh-keys|--fetch-keys|--locate-keys|--auto-key-locate|--keyserver]
    upload = @none [--send-keys]
    ex: gpg --verify a.sig a => read a; read a.sig
    ex: gpg --recv-keys ABCD => fetch
    note: Key server options reach the network.

gpgv
    like: reader
    valued: --keyring
    ex: gpgv --keyring k a.sig a => read a; read a.sig
    note: Verifies signatures offline.

# ---- build tools ----

make, gmake, cmake, ctest, cpack, ninja, meson, arch-meson, ./configure, configure, ./autogen.sh, ./bootstrap, ./bootstrap.sh, ./buildconf, ./waf, ./b2, ./bjam, autoreconf, autoconf, automake, autoheader, libtoolize, aclocal, gettextize, intltoolize, glib-gettextize, scons, qmake, qmake6, qmake-qt5, xmkmf, pkg-config, pkgconf, gcc, g++, cc, c++, clang, clang++, cpp, ld, ranlib, as, rustc, gofmt, ghc, ocaml, dune, ocamlfind, elixir, erl, nim, dmd, ldc2, valac, vala, java, javac
    like: build-tool
    ex: make -j4 => exec tree; read tree; write tree
    note: Compilers, build systems and project scripts: they execute the project's own files.

cargo, go, pip, pip3, poetry, pdm, uv, npm, pnpm, yarn, gem, bundle, composer, mvn, gradle, ant, sbt, dotnet, dart, flutter, cabal, stack, opam, mix, rebar3, luarocks, nimble, shards, dub, swift, zig, crystal
    like: fetching-build-tool
    ex: cargo build => exec tree; fetch deps; read tree; write tree
    note: Package managers and build tools that may download dependencies.

python, python2, python3, pypy, pypy3, node, ruby, perl, php, lua, luajit
    like: interpreter
    ex: python setup.py build => exec tree; read tree; write tree
    ex: python -c 'print(1)' => exec print(1); read tree; write tree
    ex: | python => exec stdin; read tree; write tree
    note: Interpreters; where the program comes from decides the target.

flex, bison, yacc, lex, m4, nasm, yasm, msgfmt, msgmerge, xgettext, glib-compile-resources, desktop-file-validate, desktop-file-install, appstreamcli, mkfontscale, mkfontdir, rsvg-convert, convert, magick, sphinx-build, doxygen, asciidoctor, help2man, sass, protoc, patchelf, chrpath, install-info, makeinfo, texi2any
    like: file-tool
    ex: msgfmt a.po => read a.po; write a.po
    note: Generators and converters that read the files given and write results next to them.

glib-compile-schemas, fc-cache, gtk-update-icon-cache, update-desktop-database, xdg-icon-resource
    like: file-tool
    where: build hook
    ex: fc-cache -f dir => read dir; write dir
    note: Rebuild a cache in the directory they are given; on the live system the path says where.

# ---- wrappers ----

time, nice, timeout, stdbuf, ionice, fakeroot, builtin
    like: wrapper
    valued: -n -c -p -s -k -i -o -e
    ex: nice -n 10 make => exec make
    ex: timeout 5 sleep => exec sleep
    note: Run the rest of the command line.

env
    like: wrapper
    valued: -u -C -S
    ex: env X=1 make => exec make
    note: Runs the rest of the command line with changed variables.

command
    covers: *
    where: build hook
    exec = @cmd [!-v !-V]
    ex: command -v foo => none
    ex: command foo => exec foo
    note: `command -v` only looks a name up; otherwise it runs the command and skips functions.

# ---- version control and packages ----

git
    covers: *
    where: build hook
    valued: -C -c --git-dir --work-tree --namespace
    subs: rev-parse rev-list describe log show status config apply init add diff ls-files cat-file symbolic-ref branch tag archive checkout reset am format-patch cherry-pick version
    read = @tree
    write = @tree
    exec = @none [?git-config-exec]
    ex: git log => read tree; write tree
    ex: git clone https://x => read tree; unknown subcommand clone; write tree
    ex: git -c core.sshCommand=x log => exec; read tree; write tree
    note: Only the subcommands listed are local packaging steps; configuration that names a program makes git run it.

pacman
    covers: *
    where: build hook
    system = packages [?pacman-write]
    ex: pacman -Q foo => none
    ex: pacman -S foo => system packages
    note: Queries are read-only; every other operation installs or removes packages.

# ---- only in install hooks (they run as root on the live system) ----

getent
    like: reader
    where: hook
    ex: getent passwd foo => read passwd; read foo
    note: Looks up a name in the system databases.

aa-enabled
    like: pure
    where: hook
    ex: aa-enabled => none
    note: Reports whether AppArmor is enabled.

ldconfig
    covers: *
    where: hook
    system = linker-cache
    ex: ldconfig => system linker-cache
    note: Rebuilds the system linker cache.

depmod
    covers: *
    where: hook
    system = modules
    ex: depmod -a => system modules
    note: Rebuilds the kernel module dependency list.

systemd-sysusers
    covers: *
    where: hook
    system = users
    ex: systemd-sysusers => system users
    note: Creates the system users that sysusers.d files declare.

systemd-tmpfiles
    covers: *
    where: hook
    system = files
    ex: systemd-tmpfiles --create => system files
    note: Creates files and directories that tmpfiles.d files declare.

systemctl
    covers: *
    where: hook
    system = services [!sub:status|is-active|is-enabled|is-failed|show|cat|list-units|list-unit-files]
    ex: systemctl enable foo => system services
    ex: systemctl status foo => none
    note: Enables, starts, stops or reloads services; the queries do none of that.

udevadm
    covers: *
    where: hook
    system = devices [sub:control|trigger|settle]
    ex: udevadm control --reload => system devices
    ex: udevadm info /dev/x => none
    note: Reloads rules and triggers events; info and test only read.

useradd, groupadd, userdel, groupdel, usermod, groupmod, gpasswd
    covers: *
    where: hook
    system = users
    ex: groupadd foo => system users
    note: Creates or changes system users and groups; the user-management rule also reports it.

modprobe, rmmod, insmod
    covers: *
    where: hook
    system = modules
    ex: modprobe foo => system modules
    note: Loads or unloads kernel modules; the kernel-module rule also reports it.

apparmor_parser
    covers: *
    where: hook
    system = apparmor
    ex: apparmor_parser -r p => system apparmor
    note: Loads an AppArmor profile into the running kernel.

update-mime-database, gtk4-update-icon-cache, xdg-desktop-menu, xdg-mime, gio, gdk-pixbuf-query-loaders
    like: file-tool
    where: hook
    ex: update-mime-database /usr/share/mime => read /usr/share/mime; write /usr/share/mime
    note: Update desktop or loader caches in the directory they are given.
"""
