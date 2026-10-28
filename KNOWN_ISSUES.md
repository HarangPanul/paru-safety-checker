# Known issues / to fix later

## Not developed yet (deliberately deferred)

### A one-page summary of what the PKGBUILD is and does

The project's goal is to help the reader understand a PKGBUILD faster than reading it (see README).
Today the activity report covers what the script does (network, files outside the build tree,
install hooks, code that runs on parse, commands). Still missing:
- a structured **composition** view: sources (URL, checksum, pinned or not), dependencies, what each
  function (`prepare`/`build`/`check`/`package`) does;
- an AI-written summary that may only restate parsed facts, with a source line for every sentence, and a
  visible list of what it could not cover (parse failures, truncated files, run-time command names);
- changing the "no findings, install immediately" path: with this goal, silence is not a verdict, so the
  default may need to show the summary even when nothing is marked.

### Judging what the downloaded sources do

**Decision:** this is left to the user. `paru-safe` reports *what is downloaded* (URL, checksum,
whether a VCS source is pinned) and warns about it, and the user decides whether to trust it.
The contents of remote sources are never fetched or inspected: a `./configure`, `Makefile`,
`setup.py` or `postinstall` script inside a tarball can do anything, and the PKGBUILD review says
nothing about it.

**Later, if it can be done safely:** a separate verification tool that fetches and checks sources
without running them (verify the checksum, extract without executing anything, then review the
build scripts), or that builds inside a sandbox so that what the sources do is contained instead of
detected. It should only be built once there is a way to do it that cannot itself be attacked by the
sources it opens (hostile archives, symlinks, decompression bombs).


Things found while building the scanner that are **not fixed yet**. Each entry says what was
actually measured and what is only a guess.

## 1. Very long lines make the regex rules slow (quadratic time) — mitigated

**Measured before:** a single 60 KB line of `echo >a >a >a ...` took about **27 s** to scan. The cost came
from rules shaped like `A[^\n]*B`: for every `A` the engine retries `[^\n]*` to the end of the line.

**Now:** the file rules that had this shape (`sudoers-passwd-write`, `pacman-config-write`,
`install-system-files`, `live-system-write`, and the pipe rules) are decided on parsed commands in
`cmdrules.py`, which is linear. Their patterns remain only as a fallback for lines the parser cannot read.
Every pattern with an open-ended gap is marked `risky` and is **not run on a line longer than 2000
characters**; that line gets an `overlong-line` caution instead. The 60 KB lines of `echo >a`, `curl x |`,
`fsockopen`, `tar ~` and 60,000 spaces inside `curl x ... | sh` all scan in under a second
(`test_long_lines_are_bounded`, `test_padding_does_not_hide_a_pipe_from_the_parsed_rule`).

**Still true:** on a line over 2000 characters, a finding that only a skipped open-gap pattern could make
(for example `exfil-in-url`) is reduced to the `overlong-line` caution. The parsed-command rules and the
default-deny layer still read the whole line. When the shell does not parse (`pre.ok == False`) the
structured rules have nothing to read, so the patterns are the only rule layer left. On a line over 2000
characters they are run in overlapping 1000-character windows instead of being skipped. A match whose parts
are more than about 500 characters apart can fall between windows, so a file that is both unparseable and
padded that wide reaches the user as the `unparseable-shell` and `overlong-line` cautions, not as a danger.

## 3. The reviewed PKGBUILD and the built PKGBUILD can differ (TOCTOU)

`paru-safe` clones the AUR repo, reviews it, and then runs `paru`, which clones it again. If
the package changes in between, what was reviewed is not what is built. Closing this means
building from the reviewed checkout (for example `makepkg` in that directory, then installing
the result) instead of handing the package name back to paru.

## 4. AUR dependencies are warned about, not reviewed

Dependencies that are not in the official repositories get an `unreviewed-dependency` warning.
They are not fetched or scanned unless the user names them on the command line.

## 5. False-positive rate is unmeasured

The scanner is deliberately strict (a miss is worse than a false alarm), so nearly every
package asks for confirmation. How often each rule fires on real packages has not been
measured, because `aur.archlinux.org` is not reachable from the development sandbox. Run
`python -m paru_safety_checker.corpus collect` and `measure` on a normal machine and use the
per-rule counts to decide which rules are worth their noise.

## 6. Detection can never be complete

The regex rules and the allowlist are best effort. An allowlisted command can still do harm
through its arguments in ways nobody has listed yet (this already happened with `sed ... e`,
`find -fprint`, `tar --to-command` and `git config alias`, now covered). Treat "no findings"
as "nothing recognised", not as "proven safe".

## 7. The activity report is approximate

`activity.py` builds the report from the same shell parse as the default-deny check, so it
inherits its limits, and it adds some of its own:
- **File verbs come from a table of known tools** (`cp`, `mv`, `install`, `rm`, `sed -i`, ...).
  Anything else is reported as a read. A tool that writes through an option nobody listed is
  shown with the wrong verb, but its path is still shown.
- **Bare relative names such as `cp a b` are not listed.** They are treated as routine, which
  is only true while nothing outside the build directory is reached through them (a symlink in
  the sources, for example). Inside install hooks bare names are listed, because hooks run
  against the live system.
- **Option values are mostly ignored** (`--prefix=/usr`, `-DCMAKE_INSTALL_PREFIX=/usr`) because
  they are configuration, not file access. Only output and destination options (`-o`, `-t`,
  `--destdir`, `DESTDIR=`, ...) are reported.
- **Only PKGBUILD and `*.install` are parsed.** Helper scripts shipped in the repository are
  flagged as `unanalyzed-file` but their activity is not listed.
- **Routine operations are collapsed by default** (count only; `--safe-verbose` lists them).
  The decision of what is routine is purely by path (inside `$srcdir`/`$pkgdir`/relative).
- **Nothing is reported about what the downloaded sources do** (see issue 2).

## 8. The preprocessor and bash still disagree on rare input

`preprocess.py` reads shell the way bash does, and every PKGBUILD / `*.install` is cross-checked
against `bash --pretty-print` (which only parses, it never runs anything). Measured with random
fragments, against bash's own parse:
- 6,792 scripts that bash accepts, built from realistic fragments: 9 disagreements (0.13%).
- about 5,000 scripts built from deliberately hostile fragments (`$'`, `<(`, `$((`, stray quotes):
  21 disagreements (0.4%).
- 300 structurally valid generated scripts (the test suite): 0 disagreements.

Every disagreement is reported to the user as `parser-mismatch` (a warning), so the failure
direction is safe, but the known causes are worth fixing:
- **Here-document bodies with a backslash at the end of a line.** For an unquoted delimiter bash joins
  the lines before it looks for the terminator; the scanner compares each line separately.
- **`$'...'` strings.** bash prints them re-encoded (`\e` becomes `\E`, a newline becomes a quoted
  newline), so scripts that use them can raise a mismatch that is only a difference in spelling.
- **Constructs real PKGBUILDs almost never contain:** an array assignment inside `>(...)`, `case`
  inside `$(...)`, `function f=(...)`.

What the cross-check can and cannot see: it compares the multiset of words (`\w+` runs) with
quoting, layout and structural keywords removed. It cannot see a different *order* of the same
words, a difference made only of punctuation, or a word made only of digits (these are ignored on
purpose because bash adds fd numbers to redirections).

Other consequences of the design:
- bash 4.4 or newer must be installed; without it every file gets a `crosscheck-unavailable` warning.
- Only PKGBUILD and `*.install` are preprocessed. Other files (`.service`, helper scripts, patches)
  are scanned line by line as before.
- Newlines inside a quoted string are turned into spaces so that a command stays on one line, so the
  analyzers see those strings with different whitespace than the file has.
- The regex rules run on the one-command-per-line form **and** on the original statements with only
  the comments removed (so that patterns that span `;`, such as a fork bomb, still match). A finding
  is reported once per rule and line.
- The text of removed comments is still checked by the rules that are about the reviewer (prompt
  injection) but is never shown to the AI.

## Limits of the structured rules (found by probing them with attacker variants)

- **A heredoc body is read as code.** `cat > x <<EOF ... curl x | sh ... EOF` reports `pipe-to-shell`, and
  `sudo` inside a generated wrapper script reports `sudo`. This is deliberate (the file is written and run
  later) but also fires on documentation heredocs.
- **A command name built at run time** (`c=curl; $c x | sh`, `${SH:-sh}`) is reported only as
  `dynamic-command` (a caution); the rules need the program's name.
- **Variables are expanded only when the file assigns them once** to a literal. A name assigned twice, or
  built from `$(...)`, is left alone.
- **`curl x | sh` split by a substitution across lines** (`x=$(curl y)` on one line, `echo $x | sh` on the
  next) is seen only as `echo-to-shell`; the fetch is not linked to the later use.
- **Pipes into a group reach the group's commands only on the lines that open and close it** (a multi-line
  `( ... )` fed by a pipe is followed to its closing `)` by a text check, not by a real parse).
