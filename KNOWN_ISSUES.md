# Known issues / to fix later

## Not developed yet (deliberately deferred)

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

## 1. Very long lines make the regex rules slow (quadratic time)

**Measured:** a single 60 KB line of `echo >a >a >a ...` (20,000 repeats) takes about **27 s**
to scan. Other adversarial lines of the same size (long word, many pipes, many quotes, many
`$(`, many backticks, many heredocs, unterminated quote, 3,000 nested parens) all finished in
under 1 s. The check was interrupted before the other repeated-trigger cases were run.

**Not a bypass**, only a slowdown: the file limit is 64 KB per file, so the cost is bounded,
and a stalled scan blocks the install rather than letting it through.

**Likely cause (not confirmed with a profiler):** rules shaped like `A[^\n]*B` where `A` can
repeat many times and `B` never follows. The regex retries `[^\n]*` to the end of the line for
every `A`. The rules built from `_WRITE + [^\n]* + path` in `heuristics.py`
(`sudoers-passwd-write`, `pacman-config-write`, `install-system-files`) match this shape and
`>` is part of `_WRITE`, which fits the measurement. Many other rules have the same shape
(`pipe-to-shell`, `pipe-to-network`, `exfil-in-url`, `curl-upload`, `decode-exec`,
`reverse-shell`, `home-archive`, ...), so they are suspects too, but none were measured.

**Ideas for the fix:**
- Two-step match for "write operation, then a path": find the first write operation, then
  search for the path from that position (`pattern.search(line, pos)`). Linear, and unlike
  capping `[^\n]*` at N characters it cannot be defeated by padding.
- Alternatively scan over-long lines in overlapping windows and report the line itself as
  `overlong-line` (caution). The default-deny layer in `strict.py` is linear and still sees
  the whole line, so a payload hidden behind padding would still be reported there.
- Add a test that scans a 60 KB line per trigger word with a time budget.

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
