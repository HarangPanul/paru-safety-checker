# Known issues / to fix later

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

## 2. The contents of remote sources are never reviewed

`source=(...)` URLs, VCS clones, and anything a build tool downloads (`npm`, `cargo`, `pip`,
`go`, ...) are only **warned about**, never fetched or inspected. A `./configure`, `Makefile`,
`setup.py` or `postinstall` script inside a tarball can do anything, and the allowlist in
`strict.py` only judges the PKGBUILD's own commands. This is the largest remaining gap.

Options: download and verify sources, then scan their build scripts; or build inside a sandbox
so that what the sources do is contained instead of detected.

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
