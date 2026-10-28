# Planned work (recorded only, not implemented)

## Access-location analysis (idea, not started)

Goal: tell the reader which locations (URLs, directories) a script can reach when it runs, and
which it provably cannot. Complete knowledge is impossible statically (`eval`, build tools,
downloaded code, environment state), so the result is split into regions and never reported as a
verdict.

| Region | Meaning |
|---|---|
| confirmed access | locations that appear concretely in the code (`source=` URLs, `curl`/`git clone` arguments, `install`/`cp`/`rm` paths; variables resolved by constant propagation) |
| possible access | what a tool can reach by its behaviour (`make`/`cmake`/`cargo`/`go build`: network and writes outside the build dir; `npm`/`pip`/`go mod`/`cargo fetch`: any registry host) |
| unknown | cannot be bounded statically (`eval`, dynamic command names, running downloaded scripts); recorded as a gap with a reason and a line number |
| confirmed non-access | only for a **closed** step: every command is a known one with a known reach and every argument resolved; then anything outside the sets above is not reached (e.g. "package() writes only under $pkgdir and uses no network") |

Rules to keep:
- A step is closed only if all its commands are known and all arguments are resolved. One unknown
  command opens the step, and an open step has no non-access claim. Enforce this in code.
- Track reads and writes separately (a closed write set can sit beside an open read set).
- Track state passed between steps (a file or link written earlier and run later opens a later step;
  `fetched-xargs-exec` is an early form of this).
- The tool models must be right: symlink following of `cp -r`/`install`, glob expansion, `$HOME`/`$PWD`.
  A wrong model makes a non-access claim false.
- Assumptions to state in the output: makepkg runs unsandboxed with the user's rights; `$srcdir`,
  `$pkgdir` and `$startdir` are where makepkg puts them.

Suggested first steps:
1. Give the entries `activity.py` already collects (downloads, writes, deletes) a region label
   (confirmed / possible / unknown).
2. Compute per-step "closed or open" from the default-deny classification in `strict.py`.
3. Only for closed steps, emit the non-access list; map everything onto `effects` and `gaps` in `docs/IR.md`.

## Prediction before install, observed access after install (decided, not started)

Decision: before installing, static analysis (plus the AI) tells the user what the package is *expected* to
access (the regions above). After installing, the tool reports what the install *actually* accessed
(files, URLs, programs run) and compares it with the prediction. The prediction informs the install
decision; the observation is an after-the-fact report, not a defence.

Consequences to keep in mind:
- The observation arrives after the code ran. It cannot stop anything and must never be worded as
  "verified safe". Install is still always asked for first, on the prediction alone.
- It covers what the static analysis cannot see: subshells, other programs (`make`, `npm`, downloaded
  binaries), `eval`, anything built at run time. A path that did not run this time is unknown, not
  "not accessed"; "observed" and "predicted non-access" are different guarantees.
- The record must live outside the observed process (a parent process or a separate log), because
  the installed code can delete or alter a log it can reach. `.install` hooks run as root, which needs
  separate handling.
- A script that detects tracing can behave differently, so a clean record proves little.

How to observe (candidates): `strace -f -e trace=file,network,execve` around makepkg / paru and the
pacman install; namespaces or `bwrap` when blocking is wanted; a proxy or firewall log for URLs
(HTTPS shows only the host).

Report layout (after install):
| Section | Meaning |
|---|---|
| as predicted | in the prediction and observed |
| not predicted | observed but the prediction did not cover it: the most important section, shown first |
| not observed | predicted but did not happen this time (says nothing about other runs) |

Open questions: where to run the observation (the user's own build vs a separate isolated build before
install, which would make it a pre-install defence at the cost of build time and dependencies); how to
record root-run hooks; how the AI should use the "not predicted" list to improve its next prediction.

## Other recorded items
- Run the cross-check against bash (`crosscheck.py`) on the syntax tree instead of the lexer's lines, and let the
  pattern rules read units made from the tree (they still read `preprocess.py`'s lines, a lexical view).
  Statements the grammar cannot read hide their assignments from `definitions`/`variables`; consider reading
  arrays out of those lines with a small fallback.
- Validate the parser and adapter on the real 500-package corpus (parse failure rate, agreement with `bash -n`,
  old/new route differences).
- Split facts from marks in the level computation (external-source, prebuilt-source, symlink, binary-in-repo,
  unanalyzed-file, unpinned-vcs as facts).
- Minimal IR implementation: unified gaps, steps/effects, a coverage-invariant test; add notes on one step
  becoming several ops and on op dataflow to `docs/IR.md`.
- Idea: per-function natural-language summaries from the AI, shown next to the original body, never in place
  of it (the rules keep running on the original; check the summary against the static facts; treat the body
  as untrusted input).
