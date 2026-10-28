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

## Other recorded items
- Move the remaining old-route readers to the syntax tree (arrays and variables are done; they fall back to the
  text route when the tree has an unread statement): regex input lines (`units`), `strict.py`, the `activity.py` step list; then remove
  `Group`/`feeding`/`_split_operators` and `parsed.USE_AST`.
- Validate the parser and adapter on the real 500-package corpus (parse failure rate, agreement with `bash -n`,
  old/new route differences).
- Split facts from marks in the level computation (external-source, prebuilt-source, symlink, binary-in-repo,
  unanalyzed-file, unpinned-vcs as facts).
- Minimal IR implementation: unified gaps, steps/effects, a coverage-invariant test; add notes on one step
  becoming several ops and on op dataflow to `docs/IR.md`.
- Idea: per-function natural-language summaries from the AI, shown next to the original body, never in place
  of it (the rules keep running on the original; check the summary against the static facts; treat the body
  as untrusted input).
