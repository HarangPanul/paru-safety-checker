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

## Pause before network access during install (idea, not decided, not started)

Idea: while the package builds or installs, stop just before it fetches from or sends to the internet and ask
the user. Unlike observation (above), this can block, so it is a defence and not only a report.

Three stages together:
1. before install: static analysis and the AI show the predicted access;
2. during install: run inside a sandbox; a connection the prediction does not cover is paused and put to the
   user before it happens; file writes and sensitive reads are handled by policy, not by asking;
3. after install: report the difference between prediction and observation.

Ways to pause (candidates):
| Way | Note |
|---|---|
| network namespace (`bwrap --unshare-net`) with only a proxy attached | cannot be bypassed by ignoring `http_proxy`; HTTPS shows the host (SNI) only |
| seccomp user notification on `connect()` | stops exactly before the call; more work to build |
| plain proxy through environment variables | bypassed by direct sockets and `--noproxy`; not a defence |
| `strace` | observes only, cannot stop; not a defence |

Problems to design around:
- Asking for every connection teaches the user to click "allow". A normal build fetches sources, runs `git clone`,
  `npm install`, `cargo fetch`: dozens to hundreds of connections.
- Direction (upload or download) is not known at connect time; only the destination is. Asking per connection,
  not per request.
- It cannot stop an upload to a host the user allowed (a secret pushed to an allowed code host), nor data
  carried in DNS names.
- The build waits for the answer; long unattended builds need a no-prompt policy.
- Root-run `.install` hooks need separate handling. Sandbox escape and kernel bugs are out of scope.

Keeping the questions few:
- Destinations the static analysis predicted (`source=` URLs, hosts on command lines) are approved once, before
  install, and then pass silently. Only a connection outside the prediction is paused.
- Registries a build tool normally uses (crates.io, the npm registry, PyPI, the Go proxy, ...) are asked once per
  package as a group.
- Choices: allow once, allow this host, block, abort the install. A blocked connection that breaks the build is
  reported as such.
- Every attempt is recorded whether allowed or not and goes into the after-install report.
- An unattended mode blocks everything outside the prediction and only reports it.

Files: asking per write is too frequent. Use sandbox policy instead (writes only under `$srcdir`/`$pkgdir`;
reads of sensitive places such as `~/.ssh` blocked, the attempt recorded).

## Shared observation server (idea, not decided, not started)

Idea: a server collects what installing a package did on other users' machines (files, hosts, programs) and
shows it before the next user installs. Valuable, but the server becomes a new thing to trust and a new target.

Gains:
- many real runs in different environments reduce the "a path that did not run is unknown" gap, at no build
  cost to the one user;
- the strongest signal is change between versions ("the last version only contacted github.com, this one
  contacts a new domain"), which is what a hijacked maintainer account looks like;
- predicted-versus-observed differences show where the static analysis and the AI miss things, and feed
  rule and prompt improvements.

Risks:
- the server is a single point of trust: a compromised or malicious server can show a false "normal";
- the uploaders are untrusted: fake users (sybil) can fill a malicious package with "normal" records, and a
  package can behave only for a few targeted users or only outside an analysis environment;
- new versions and new packages have no record, which is where attacks concentrate; "no record" is not a
  sign of safety;
- records carry paths, host names, IPs and the list of installed packages: privacy, consent and deletion;
- operations cost, abuse handling, availability; records and package metadata are untrusted input to the
  server too (injection, prompt injection when shown to the AI);
- environments differ (dependencies, options, architecture), so one "normal profile" does not exist;
- "hundreds installed it without trouble" reads as a safety signal, against the rule that silence is not a verdict.

Design rules to keep:
- the server is reference material, not a judge: show facts ("observed on N machines: ..."), never a score or a
  verdict; do not use the number of records as trust;
- lead with differences (between versions, and between prediction and observation), which stay meaningful
  even if the records are polluted;
- minimise and generalise records before upload: `$HOME`/`$srcdir`/`$pkgdir` instead of real paths, domains
  instead of full URLs, package name and version plus kind of access, no user identifier;
- the tool must work without the server; data from it is treated as untrusted like any other input;
- show where a record comes from (architecture, sandboxed or not, how many times) and say "no record" plainly.

First step, no server: keep the observation of each install on the user's own machine per package and
version, and on an update show only the access that is new compared with the last install. This gives the
most valuable part (change between versions) without the privacy, trust and sybil problems. Share
anonymised summaries through a server only once there are enough users.

### Shared observation server: signing and storage (discussed, not decided)

Trust moves from the server to keys, but only partly. A signature proves who said it, not that it is true:
- solved: a compromised server or a man in the middle cannot forge a record when the signing key is kept off
  the server; the server becomes plain storage; a bad signer can be revoked;
- not solved: a signer that lies or is compromised, many fake keys (the number of signatures is not trust),
  targeted attacks, the privacy of a key that links its uploads, and the gap for new versions.
- OpenSSH can do it (`ssh-keygen -Y sign` / `-Y verify` with an `allowed_signers` file, called as a
  process so the tool stays standard-library only). GPG (the Arch keyring already exists), minisign and
  sigstore are alternatives. The real question is the same for all: who decides which keys are trusted.

Rules:
- a record without a valid signature from an allowed key is ignored, and the report says it was ignored;
- a valid signature does not make the content a verdict: it is still shown as facts only;
- the signature covers the key (below), the record, the environment and the time as one block, so an old
  signed record cannot be reused for another package or version (replay); freshness is checked.

Trust models, most realistic first:
1. keys of a few audit agents run by the project (an isolated environment installs the package and the
   project signs the result; the key is kept offline, which is a much smaller target than a server);
2. only keys the user chose (`allowed_signers`): safest, useless without people to trust;
3. every user signs their own upload: shows origin only, does not stop fake keys or pollution.
Until there are enough users, ordinary user records stay local and are not uploaded.

What a record is about (the key). The PKGBUILD hash alone is not enough: `.install` hooks (run as root), patches
and helper scripts change without it, and so do unpinned sources (`SKIP`, a VCS source without `#commit=`) and
dependencies. A git commit hash covers the whole repository, but it also contains author, time, message and
parent, so equal content can have different hashes, and it is SHA-1. So:
| Field | Use |
|---|---|
| git tree hash of HEAD | the key: equal content, equal key |
| HEAD commit hash and parent commit hash | link to the previous version; what a user can compare with their own checkout |
| sha256 of every file | inside the signed block, to make up for SHA-1; computed over the whole repository, not only the files the tool read (large files can be omitted from review) |
| pkgbase, pkgver, pkgrel | readable name |
| whether each source is pinned, and the real hash of what was downloaded | marks the part of the behaviour the key does not cover |

A key holds many records, not one pair: one per environment (architecture, tool versions, sandboxed or not,
network policy) and per signer, each with the result (success or the step that failed) and a schema version.
They are shown as counts of facts ("observed 12 times; contacted X in 12, Y in 3"), never merged into a score.
Change detection compares the record set of a key with that of its parent key. Whether AUR allows rewriting
history is to be checked; a rewrite breaks the link to the previous version but not the content hash.

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
