"""The intermediate representation (docs/IR.md): what a package's files contain, as a list of facts.

One pass over the parsed files gives sources, dependencies, declarations, the units that hold code, the
steps (one command each, with what it does as `ops`), the effects those add up to, the places the analysis
could not read (`gaps`) and, on a separate layer, the rules' `marks`. The same data can then feed a summary
for the person, the input of the model, and the rules, so that none of them reads the files differently.

Every string in it comes from the package author. It is data, never an instruction: a renderer must quote
it, and a model must be told so.
"""
from __future__ import annotations

import json
import re
import sys
from urllib.parse import urlsplit

from . import commandtable, invocation, roles as role_names, strict
from .fetch import TRUNCATED_MARKER
from .fileaccess import FILE_COMMANDS, file_accesses
from .heuristics import DATA_EXTENSIONS, DATA_NAME_PREFIXES, MAX_PATTERN_LINE, is_prose, source_entries
from .models import Finding
from .parsed import ParsedFile, expand
from .shast import FunctionDef, walk

IR_VERSION = 1

DEP_KEY = re.compile(r"^(depends|makedepends|checkdepends|optdepends)(?:_\w+)?$")
FETCHERS = frozenset({"curl", "wget", "aria2c", "axel", "lftp", "wget2", "http", "https", "xh"})
GIT_NETWORK = frozenset({"clone", "fetch", "pull", "submodule", "ls-remote"})
URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
OMITTED = re.compile(r"^(?P<name>.*) \((?P<why>symlink|binary or unreadable|total size limit)\)$")
OMITTED_KIND = {"symlink": "symlink", "binary or unreadable": "binary", "total size limit": "omitted"}
OMITTED_REASON = {"symlink": "symlink", "binary or unreadable": "binary", "total size limit": "truncated"}
PRIVILEGE = frozenset({"sudo", "su", "doas"})
# programs the IR has a translation for (what they do is recorded as ops), whether or not the allowlist lets them run
TRANSLATED = (FETCHERS | invocation.SHELLS | FILE_COMMANDS
              | frozenset("git chmod pacman pip pip3 npm yarn pnpm cargo go gem base64 xxd uudecode nohup setsid disown systemd-run source . eval".split()))
DETACH = frozenset({"nohup", "setsid", "disown", "systemd-run"})
# lines that only close or open a construct: no command of their own, so no statement covers them
STRUCTURAL = re.compile(
    r"^\s*(?:[{}()]|fi|done|esac|then|else|do|;;|;&|;;&|in|(?:function\s+)?[^\s()=]+\s*\(\s*\)\s*\{?|function\s+\S+\s*\{?"
    r"|(?:if|elif|while|until|for|select|case)\b.*|.*\)|.*;;|.*\bthen|.*\bdo)\s*;?\s*(?:#.*)?$"
)


def file_kind(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    if name == "PKGBUILD":
        return "pkgbuild"
    if name.endswith(".install"):
        return "install"
    if name.endswith((".patch", ".diff")):
        return "patch"
    if name.startswith("("):
        return "omitted"
    if base.startswith(DATA_NAME_PREFIXES) or base.endswith(DATA_EXTENSIONS) or is_prose(name):
        return "data"
    return "script"


def area(path: str, variables: dict, hook: bool) -> str:
    """Where a path is: srcdir, pkgdir, home, system, tmp, device, or unresolved."""
    p = expand(path, variables) if "$" in path else path
    if re.match(r"^\$\{?pkgdir\}?(?:/|$)", p):
        return "pkgdir"
    if re.match(r"^\$\{?(?:srcdir|startdir)\}?(?:/|$)", p):
        return "srcdir"
    if re.match(r"^(?:~|\$HOME|\$\{HOME\})(?:/|$)|^/(?:home|root)(?:/|$)", p):
        return "home"
    if re.match(r"^/(?:tmp|var/tmp|dev/shm)(?:/|$)", p):
        return "tmp"
    if re.match(r"^/(?:dev|proc|sys)(?:/|$)", p):
        return "device"
    if "$" in p or "`" in p or p.startswith("~"):
        return "unresolved"
    if p.startswith("/"):
        return "system"
    if ".." in p.split("/"):
        return "unresolved"
    return "system" if hook else "srcdir"        # an install hook runs from /, a build from $srcdir


def _first_operand(args: list[str]) -> str | None:
    return next((a for a in args if not a.startswith("-")), None)


def _fetch_target(name: str, args: list[str], redirects: tuple) -> str:
    for i, arg in enumerate(args):
        if name == "curl" and arg in ("-o", "--output") and i + 1 < len(args):
            return args[i + 1]
        if name == "curl" and arg in ("-O", "--remote-name"):
            return "file"
        if name.startswith("wget") and arg == "-O" and i + 1 < len(args):
            return "stdout" if args[i + 1] == "-" else args[i + 1]
        if name.startswith("wget") and re.fullmatch(r"-[A-Za-z]*O-", arg):
            return "stdout"
    for op, target in redirects:
        if op in (">", ">>", "&>", "&>>", ">|"):
            return target
    return "file" if name.startswith("wget") else "stdout"


def _install_pkg(name: str, args: list[str]) -> dict | None:
    words = [a for a in args if not a.startswith("-")]
    if name == "pacman" and any(re.fullmatch(r"-[A-Za-z]*[SU][A-Za-z]*", a) for a in args if a.startswith("-") and not a.startswith("--")):
        if not strict.PACMAN_READ_ONLY.match(next((a for a in args if a.startswith("-")), "")):
            return {"op": "install-pkg", "via": "pacman", "what": " ".join(words)}
    if name in ("pip", "pip3") and words[:1] == ["install"]:
        return {"op": "install-pkg", "via": "pip", "what": " ".join(words[1:])}
    if name in ("npm", "yarn", "pnpm") and words[:1] and words[0] in ("install", "i", "add", "ci"):
        return {"op": "install-pkg", "via": name, "what": " ".join(words[1:])}
    if name == "cargo" and words[:1] == ["install"]:
        return {"op": "install-pkg", "via": "cargo", "what": " ".join(words[1:])}
    if name == "go" and words[:1] and words[0] in ("install", "get"):
        return {"op": "install-pkg", "via": "go", "what": " ".join(words[1:])}
    if name == "gem" and words[:1] == ["install"]:
        return {"op": "install-pkg", "via": "gem", "what": " ".join(words[1:])}
    return None


def ops_of(final, name: str, fed_by: list[str], variables: dict, hook: bool, known: bool) -> list[dict]:
    """What one command (with its wrappers taken off) does, in the vocabulary of docs/IR.md."""
    args = final.args
    ops: list[dict] = []
    if name in FETCHERS:
        urls = [a for a in args if URL.match(a)]
        target = _fetch_target(name, args, final.redirects)
        ops.extend({"op": "fetch", "url": u, "to": target} for u in urls)
        if not urls:
            ops.append({"op": "fetch", "url": None, "to": target})
    elif name == "git" and next((a for a in args if not a.startswith("-")), "") in GIT_NETWORK:
        urls = [a for a in args if URL.match(a)]
        ops.extend({"op": "fetch", "url": u, "to": "repository"} for u in urls)
        if not urls:
            ops.append({"op": "fetch", "url": None, "to": "repository"})
    if name in invocation.SHELLS or invocation.interpreter(name):
        if invocation.reads_program_from_stdin(name, args):
            ops.append({"op": "exec", "target": "stdin", "from": fed_by})
        elif any(a == "-c" or re.fullmatch(r"-[A-Za-z]*[ce]", a) for a in args):
            ops.append({"op": "exec", "target": "string"})
        elif (script := _first_operand(args)) is not None:
            ops.append({"op": "exec", "target": script})
    elif name in ("source", "."):
        ops.append({"op": "exec", "target": _first_operand(args) or "?"})
    elif name == "eval":
        ops.append({"op": "exec", "target": "string"})
    elif name.startswith(("./", "/", "$")) and not known:
        ops.append({"op": "exec", "target": final.name})
    if name == "chmod":
        operands = [a for a in args if not a.startswith("-")]
        mode = operands[0] if operands else ""
        sets_id = bool(re.search(r"[ug]?\+s|^[0-7]?[4-7][0-7]{3}$", mode))
        for path in operands[1:]:
            ops.append({"op": "chmod", "path": path, "mode": mode, "sets_id_bit": sets_id, "area": area(path, variables, hook)})
    string_program = any(o["op"] == "exec" and o["target"] == "string" for o in ops)
    accessed = final._replace(args=[]) if string_program else final        # the string after -c is a program, not a path
    for verb, path in file_accesses(accessed, hook):
        ops.append({"op": "read" if verb in ("read", "access") else verb, "path": path, "area": area(path, variables, hook)})
    if (found := _install_pkg(name, args)) is not None:
        ops.append(found)
    for effect in commandtable.load().effects_of(strict._table_key(commandtable.load(), name), args, final.piped) or ():
        if effect.kind == "system" and effect.target != "packages":       # packages are the install-pkg op above
            ops.append({"op": "system", "what": effect.target})
    if name == "base64" and any(a in ("-d", "-D", "--decode") for a in args):
        ops.append({"op": "decode", "kind": "base64"})
    elif name in ("xxd",) and "-r" in args:
        ops.append({"op": "decode", "kind": "hex"})
    elif name == "uudecode":
        ops.append({"op": "decode", "kind": "uuencode"})
    if name in DETACH:
        ops.append({"op": "spawn", "detached": True})
    if not known:
        ops.append({"op": "other"})
    return ops


def _runs(roles: frozenset) -> str:
    """Who runs the code and when, from its roles (roles.py): `unknown` is any role at all, so it is not claimed."""
    if roles == {role_names.HOOK}:
        return "as-root-on-install"
    if roles == {role_names.PARSE}:
        return "at-parse"
    if roles and roles <= {role_names.BUILD, role_names.PACKAGE}:
        return "as-user"
    return "unknown"


def _scheme(url: str) -> str:
    bare = url.split("+", 1)[1] if re.match(r"^[a-z]+\+\w+://", url) else url
    return urlsplit(bare).scheme


def _functions(parsed: ParsedFile) -> list[tuple[str, int, int]]:
    if parsed.ast is None:
        return []
    return [(n.name, n.line, n.end) for n in walk(parsed.ast.script) if isinstance(n, FunctionDef)]


def _innermost(functions: list, line: int) -> str | None:
    best = None
    for name, start, end in functions:
        if start <= line <= end and (best is None or end - start < best[2] - best[1]):
            best = (name, start, end)
    return best[0] if best else None


def _declarations(parsed: ParsedFile) -> list[dict]:
    found = []
    for name, array in parsed.arrays.items():
        found.append({"file": parsed.name, "name": name, "kind": "array", "value": list(array.items), "line": array.line})
    for name, value in parsed.variables.items():
        if name not in parsed.arrays:
            found.append({"file": parsed.name, "name": name, "kind": "scalar", "value": value,
                          "line": parsed.assignment_line(name)})
    return sorted(found, key=lambda d: (d["line"] or 0, d["name"]))


def _sources(parsed: ParsedFile) -> list[dict]:
    replaced_lines = {line for _, array in parsed.replaced_arrays[1] for line in array.item_lines}
    found = []
    for index, entry in enumerate(source_entries(parsed), 1):
        vcs = entry.url.split("+", 1)[0] if entry.vcs else None
        found.append({"id": f"src{index}", "url": entry.url, "scheme": _scheme(entry.url), "vcs": vcs, "pinned": entry.pinned,
                      "checksum": entry.checksum, "line": entry.line, "overridden": entry.line in replaced_lines})
    return found


def _dependencies(parsed: ParsedFile) -> list[dict]:
    found = []
    for definition in parsed.definitions:
        match = DEP_KEY.match(definition.name)
        if not match:
            continue
        kind = match.group(1)
        for item, line in zip(definition.items, definition.item_lines):
            text = expand(item, parsed.variables)
            if kind == "optdepends":
                name, constraint = text.split(":", 1)[0].strip(), None
            else:
                parts = re.match(r"^([^<>=:\s]+)\s*((?:[<>]=?|=)[^\s]*)?", text)
                name, constraint = (parts.group(1), parts.group(2)) if parts else (text, None)
            found.append({"name": name, "kind": kind, "constraint": constraint, "in_official_repo": None, "line": line,
                          "unresolved": "$" in name})
    return found


def build_ir(files: dict[str, str], findings: list[Finding] | None = None, package: str | None = None) -> dict:
    """The IR of one package. `files` maps names to text (what fetch.collect_files returns)."""
    ir: dict = {"ir_version": IR_VERSION, "package": package, "files": [], "declarations": [], "sources": [],
                "dependencies": [], "units": [], "steps": [], "statements": [], "effects": {}, "gaps": [], "marks": []}
    network, writes, deletes, reads, privilege, installs = [], [], [], [], [], []
    step_number = 0

    for name, text in files.items():
        kind = file_kind(name)
        if kind == "omitted":
            for note in text.splitlines()[1:]:
                m = OMITTED.match(note)
                if m:
                    ir["files"].append({"path": m["name"], "kind": OMITTED_KIND[m["why"]], "bytes": None, "truncated": False, "parse": "not-shell"})
                    ir["gaps"].append({"file": m["name"], "lines": None, "reason": OMITTED_REASON[m["why"]], "note": f"not reviewed: {m['why']}"})
                elif note.strip():
                    ir["gaps"].append({"file": "(omitted-files)", "lines": None, "reason": "unreadable", "note": note[:200]})
            continue
        parsed = ParsedFile(name, text)
        line_count = text.count("\n") + 1
        truncated = TRUNCATED_MARKER in text
        entry = {"path": name, "kind": kind, "bytes": len(text.encode("utf-8", "replace")), "truncated": truncated, "parse": "not-shell"}
        if truncated:
            ir["gaps"].append({"file": name, "lines": None, "reason": "truncated", "note": "larger than the review limit; only the beginning was read"})
        if not parsed.is_shell:
            ir["files"].append(entry)
            if kind == "script":
                ir["gaps"].append({"file": name, "lines": None, "reason": "unanalyzed-file", "note": "script or unrecognised file, only pattern-checked"})
            continue
        hook = parsed.is_install
        entry["parse"] = "ok" if parsed.pre.ok and not parsed.ast.errors else "failed"
        ir["files"].append(entry)
        if not parsed.pre.ok:
            ir["gaps"].append({"file": name, "lines": [1, line_count], "reason": "parse-failed", "note": parsed.pre.error})
        for number, raw in enumerate(text.split("\n"), 1):
            if len(raw) > MAX_PATTERN_LINE:
                ir["gaps"].append({"file": name, "lines": [number, number], "reason": "overlong-line", "note": f"{len(raw)} characters"})

        ir["declarations"].extend(_declarations(parsed))
        if parsed.is_pkgbuild:
            ir["sources"] = _sources(parsed)
            ir["dependencies"] = _dependencies(parsed)

        functions = _functions(parsed)
        unit_steps: dict[str, list[str]] = {}
        where = "hook" if hook else "build"
        local = parsed.function_names
        variables = parsed.stable_variables
        ids: dict[int, str] = {}
        commands = parsed.commands
        for pc in commands:
            step_number += 1
            ids[id(pc.command)] = f"s{step_number}"
        for pc in commands:
            sid = ids[id(pc.command)]
            chain = list(invocation.views(pc.command))
            final = chain[-1]
            program = strict.normalise(final.name)
            roles = parsed.roles_of(pc.function)
            verdict = strict.classify(final, where, local, roles)
            known = verdict is None or verdict[0] in ("inline-code", "network-command", "source-tree-program") or (
                verdict[0] == "unknown-command" and (program in TRANSLATED or invocation.interpreter(program)))
            fed_by = [ids[id(c)] for c in pc.upstream() if id(c) in ids]
            unit = f"{name}:(top)" if pc.top else f"{name}:{_innermost(functions, pc.line) or '(top)'}"
            unit_steps.setdefault(unit, []).append(sid)
            ops = ops_of(final, program, fed_by, variables, hook, known)
            if verdict is not None and verdict[0] == "source-tree-program":
                ops.append({"op": "exec", "target": final.name})
            ir["steps"].append({
                "id": sid, "unit": unit, "file": name, "line": pc.line, "lines": [pc.line, max(pc.line, pc.end)],
                "text": pc.text, "program": program, "argv": list(final.args), "via": [v.name for v in chain[:-1]], "known": known, "roles": sorted(roles),
                "pipeline": {"segment": pc.command.segment, "piped": pc.command.piped, "fed_by": fed_by},
                "ops": ops, "substitution": pc.command.inside, "inside": ids.get(id(pc.parent)) if pc.parent is not None else None,
            })
            if verdict is not None and (not known or verdict[0] == "inline-code"):
                reason = {"unknown-command": "unknown-program", "dynamic-command": "dynamic-command"}.get(verdict[0], "inline-code")
                ir["gaps"].append({"file": name, "lines": [pc.line, max(pc.line, pc.end)], "reason": reason, "note": verdict[1], "step": sid})
            for op in ops:
                at = {"step": sid}
                if op["op"] == "fetch":
                    network.append({**at, "url": op["url"], "scheme": _scheme(op["url"]) if op["url"] else None})
                elif op["op"] == "write":
                    writes.append({**at, "path": op["path"], "area": op["area"]})
                elif op["op"] == "delete":
                    deletes.append({**at, "path": op["path"], "area": op["area"]})
                elif op["op"] == "read":
                    reads.append({**at, "path": op["path"], "area": op["area"]})
                elif op["op"] == "install-pkg":
                    installs.append({**at, "via": op["via"], "what": op["what"]})
            if program in PRIVILEGE or any(v.name in PRIVILEGE for v in chain[:-1]):
                privilege.append({"step": sid, "program": next(v.name for v in chain if strict.normalise(v.name) in PRIVILEGE)})

        for unit in parsed.code_units:
            kind_ = "gap" if not unit.ok else "step" if unit.code else "declaration"
            ir["statements"].append({"file": name, "lines": [unit.line, max(unit.line, unit.end)], "kind": kind_})
            if not unit.ok:
                ir["gaps"].append({"file": name, "lines": [unit.line, max(unit.line, unit.end)], "reason": "parse-failed", "note": unit.text[:120]})

        top_lines = [u for u in parsed.code_units if u.top]
        for fname, start, end in functions:
            unit_id = f"{name}:{fname}"
            unit_roles = parsed.roles_of(fname)
            ir["units"].append({"id": unit_id, "kind": "hook" if hook else "function", "file": name, "lines": [start, end],
                                "runs": _runs(unit_roles), "roles": sorted(unit_roles), "steps": unit_steps.get(unit_id, [])})
        if top_lines:
            ir["units"].append({"id": f"{name}:(top)", "kind": "toplevel", "file": name,
                                "lines": [min(u.line for u in top_lines), max(max(u.line, u.end) for u in top_lines)],
                                "runs": _runs(parsed.roles_of(None)), "roles": sorted(parsed.roles_of(None)),
                                "steps": unit_steps.get(f"{name}:(top)", [])})

    ir["effects"] = {"network": network, "writes": writes, "deletes": deletes, "reads": reads, "privilege": privilege, "installs": installs}
    step_by_file: dict[str, list[dict]] = {}
    for step in ir["steps"]:
        step_by_file.setdefault(step["file"], []).append(step)
    for finding in findings or ():
        covering = next((s["id"] for s in step_by_file.get(finding.file, ()) if finding.line and s["lines"][0] <= finding.line <= s["lines"][1]), None)
        ir["marks"].append({"rule": finding.rule, "severity": finding.severity, "file": finding.file, "line": finding.line,
                            "step": covering, "message": finding.message})
    return ir


def uncovered_lines(ir: dict, files: dict[str, str]) -> list[tuple[str, int]]:
    """Lines of the shell files that are neither blank, a comment, structural (`fi`, `}`, a function header, a
    compound-command header) nor inside a statement or a gap: the coverage invariant of docs/IR.md says there
    are none. Heredoc bodies and multi-line strings sit inside their statement's range."""
    ranges: dict[str, list[tuple[int, int]]] = {}
    for entry in ir["statements"]:
        ranges.setdefault(entry["file"], []).append(tuple(entry["lines"]))
    for gap in ir["gaps"]:
        if gap["lines"]:
            ranges.setdefault(gap["file"], []).append(tuple(gap["lines"]))
    missing = []
    for entry in ir["files"]:
        if entry["parse"] == "not-shell":
            continue
        name = entry["path"]
        spans = ranges.get(name, [])
        for number, raw in enumerate(files[name].split("\n"), 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or STRUCTURAL.match(raw):
                continue
            if not any(start <= number <= end for start, end in spans):
                missing.append((name, number))
    return missing


def to_json(ir: dict, indent: int | None = 2) -> str:
    return json.dumps(ir, indent=indent, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    """`python -m paru_analyzer.ir DIR`: the IR of the package files in DIR, as JSON."""
    from pathlib import Path

    from .fetch import collect_files
    from .heuristics import scan

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not Path(args[0]).is_dir():
        print("usage: python -m paru_analyzer.ir DIR   (a folder with a PKGBUILD)", file=sys.stderr)
        return 2
    files = collect_files(Path(args[0]))
    print(to_json(build_ir(files, scan(files), Path(args[0]).resolve().name)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
