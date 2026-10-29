"""Compare the regex rules about files with what the syntax tree says (docs/COMMANDS.md, replacing regexes by the AST).

Nothing here changes a result. For every input it asks two questions:
  regex: which of the file rules of heuristics.py fired?
  tree:  does ir.py see a write / delete / chmod whose area is `system`, `home` or `unresolved`?
and prints where the two disagree, so that the tree's judgement can be tuned before it replaces a regex.

    python -m experiments.file_ops_compare [lines.json]      # one shell command per entry of the JSON list
"""
from __future__ import annotations

import collections
import json
import sys

from paru_analyzer.heuristics import scan
from paru_analyzer.ir import build_ir

# the rules whose subject is a file being written, deleted, made executable or read from a sensitive place
FILE_RULES = frozenset("""
sudoers-passwd-write sudoers-remove ld-preload-file pacman-config-write rm-root rm-system-dir find-delete-root
recursive-perm-root disk-wipe home-delete live-system-write install-system-files world-writable setuid setuid-shell
chattr-immutable ssh-authorized-keys credential-paths read-shadow home-archive home-persistence-write
""".split())
CONCERN_AREAS = {"build": {"system", "home", "unresolved"}, "hook": {"home", "unresolved"}}


def tree_concerns(files: dict[str, str]) -> list[tuple]:
    """(program, op, path, area) of every write, delete or chmod the tree places outside the build and package directories."""
    found = []
    ir = build_ir(files)
    hook = {name for name in files if name.endswith(".install")}
    for step in ir["steps"]:
        areas = CONCERN_AREAS["hook" if step["file"] in hook else "build"]
        for op in step["ops"]:
            if op["op"] in ("write", "delete", "chmod") and op.get("area") in areas:
                found.append((step["program"], op["op"], op["path"], op["area"]))
    return found


def inputs(lines: list[str]):
    for line in lines:
        yield f"build: {line}", {"PKGBUILD": f"build() {{\n  {line}\n}}\n"}
        yield f"hook: {line}", {"x.install": f"post_install() {{\n  {line}\n}}\n"}


def main(argv: list[str]) -> int:
    from tests import test_rule_matrix as matrix
    lines = json.load(open(argv[1])) if len(argv) > 1 else []
    lines += [line for line, _ in matrix.CASES]
    regex_only: dict[str, list] = collections.defaultdict(list)
    fired_total: collections.Counter = collections.Counter()
    both: collections.Counter = collections.Counter()
    tree_only: collections.Counter = collections.Counter()
    tree_only_examples: dict[tuple, str] = {}
    total = 0
    for label, files in inputs(lines):
        total += 1
        rules = {f.rule for f in scan(files)} & FILE_RULES
        concerns = tree_concerns(files)
        for rule in rules:
            rule = f"{rule} ({label.split(':')[0]})"
            fired_total[rule] += 1
            if concerns:
                both[rule] += 1
            else:
                regex_only[rule].append(label)
        if concerns and not rules:
            for program, op, path, area in concerns:
                key = (program, op, area)
                tree_only[key] += 1
                tree_only_examples.setdefault(key, f"{label}  ->  {path}")
    print(f"{total} inputs\n")
    print("regex rule: fired / tree also sees a write, delete or chmod outside the build dirs / only the regex")
    for rule in sorted(fired_total):
        print(f"  {rule:34} {fired_total[rule]:5} {both[rule]:5} {len(regex_only[rule]):5}   e.g. {regex_only[rule][0][:90] if regex_only[rule] else ''}")
    print("\ntree sees a concern, no file rule fired (program, op, area): count")
    for key, count in tree_only.most_common(40):
        print(f"  {count:5} {key}   e.g. {tree_only_examples[key][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
