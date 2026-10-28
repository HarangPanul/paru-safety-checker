"""In which role each function of a PKGBUILD or .install runs (docs/COMMANDS.md, "Execution context").

The same command is normal in one place and a problem in another: `systemctl enable` belongs in
`post_install()` and not in `build()`. The roles are

    parse    top level of a PKGBUILD and pkgver(): makepkg reads the file, as the user
    build    prepare(), build(), check(): as the user, while building
    package  package() and package_<name>(): as the user under fakeroot
    hook     the six install hooks, and the top level of a .install: as root on the real system
    unknown  the function is not reached from any of these by a call this module can follow

A helper function gets the union of the roles of every function that calls it. `unknown` is what is left when the
call graph does not say: a function nobody calls, one that only an `eval` / `sh -c` string or a variable calls
(neither is followed), and everything such a function calls in turn. A policy has to treat `unknown` as every
role at once, since the function may run anywhere.

Only the roles are computed here. Nothing reads them yet, so no result changes.
"""
from __future__ import annotations

import re

PARSE, BUILD, PACKAGE, HOOK, UNKNOWN = "parse", "build", "package", "hook", "unknown"
ROLES = (PARSE, BUILD, PACKAGE, HOOK, UNKNOWN)

HOOKS = frozenset({"pre_install", "post_install", "pre_upgrade", "post_upgrade", "pre_remove", "post_remove"})
_BUILD_FUNCTIONS = frozenset({"prepare", "build", "check"})
_PACKAGE_FUNCTION = re.compile(r"package(_[A-Za-z0-9@._+-]+)?\Z")
TOP = "<top>"                          # the key of code outside every function


def entry_role(name: str, is_install: bool) -> str | None:
    """The role a function has because of its own name, None for a helper."""
    if is_install:
        return HOOK if name in HOOKS else None
    if name == "pkgver":
        return PARSE
    if name in _BUILD_FUNCTIONS:
        return BUILD
    if _PACKAGE_FUNCTION.match(name):
        return PACKAGE
    return None


def top_role(is_install: bool) -> str:
    """Code outside every function runs when the file is read: by makepkg for a PKGBUILD, as root by pacman for a .install."""
    return HOOK if is_install else PARSE


def call_graph(parsed) -> tuple[dict[str, set[str]], set[str]]:
    """(container -> functions it calls directly, functions called through a string). The container is a function
    name or TOP. A call whose command is inside an `eval` / `sh -c` string is not an edge: where that string runs
    is not followed, so its callee is reported in the second set and becomes `unknown`."""
    defined = parsed.function_names
    edges: dict[str, set[str]] = {}
    indirect: set[str] = set()
    for item in parsed.commands:
        name = item.command.name
        if name not in defined:
            continue
        if item.parent is not None:
            indirect.add(name)
        else:
            edges.setdefault(item.function or TOP, set()).add(name)
    return edges, indirect


def function_roles(parsed) -> dict[str, frozenset]:
    """function name -> its roles (never empty for a defined function)."""
    if not parsed.is_shell:
        return {}
    edges, indirect = call_graph(parsed)
    roles: dict[str, set[str]] = {name: set() for name in parsed.function_names}
    todo: list[tuple[str, str]] = []                  # (function, role) not passed on to its callees yet

    def give(function: str, role: str) -> None:
        if role not in roles[function]:
            roles[function].add(role)
            todo.append((function, role))

    for name in roles:
        role = entry_role(name, parsed.is_install)
        if role:
            give(name, role)
    for name in edges.get(TOP, ()):
        give(name, top_role(parsed.is_install))
    for name in indirect:
        give(name, UNKNOWN)
    def spread() -> None:
        while todo:
            function, role = todo.pop()
            for callee in edges.get(function, ()):
                give(callee, role)

    spread()
    for name, found in roles.items():
        if not found:
            give(name, UNKNOWN)                        # nothing reaches it
    spread()
    return {name: frozenset(found) for name, found in roles.items()}


def roles_of(parsed, function: str | None) -> frozenset:
    """The roles of code in `function`, or of the top level for None."""
    if function is None:
        return frozenset({top_role(parsed.is_install)})
    return parsed.function_roles.get(function, frozenset({UNKNOWN}))
