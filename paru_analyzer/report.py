from __future__ import annotations

import os
import sys

from .models import FACT, Verdict

# "clear" is the lowest level. It means the scanner marked nothing, not that the package was judged safe.
# The symbol is always printed so the level never depends on colour alone.
SYMBOLS = {"fact": "", "clear": "", "info": "! ", "warning": "!! "}


def _color_code(level: str) -> str:
    if level == "warning":
        return "31"
    if level == "info":
        return "38;5;208" if "256color" in os.environ.get("TERM", "") else "33"
    return ""


def _use_color() -> bool:
    return sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def label(level: str) -> str:
    """The bracketed level tag, with its symbol and colour (colour only on a terminal, never with NO_COLOR)."""
    text = f"[{SYMBOLS[level]}{level}]"
    code = _color_code(level)
    return f"\033[{code}m{text}\033[0m" if code and _use_color() else text


def format_verdict(package: str, verdict: Verdict) -> str:
    lines = [f"{label(verdict.level)} {package}: {verdict.summary}"]
    # facts come last; they describe the package and never changed the level
    for finding in sorted(verdict.findings, key=lambda f: f.severity == FACT):
        where = finding.file + (f":{finding.line}" if finding.line else "")
        tag = f" [{finding.rule}]" if finding.rule else ""
        lines.append(f"  - {label(finding.severity)} {where + ': ' if where else ''}{finding.message}{tag}")
    return "\n".join(lines)
