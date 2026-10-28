from __future__ import annotations

import sys

from .models import Verdict

COLORS = {"safe": "32", "caution": "33", "danger": "31"}
# "safe" is the internal name of the lowest level. It means the scanner marked nothing, not that the
# package was judged safe, so the screen says so.
LABELS = {"safe": "NO FINDINGS", "caution": "CAUTION", "danger": "DANGER"}


def _paint(text: str, level: str) -> str:
    if sys.stderr.isatty():
        return f"\033[{COLORS[level]}m{text}\033[0m"
    return text


def format_verdict(package: str, verdict: Verdict) -> str:
    lines = [f"[{_paint(LABELS[verdict.level], verdict.level)}] {package}: {verdict.summary}"]
    for finding in verdict.findings:
        where = finding.file + (f":{finding.line}" if finding.line else "")
        prefix = f"  - {_paint(finding.severity, finding.severity)}"
        tag = f" [{finding.rule}]" if finding.rule else ""
        lines.append(f"{prefix} {where + ': ' if where else ''}{finding.message}{tag}")
    return "\n".join(lines)
