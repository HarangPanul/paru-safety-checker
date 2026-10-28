from __future__ import annotations

from dataclasses import dataclass, field

LEVELS = ("clear", "info", "warning")
# "expected" is not a level. It states how the package is built ("the source comes from github.com and was not
# reviewed") without saying the package is risky, so it is shown but never raises the level, and the AI cannot
# report one (the schema below only offers LEVELS). Everything else is a "concern" and raises the level.
EXPECTED = "expected"

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "level": {"type": "string", "enum": list(LEVELS)},
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": list(LEVELS)},
                    "message": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                },
                "required": ["severity", "message"],
            },
        },
    },
    "required": ["level", "summary", "findings"],
}


def worst(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


@dataclass
class Finding:
    severity: str
    message: str
    file: str = ""
    line: int | None = None
    rule: str = ""


@dataclass
class Verdict:
    level: str
    summary: str
    findings: list[Finding] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Verdict":
        level = data["level"]
        if level not in LEVELS:
            raise ValueError(f"unknown level: {level!r}")
        findings = []
        for raw in data.get("findings", []):
            severity = raw["severity"]
            if severity not in LEVELS:
                raise ValueError(f"unknown severity: {severity!r}")
            line = raw.get("line")
            findings.append(
                Finding(severity, raw["message"], raw.get("file", ""), line if isinstance(line, int) else None)
            )
        return cls(level, str(data["summary"]), findings)
