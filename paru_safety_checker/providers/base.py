from __future__ import annotations

from typing import Protocol

from ..models import Finding, Verdict


class ProviderError(Exception):
    """The provider could not produce a verdict (network, API, or parse failure)."""


class Provider(Protocol):
    def analyze(self, package: str, files: dict[str, str], findings: list[Finding] | None = None, inventory: str = "") -> Verdict: ...
