from __future__ import annotations

import os

from .base import Provider, ProviderError
from .claude import ClaudeProvider

__all__ = ["Provider", "ProviderError", "ClaudeProvider", "make_provider"]


def make_provider() -> Provider:
    name = os.environ.get("PARU_SAFE_PROVIDER", "claude")
    if name == "claude":
        return ClaudeProvider()
    raise ProviderError(f"unknown provider: {name!r}")
