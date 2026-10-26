from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ..models import VERDICT_SCHEMA, Verdict
from ..prompt import SYSTEM_PROMPT, build_user_prompt
from .base import ProviderError

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"
TOOL_NAME = "report_verdict"
TOOL = {
    "name": TOOL_NAME,
    "description": "Report the security verdict for the AUR package.",
    "input_schema": VERDICT_SCHEMA,
}


class ClaudeProvider:
    def __init__(self, api_key: str | None = None, model: str | None = None, base_url: str | None = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        self.model = model or os.environ.get("PARU_SAFE_MODEL", DEFAULT_MODEL)
        self.base_url = (base_url or os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")

    def analyze(self, package: str, files: dict[str, str]) -> Verdict:
        body = {
            "model": self.model,
            "max_tokens": 2048,
            "system": SYSTEM_PROMPT,
            "tools": [TOOL],
            "tool_choice": {"type": "tool", "name": TOOL_NAME},
            "messages": [{"role": "user", "content": build_user_prompt(package, files)}],
        }
        request = urllib.request.Request(
            f"{self.base_url}/v1/messages",
            data=json.dumps(body).encode(),
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                data = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Claude API request failed: {exc}") from exc

        for block in data.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == TOOL_NAME:
                try:
                    return Verdict.from_dict(block["input"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ProviderError(f"invalid verdict from model: {exc}") from exc
        raise ProviderError("model returned no verdict")
