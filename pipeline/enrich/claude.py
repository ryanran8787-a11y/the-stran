"""Anthropic Claude 結構化輸出 provider。

優先用 output_config.format（新版 API）；若失敗則退回 strict tool use。
"""

from __future__ import annotations

import json
from typing import Any

from ..config import Settings
from ..util import http_post_json, log
from .jsonparse import parse_json_loose
from .schemas import LLM_OUTPUT_SCHEMA

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
TOOL_NAME = "emit_digest"


class ClaudeProvider:
    name = "claude"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.anthropic_api_key
        self.model = settings.anthropic_model or "claude-haiku-4-5"
        self.schema = json.loads(json.dumps(LLM_OUTPUT_SCHEMA))

    def available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
            "Content-Type": "application/json",
        }

    def enrich(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        base: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 8192,
            "temperature": 0.2,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

        body = dict(base)
        body["output_config"] = {"format": {"type": "json_schema", "schema": self.schema}}
        try:
            payload = http_post_json(API_URL, body, headers=self._headers(), timeout=180, retries=2)
            return self._extract(payload)
        except Exception as exc:  # noqa: BLE001 - 退回 strict tool use
            log.warning("Claude output_config 失敗，改用 strict tool use：%s", exc)

        body = dict(base)
        body["tools"] = [
            {"name": TOOL_NAME, "description": "輸出整理後的資安日報結構", "input_schema": self.schema}
        ]
        body["tool_choice"] = {"type": "tool", "name": TOOL_NAME}
        payload = http_post_json(API_URL, body, headers=self._headers(), timeout=180, retries=2)
        return self._extract(payload)

    @staticmethod
    def _extract(payload: dict[str, Any]) -> dict[str, Any]:
        blocks = payload.get("content") if isinstance(payload, dict) else None
        if not isinstance(blocks, list) or not blocks:
            raise ValueError(f"Claude 回應異常：{json.dumps(payload, ensure_ascii=False)[:400]}")
        text = ""
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and isinstance(block.get("input"), dict):
                return block["input"]
            if block.get("type") == "text" and block.get("text"):
                text += block["text"]
        if not text.strip():
            raise ValueError("Claude 回應沒有可用內容")
        return parse_json_loose(text)
