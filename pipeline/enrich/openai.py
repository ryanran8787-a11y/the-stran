"""OpenAI 結構化輸出 provider（response_format: json_schema, strict）。"""

from __future__ import annotations

import json
from typing import Any

from ..config import Settings
from ..util import http_post_json, log
from .jsonparse import parse_json_loose
from .schemas import LLM_OUTPUT_SCHEMA, to_openai_strict

API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider:
    name = "openai"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.openai_api_key
        self.model = settings.openai_model or "gpt-4.1-mini"
        self.schema = to_openai_strict(json.loads(json.dumps(LLM_OUTPUT_SCHEMA)))

    def available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "security_daily_digest",
                    "strict": True,
                    "schema": self.schema,
                },
            },
        }
        try:
            payload = http_post_json(
                API_URL,
                body,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=180,
                retries=2,
            )
        except Exception as exc:  # noqa: BLE001 - 舊模型可能不支援 json_schema
            log.warning("OpenAI json_schema 失敗，改以 json_object 重試：%s", exc)
            body["response_format"] = {"type": "json_object"}
            payload = http_post_json(
                API_URL,
                body,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=180,
                retries=2,
            )
        return _extract(payload)


def _extract(payload: dict[str, Any]) -> dict[str, Any]:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices:
        raise ValueError(f"OpenAI 回應異常：{json.dumps(payload, ensure_ascii=False)[:400]}")
    message = (choices[0] or {}).get("message") or {}
    content = message.get("content")
    if isinstance(content, list):  # 內容區塊形式
        content = "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    if not isinstance(content, str) or not content.strip():
        raise ValueError("OpenAI 回應沒有內容")
    return parse_json_loose(content)
