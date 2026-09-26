"""Gemini（Google AI Studio）結構化輸出 provider。"""

from __future__ import annotations

import json
from typing import Any

from ..config import CACHE_DIR, Settings
from ..util import http_get, http_post_json, log, read_json, write_json
from .jsonparse import parse_json_loose
from .schemas import LLM_OUTPUT_SCHEMA, to_gemini_schema

API_BASE = "https://generativelanguage.googleapis.com/v1beta"
MODEL_CACHE = CACHE_DIR / "gemini-model.json"

# 自動挑模型時的偏好排序（越前面越優先）
MODEL_PREFERENCES = ("flash", "2.5", "3", "pro", "lite")
MODEL_PENALTIES = ("embedding", "image", "tts", "audio", "vision-only", "veo", "lyria", "nano")


class GeminiProvider:
    name = "gemini"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.gemini_api_key
        self.model = (settings.gemini_model or "").strip()
        self.schema = to_gemini_schema(json.loads(json.dumps(LLM_OUTPUT_SCHEMA)))

    def available(self) -> bool:
        return bool(self.api_key)

    # ------------------------------------------------------------ 內部
    def _headers(self) -> dict[str, str]:
        return {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}

    def _score_model(self, name: str) -> int:
        lowered = name.lower()
        if any(bad in lowered for bad in MODEL_PENALTIES):
            return -1
        score = 0
        for index, keyword in enumerate(MODEL_PREFERENCES):
            if keyword in lowered:
                score += (len(MODEL_PREFERENCES) - index) * 2
        if "latest" in lowered:
            score += 1
        if "preview" in lowered or "exp" in lowered:
            score -= 1
        return score

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        cached = read_json(MODEL_CACHE) if MODEL_CACHE.exists() else None
        if isinstance(cached, dict) and cached.get("model"):
            self.model = str(cached["model"])
            return self.model
        try:
            payload = http_get_models(self.api_key)
        except Exception as exc:  # noqa: BLE001 - 列模型失敗就用保守預設
            log.warning("Gemini 列出模型失敗，改用預設名稱：%s", exc)
            self.model = "gemini-2.5-flash"
            return self.model

        candidates: list[tuple[int, str]] = []
        for entry in payload.get("models") or []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").removeprefix("models/")
            methods = entry.get("supportedGenerationMethods") or []
            if "generateContent" not in methods:
                continue
            score = self._score_model(name)
            if score >= 0:
                candidates.append((score, name))
        candidates.sort(key=lambda pair: (-pair[0], pair[1]))
        self.model = candidates[0][1] if candidates else "gemini-2.5-flash"
        log.info("Gemini 自動選擇模型：%s（候選 %s 個）", self.model, len(candidates))
        try:
            write_json(MODEL_CACHE, {"model": self.model})
        except Exception:  # noqa: BLE001 - 快取失敗無妨
            pass
        return self.model

    def enrich(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        model = self.resolve_model()
        url = f"{API_BASE}/models/{model}:generateContent"
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
                "responseSchema": self.schema,
            },
        }
        try:
            payload = http_post_json(url, body, headers=self._headers(), timeout=180, retries=2)
        except Exception as exc:  # noqa: BLE001 - 退回無 schema 模式
            log.warning("Gemini 帶 responseSchema 失敗，改以純 JSON 模式重試：%s", exc)
            body["generationConfig"].pop("responseSchema", None)
            payload = http_post_json(url, body, headers=self._headers(), timeout=180, retries=2)
        return extract_json(payload)


def http_get_models(api_key: str) -> dict[str, Any]:
    payload = http_get(
        f"{API_BASE}/models?pageSize=200",
        headers={"x-goog-api-key": api_key, "Accept": "application/json"},
        timeout=45,
        retries=1,
    )
    return json.loads(payload.decode("utf-8", "replace"))


def extract_json(payload: dict[str, Any]) -> dict[str, Any]:
    """從 Gemini 回應取出 JSON 物件。"""
    candidates = payload.get("candidates") if isinstance(payload, dict) else None
    text = ""
    if isinstance(candidates, list):
        for candidate in candidates:
            content = (candidate or {}).get("content") or {}
            for part in content.get("parts") or []:
                if isinstance(part, dict) and part.get("text"):
                    text += part["text"]
    if not text:
        raise ValueError(f"Gemini 回應沒有文字內容：{json.dumps(payload, ensure_ascii=False)[:400]}")
    return parse_json_loose(text)
