"""Gemini（Google AI Studio）結構化輸出 provider。

額度策略：免費層額度通常是「每模型每日」限制（例如 flash-lite 每日 20 次），
等待無濟於事。因此這裡會準備一份候選模型清單，遇到「每日額度」型 429 就自動
換下一個模型繼續，完全失敗才退回規則模板。
"""

from __future__ import annotations

import json
from typing import Any

from ..config import CACHE_DIR, Settings
from ..util import HttpError, http_get, http_post_json, log, read_json, write_json
from .jsonparse import parse_json_loose
from .schemas import LLM_OUTPUT_SCHEMA, to_gemini_schema

API_BASE = "https://generativelanguage.googleapis.com/v1beta"
MODEL_CACHE = CACHE_DIR / "gemini-models.json"
MAX_MODELS_TO_TRY = 4

# 分數越高越優先；刻意讓非 lite 版本排在前面（額度較寬）
MODEL_BOOST = ("flash", "2.5", "3", "pro")
MODEL_PENALTY = ("lite", "preview", "exp", "embedding", "image", "tts", "audio", "veo", "nano")


class GeminiProvider:
    name = "gemini"

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.gemini_api_key
        self.forced_model = (settings.gemini_model or "").strip()
        self.model = self.forced_model
        self.schema = to_gemini_schema(json.loads(json.dumps(LLM_OUTPUT_SCHEMA)))

    def available(self) -> bool:
        return bool(self.api_key)

    # ------------------------------------------------------------ 內部
    def _headers(self) -> dict[str, str]:
        return {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}

    def _score_model(self, name: str) -> int:
        lowered = name.lower()
        if any(bad in lowered for bad in MODEL_PENALTY if bad not in ("lite", "preview", "exp")):
            return -1
        score = 0
        for index, keyword in enumerate(MODEL_BOOST):
            if keyword in lowered:
                score += (len(MODEL_BOOST) - index) * 2
        for keyword in MODEL_PENALTY:
            if keyword in lowered:
                score -= 2
        if "latest" in lowered:
            score += 1
        return score

    def resolve_models(self) -> list[str]:
        """回傳「由優到劣」的候選模型清單（自動偵測 + 快取）。"""
        if self.forced_model:
            return [self.forced_model]

        cached = read_json(MODEL_CACHE) if MODEL_CACHE.exists() else None
        if isinstance(cached, dict) and isinstance(cached.get("models"), list):
            models = [str(entry) for entry in cached["models"] if isinstance(entry, str) and entry]
            if models:
                self.model = models[0]
                return models

        try:
            payload = http_get(
                f"{API_BASE}/models?pageSize=200",
                headers={"x-goog-api-key": self.api_key, "Accept": "application/json"},
                timeout=45,
                retries=1,
            )
            data = json.loads(payload.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 - 列模型失敗就用保守預設
            log.warning("Gemini 列出模型失敗，改用預設名稱：%s", exc)
            return ["gemini-2.5-flash"]

        scored: list[tuple[int, str]] = []
        for entry in data.get("models") or []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").removeprefix("models/")
            methods = entry.get("supportedGenerationMethods") or []
            if "generateContent" not in methods:
                continue
            score = self._score_model(name)
            if score >= 0:
                scored.append((score, name))
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        models = [name for _, name in scored] or ["gemini-2.5-flash"]

        log.info("Gemini 候選模型（由優到劣）：%s", " → ".join(models[:MAX_MODELS_TO_TRY]))
        try:
            write_json(MODEL_CACHE, {"models": models})
        except Exception:  # noqa: BLE001 - 快取失敗無妨
            pass
        self.model = models[0]
        return models

    # ------------------------------------------------------------ 調用
    def _build_body(self, system_prompt: str, user_prompt: str, with_schema: bool) -> dict[str, Any]:
        generation: dict[str, Any] = {"temperature": 0.2, "responseMimeType": "application/json"}
        if with_schema:
            generation["responseSchema"] = self.schema
        return {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": generation,
        }

    def _call(self, model: str, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        url = f"{API_BASE}/models/{model}:generateContent"
        body = self._build_body(system_prompt, user_prompt, with_schema=True)
        try:
            payload = http_post_json(url, body, headers=self._headers(), timeout=180, retries=3)
        except Exception as exc:  # noqa: BLE001 - 部分模型不支援 responseSchema
            if _is_quota_error(exc):
                raise  # 額度問題換 schema 沒意義
            log.warning("Gemini %s 帶 responseSchema 失敗，改以純 JSON 模式重試：%s", model, exc)
            body = self._build_body(system_prompt, user_prompt, with_schema=False)
            payload = http_post_json(url, body, headers=self._headers(), timeout=180, retries=2)
        return extract_json(payload)

    def enrich(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        models = self.resolve_models()[:MAX_MODELS_TO_TRY]
        last_error: Exception | None = None

        for index, model in enumerate(models):
            try:
                result = self._call(model, system_prompt, user_prompt)
                self.model = model
                if index > 0:
                    log.info("已切換到模型 %s 完成提煉", model)
                return result
            except Exception as exc:  # noqa: BLE001 - 依錯誤類型決定是否換模型
                last_error = exc
                if _is_daily_quota_error(exc) and index < len(models) - 1:
                    # 「每日額度」等也等不完 → 直接換下一個模型
                    log.warning("模型 %s 每日額度已用盡，改用 %s", model, models[index + 1])
                    continue
                raise

        raise last_error if last_error else RuntimeError("Gemini 無可用模型")


def _is_quota_error(exc: BaseException) -> bool:
    text = str(exc)
    return "429" in text or "RESOURCE_EXHAUSTED" in text


def _is_daily_quota_error(exc: BaseException) -> bool:
    # 每日額度（PerDay）等也等不完；瞬時限流才由 util 內的退避處理
    return "PerDay" in str(exc) or "per day" in str(exc).lower()


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
