"""LLM 提煉子套件：結構化輸出、Prompt 組裝、規則模板 fallback。"""

from __future__ import annotations

from typing import Any

from ..config import Settings
from ..util import log
from .fallback import apply_fallback
from .prompt import build_prompts
from .schemas import LLM_OUTPUT_SCHEMA

PROVIDER_NAMES = ("gemini", "openai", "claude")


def get_provider(settings: Settings, name: str | None = None) -> Any:
    """依設定取得 provider；不可用或未設定則回傳 None。"""
    chosen = (name or settings.llm_provider or "gemini").lower()
    if chosen in ("none", "off", "template"):
        return None
    try:
        if chosen == "gemini":
            from .gemini import GeminiProvider

            provider = GeminiProvider(settings)
        elif chosen == "openai":
            from .openai import OpenAIProvider

            provider = OpenAIProvider(settings)
        elif chosen == "claude":
            from .claude import ClaudeProvider

            provider = ClaudeProvider(settings)
        else:
            log.warning("未知的 LLM provider：%s", chosen)
            return None
    except Exception as exc:  # noqa: BLE001 - provider 匯入/初始化失敗不應中斷
        log.error("LLM provider %s 初始化失敗：%s", chosen, exc)
        return None

    if not provider.available():
        log.warning("LLM provider %s 未設定 API key，改用規則模板", chosen)
        return None
    return provider


__all__ = [
    "LLM_OUTPUT_SCHEMA",
    "PROVIDER_NAMES",
    "apply_fallback",
    "build_prompts",
    "get_provider",
]
