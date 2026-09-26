"""寬鬆 JSON 擷取（LLM 回應常被 code fence 或說明文字包住）。"""

from __future__ import annotations

import json
from typing import Any


def parse_json_loose(text: str) -> dict[str, Any]:
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        parts = cleaned.split("```")
        if len(parts) >= 3:
            cleaned = parts[1]
        if cleaned.lstrip().lower().startswith("json"):
            cleaned = cleaned.lstrip()[4:]
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"回應不是合法 JSON：{cleaned[:200]}")
    return json.loads(cleaned[start : end + 1])
