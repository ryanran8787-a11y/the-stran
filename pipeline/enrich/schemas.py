"""LLM 輸出結構定義，以及各家 API 的格式轉換。"""

from __future__ import annotations

from typing import Any

from ..models import ALLOWED_TAGS

# 廠商中立版（標準 JSON Schema 小寫）
LLM_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "cve_id": {"type": "string"},
                    "title_short": {"type": "string"},
                    "title_full": {"type": "string"},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string", "enum": list(ALLOWED_TAGS)},
                    },
                    "summary_zh": {"type": "string"},
                    "impact_zh": {"type": "string"},
                    "action_zh": {"type": "string"},
                },
                "required": [
                    "cve_id",
                    "title_short",
                    "title_full",
                    "tags",
                    "summary_zh",
                    "impact_zh",
                    "action_zh",
                ],
            },
        }
    },
    "required": ["items"],
}

PROPERTY_ORDER = [
    "cve_id",
    "title_short",
    "title_full",
    "tags",
    "summary_zh",
    "impact_zh",
    "action_zh",
]


# Gemini response_schema 只支援 OpenAPI 3.0 的子集：
# 不支援 additionalProperties / required（未標 nullable 的欄位即視為必填）。
GEMINI_SUPPORTED_KEYS = ("description", "format", "nullable", "enum", "required", "title")


def to_gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """轉成 Gemini responseSchema（型別需大寫，且需剔除不支援的關鍵字）。"""
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "type" and isinstance(value, str):
            out["type"] = value.upper()
        elif key == "properties" and isinstance(value, dict):
            out["properties"] = {k: to_gemini_schema(v) for k, v in value.items()}
        elif key == "items" and isinstance(value, dict):
            out["items"] = to_gemini_schema(value)
        elif key == "enum" and isinstance(value, list):
            out["enum"] = value
        elif key in GEMINI_SUPPORTED_KEYS:
            if key == "required" and not isinstance(value, list):
                continue
            out[key] = value
    # Gemini 支援 propertyOrdering，可讓輸出更穩定
    if isinstance(out.get("properties"), dict) and set(out["properties"]) >= set(PROPERTY_ORDER):
        out["propertyOrdering"] = PROPERTY_ORDER
    return out


def to_openai_strict(schema: dict[str, Any]) -> dict[str, Any]:
    """OpenAI strict 模式要求：所有屬性都必須列在 required、且明確 additionalProperties=false。"""
    if schema.get("type") == "object":
        props = schema.get("properties") or {}
        schema["required"] = list(props.keys())
        schema["additionalProperties"] = False
        schema["properties"] = {k: to_openai_strict(v) for k, v in props.items()}
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        schema["items"] = to_openai_strict(schema["items"])
    return schema
