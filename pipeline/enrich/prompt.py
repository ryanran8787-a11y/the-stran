"""Prompt 組裝：讀取 prompts/daily_digest.md 並注入當日資料。"""

from __future__ import annotations

import json
from typing import Any

from ..config import PROMPT_PATH
from ..models import VulnItem

FALLBACK_TEMPLATE = (
    "你是資深資安情報分析師，請把輸入的漏洞資料改寫成正體中文日報，"
    "只能使用輸入中既有的資訊，不得新增 CVE 編號或分數。\n\n輸入：\n{{ITEMS_JSON}}"
)


def load_template() -> str:
    if PROMPT_PATH.exists():
        return PROMPT_PATH.read_text(encoding="utf-8")
    return FALLBACK_TEMPLATE


def items_json(items: list[VulnItem]) -> str:
    payload = [item.llm_payload() for item in items]
    return json.dumps(payload, ensure_ascii=False, indent=1)


def build_prompts(items: list[VulnItem]) -> tuple[str, str]:
    """回傳 (system_prompt, user_prompt)。

    模板以 `---` 分隔線切成「系統指令」與「資料」兩段：
    第一段之前的內容作為 system，其餘（含 {{ITEMS_JSON}} 注入後）作為 user。
    """
    template = load_template()
    injected = template.replace("{{ITEMS_JSON}}", items_json(items))
    marker = "\n## 輸入"
    if marker in injected:
        head, _, tail = injected.partition(marker)
        system = head.strip()
        user = marker.strip() + "\n" + tail
        return system, user
    return "你是資深資安情報分析師，只輸出符合結構的 JSON。", injected


def schema_hint() -> dict[str, Any]:
    """給沒有原生結構化輸出時的提示用（純文字說明）。"""
    return {
        "items": [
            {
                "cve_id": "CVE-YYYY-NNNNN",
                "title_short": "廠商 產品 NNNNN×9.8 在野",
                "title_full": "廠商 產品 CVE-YYYY-NNNNN · CVSS 9.8 · 在野利用",
                "tags": ["RCE"],
                "summary_zh": "≤80字",
                "impact_zh": "≤40字",
                "action_zh": "≤50字",
            }
        ]
    }
