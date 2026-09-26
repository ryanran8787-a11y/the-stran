"""LLM 輸出驗證器 —— 防幻覺的核心。

規則：
  * 硬性違規 → 丟棄該筆 LLM 文字，改用規則模板（寧可無聊，不可錯誤）
  * 軟性違規 → 修剪後仍採用

硬性：未知／重複的 CVE 編號、標題缺少序號、標題分數與來源不符、標題缺少在野標記、空標題
軟性：標籤不在封閉清單、欄位過長、title_full 缺失
"""

from __future__ import annotations

from typing import Any

from .enrich.fallback import apply_fallback, build_title_full
from .models import ALLOWED_TAGS, VulnItem
from .util import log, truncate

MAX_SUMMARY = 120
MAX_IMPACT = 60
MAX_ACTION = 90
MAX_TITLE = 60


def _score_text(item: VulnItem) -> str:
    return "" if item.cvss_score is None else f"{float(item.cvss_score):.1f}"


def verify_entry(entry: Any, item: VulnItem) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    """驗證單筆。回傳 (清理後的欄位 或 None, 硬性違規, 軟性違規)。"""
    hard: list[str] = []
    soft: list[str] = []
    if not isinstance(entry, dict):
        return None, ["entry_not_object"], soft

    def text(key: str) -> str:
        value = entry.get(key)
        return value.strip() if isinstance(value, str) else ""

    title_short = text("title_short")
    title_full = text("title_full")
    summary = text("summary_zh")
    impact = text("impact_zh")
    action = text("action_zh")

    if not title_short:
        hard.append("empty_title_short")
    else:
        if item.tail() not in title_short:
            hard.append(f"title_missing_tail:{item.tail()}")
        expected_score = _score_text(item)
        if expected_score and expected_score not in title_short:
            hard.append(f"title_score_mismatch:{expected_score}")
        if item.in_the_wild and "在野" not in title_short:
            hard.append("title_missing_in_the_wild")
        if len(title_short) > MAX_TITLE:
            soft.append("title_too_long")
            title_short = truncate(title_short, MAX_TITLE)

    raw_tags = entry.get("tags")
    tags: list[str] = []
    if isinstance(raw_tags, list):
        for tag in raw_tags:
            if isinstance(tag, str) and tag in ALLOWED_TAGS:
                if tag not in tags:
                    tags.append(tag)
            else:
                soft.append(f"unknown_tag:{tag}")
    elif raw_tags is not None:
        soft.append("tags_not_array")

    if len(summary) > MAX_SUMMARY:
        soft.append("summary_too_long")
        summary = truncate(summary, MAX_SUMMARY)
    if len(impact) > MAX_IMPACT:
        soft.append("impact_too_long")
        impact = truncate(impact, MAX_IMPACT)
    if len(action) > MAX_ACTION:
        soft.append("action_too_long")
        action = truncate(action, MAX_ACTION)
    if not title_full:
        soft.append("missing_title_full")
        title_full = build_title_full(item)

    if hard:
        return None, hard, soft
    return (
        {
            "title_short": title_short,
            "title_full": title_full,
            "tags": tags,
            "summary_zh": summary,
            "impact_zh": impact,
            "action_zh": action,
        },
        hard,
        soft,
    )


def verify_output(
    raw: Any,
    by_id: dict[str, VulnItem],
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    """驗證整批 LLM 輸出。回傳 (接受的欄位, 硬性違規, 軟性違規)。"""
    hard_all: list[str] = []
    soft_all: list[str] = []

    if not isinstance(raw, dict):
        return {}, ["output_not_object"], soft_all
    entries = raw.get("items")
    if not isinstance(entries, list):
        return {}, ["output_missing_items"], soft_all

    accepted: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for entry in entries:
        cve_id = (entry or {}).get("cve_id") if isinstance(entry, dict) else None
        cve_id = cve_id.strip().upper() if isinstance(cve_id, str) else ""
        if not cve_id:
            hard_all.append("missing_cve_id")
            continue
        if cve_id not in by_id:
            # 最嚴重的幻覺：LLM 自己生了一個不存在的 CVE
            hard_all.append(f"unknown_cve:{cve_id}")
            continue
        if cve_id in seen:
            hard_all.append(f"duplicate_cve:{cve_id}")
            continue
        seen.add(cve_id)
        fields, hard, soft = verify_entry(entry, by_id[cve_id])
        hard_all.extend(f"{cve_id}:{reason}" for reason in hard)
        soft_all.extend(f"{cve_id}:{reason}" for reason in soft)
        if fields is not None:
            accepted[cve_id] = fields

    missing = sorted(set(by_id) - set(accepted))
    if missing:
        soft_all.append(f"missing_items:{len(missing)}")

    log.info(
        "驗證：接受 %s/%s 筆，硬性違規 %s 項、軟性違規 %s 項",
        len(accepted),
        len(by_id),
        len(hard_all),
        len(soft_all),
    )
    return accepted, hard_all, soft_all


def apply_enrichment(
    items: list[VulnItem],
    accepted: dict[str, dict[str, Any]],
    provider_name: str,
) -> dict[str, int]:
    """把驗證通過的欄位寫回項目，其餘一律走規則模板。"""
    stats = {"llm": 0, "template": 0}
    for item in items:
        fields = accepted.get(item.cve_id)
        if fields:
            item.title_short = fields["title_short"]
            item.title_full = fields["title_full"]
            item.summary_zh = fields["summary_zh"]
            item.impact_zh = fields["impact_zh"]
            item.action_zh = fields["action_zh"]
            if fields["tags"]:
                item.tags = fields["tags"]
            item.generated_by = provider_name
            if not (item.summary_zh and item.impact_zh and item.action_zh):
                apply_fallback(item)
            stats["llm"] += 1
        else:
            apply_fallback(item)
            stats["template"] += 1
    return stats
