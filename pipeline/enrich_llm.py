"""提煉協調層：批次呼叫 LLM 並逐批驗證，任何失敗都退回規則模板。"""

from __future__ import annotations

from typing import Any

from .config import Settings
from .enrich import build_prompts, get_provider
from .enrich.fallback import apply_fallback
from .models import VulnItem
from .util import log
from .verify import apply_enrichment, verify_output


def _chunks(values: list[VulnItem], size: int) -> list[list[VulnItem]]:
    return [values[i : i + size] for i in range(0, len(values), size)]


def enrich_items(
    settings: Settings,
    items: list[VulnItem],
    provider_name: str | None = None,
) -> dict[str, Any]:
    """就地為 items 填入中文標題／摘要／處置。回傳統計資訊。"""
    stats: dict[str, Any] = {
        "llm": 0,
        "template": 0,
        "batches": 0,
        "failed_batches": 0,
        "provider": None,
        "hard_violations": [],
        "soft_violations": [],
    }
    if not items:
        return stats

    provider = get_provider(settings, provider_name)
    if provider is None:
        for item in items:
            apply_fallback(item)
            stats["template"] += 1
        log.info("提煉：未使用 LLM，全部以規則模板產出（%s 筆）", stats["template"])
        return stats

    stats["provider"] = provider.name
    limit = settings.llm_max_items or len(items)
    llm_items = items[:limit]
    tail_items = items[limit:]

    for batch in _chunks(llm_items, settings.llm_batch_size):
        stats["batches"] += 1
        by_id = {item.cve_id: item for item in batch}
        try:
            system_prompt, user_prompt = build_prompts(batch)
            raw = provider.enrich(system_prompt, user_prompt)
            accepted, hard, soft = verify_output(raw, by_id)
            stats["hard_violations"].extend(hard)
            stats["soft_violations"].extend(soft)
            applied = apply_enrichment(batch, accepted, provider.name)
            stats["llm"] += applied["llm"]
            stats["template"] += applied["template"]
        except Exception as exc:  # noqa: BLE001 - 單批失敗只影響該批
            stats["failed_batches"] += 1
            log.error("LLM 批次失敗，該批改用規則模板：%s", exc)
            for item in batch:
                apply_fallback(item)
                stats["template"] += 1

    for item in tail_items:
        apply_fallback(item)
        stats["template"] += 1

    log.info(
        "提煉：LLM %s 筆 / 模板 %s 筆（批次 %s，失敗 %s）",
        stats["llm"],
        stats["template"],
        stats["batches"],
        stats["failed_batches"],
    )
    return stats
