"""提煉協調層：批次呼叫 LLM 並逐批驗證。

強化點：
  * 單批例外失敗 → 該批走規則模板
  * 單批違規率過高（例如輸出被截斷）→ 把「未通過的項目」拆半重試，最多兩層
  * 最終統計改以項目實際狀態計算，不重複計數
"""

from __future__ import annotations

from typing import Any

from .config import Settings
from .enrich import build_prompts, get_provider
from .enrich.fallback import apply_fallback
from .models import VulnItem
from .util import log
from .verify import apply_enrichment, verify_output

MAX_RETRY_DEPTH = 2
MIN_RETRY_BATCH = 2
RETRY_TRIGGER_RATIO = 0.85


def _chunks(values: list[VulnItem], size: int) -> list[list[VulnItem]]:
    return [values[i : i + size] for i in range(0, len(values), size)]


def enrich_items(
    settings: Settings,
    items: list[VulnItem],
    provider_name: str | None = None,
) -> dict[str, Any]:
    """就地為 items 填入中文標題／摘要／處置。回傳統計資訊。"""
    stats: dict[str, Any] = {
        "provider": None,
        "batches": 0,
        "failed_batches": 0,
        "retries": 0,
        "hard_violations": [],
        "soft_violations": [],
        "llm": 0,
        "template": 0,
    }
    if not items:
        return stats

    provider = get_provider(settings, provider_name)
    if provider is None:
        for item in items:
            apply_fallback(item)
        stats["template"] = len(items)
        log.info("提煉：未使用 LLM，全部以規則模板產出（%s 筆）", stats["template"])
        return stats

    stats["provider"] = provider.name

    def process(batch: list[VulnItem], depth: int) -> None:
        if not batch:
            return
        stats["batches"] += 1
        by_id = {item.cve_id: item for item in batch}
        accepted: dict[str, dict[str, Any]] = {}
        try:
            system_prompt, user_prompt = build_prompts(batch)
            raw = provider.enrich(system_prompt, user_prompt)
            accepted, hard, soft = verify_output(raw, by_id)
            stats["hard_violations"].extend(hard)
            stats["soft_violations"].extend(soft)
            apply_enrichment(batch, accepted, provider.name)
        except Exception as exc:  # noqa: BLE001 - 單批失敗只影響該批
            stats["failed_batches"] += 1
            log.error("LLM 批次失敗，該批改用規則模板：%s", exc)
            for item in batch:
                apply_fallback(item)
            return

        pending = [item for item in batch if item.generated_by != provider.name]
        should_retry = (
            bool(pending)
            and len(batch) > MIN_RETRY_BATCH
            and depth < MAX_RETRY_DEPTH
            and len(accepted) < len(batch) * RETRY_TRIGGER_RATIO
        )
        if not should_retry:
            return

        # 違規率過高通常是輸出被截斷 → 拆半重試，避免整批白白浪費
        stats["retries"] += 1
        log.warning(
            "批次違規率過高（通過 %s/%s），拆半重試（depth=%s、待重試 %s 筆）",
            len(accepted),
            len(batch),
            depth,
            len(pending),
        )
        mid = len(pending) // 2
        process(pending[:mid], depth + 1)
        process(pending[mid:], depth + 1)

    limit = settings.llm_max_items or len(items)
    llm_items = items[:limit]
    tail_items = items[limit:]

    for batch in _chunks(llm_items, settings.llm_batch_size):
        process(batch, 0)

    for item in tail_items:
        apply_fallback(item)

    stats["llm"] = sum(1 for item in items if item.generated_by == provider.name)
    stats["template"] = len(items) - stats["llm"]

    log.info(
        "提煉：%s 產出 %s 筆 / 模板 %s 筆（批次 %s，失敗 %s，重試 %s）",
        provider.name,
        stats["llm"],
        stats["template"],
        stats["batches"],
        stats["failed_batches"],
        stats["retries"],
    )
    return stats
