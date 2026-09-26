"""風險評分與篩選（規則層：LLM 不參與「要不要收錄」的判斷）。"""

from __future__ import annotations

from .models import VulnItem
from .util import log

# 第二階段（EPSS 加分）要求的基本 CVSS 門檻，避免低分但 EPSS 稍高的雜訊灌入
EPSS_CVSS_FLOOR = 7.0


def risk_score(item: VulnItem) -> float:
    """排序用綜合分數，不是 CVSS 的替代品。"""
    score = float(item.cvss_score or 0.0)
    if item.kev:
        score += 3.0
    elif item.in_the_wild:
        score += 2.0
    if item.epss_score:
        score += item.epss_score * 2.0
    return round(score, 3)


def passes_filter(item: VulnItem, min_cvss: float, min_epss: float) -> tuple[bool, str]:
    """回傳 (是否收錄, 原因)。"""
    if item.kev:
        return True, "kev"
    if item.in_the_wild:
        return True, "in_the_wild"
    if item.cvss_score is not None and item.cvss_score >= min_cvss:
        return True, "cvss"
    if (
        item.epss_score is not None
        and item.epss_score >= min_epss
        and (item.cvss_score or 0.0) >= EPSS_CVSS_FLOOR
    ):
        return True, "epss"
    return False, "below_threshold"


def select(items: list[VulnItem], min_cvss: float, min_epss: float) -> tuple[list[VulnItem], dict[str, int]]:
    kept: list[VulnItem] = []
    reasons: dict[str, int] = {}
    for item in items:
        ok, reason = passes_filter(item, min_cvss, min_epss)
        if not ok:
            continue
        reasons[reason] = reasons.get(reason, 0) + 1
        item.risk_score = risk_score(item)
        kept.append(item)

    kept.sort(
        key=lambda i: (
            0 if i.kev else 1,
            0 if i.in_the_wild else 1,
            -(i.risk_score or 0.0),
            -(i.cvss_score or 0.0),
            i.cve_id,
        )
    )
    for index, item in enumerate(kept, start=1):
        item.rank = index

    counts: dict[str, int] = {
        "kept": len(kept),
        "critical": sum(1 for i in kept if i.severity == "CRITICAL"),
        "kev": sum(1 for i in kept if i.kev),
        "in_the_wild": sum(1 for i in kept if i.in_the_wild),
    }
    counts.update({f"reason_{k}": v for k, v in reasons.items()})
    log.info(
        "篩選：%s 筆 → 收錄 %s 筆（KEV %s / 在野 %s / CRITICAL %s）",
        len(items),
        counts["kept"],
        counts["kev"],
        counts["in_the_wild"],
        counts["critical"],
    )
    return kept, counts
