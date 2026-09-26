"""跨來源正規化：以 CVE ID 為鍵合併去重，並套用 KEV 在野標記。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .collect import CollectResult
from .models import VulnItem, severity_for, tags_from_cwes
from .util import log, parse_iso


def _earliest(a: str | None, b: str | None) -> str | None:
    if not a:
        return b
    if not b:
        return a
    da, db = parse_iso(a), parse_iso(b)
    if da is None:
        return b
    if db is None:
        return a
    return a if da <= db else b


def _latest(a: str | None, b: str | None) -> str | None:
    if not a:
        return b
    if not b:
        return a
    da, db = parse_iso(a), parse_iso(b)
    if da is None:
        return b
    if db is None:
        return a
    return a if da >= db else b


def merge_into(target: VulnItem, incoming: VulnItem) -> None:
    """把 incoming 的資訊併入 target（target 為較高優先序來源）。"""
    if not target.vendor and incoming.vendor:
        target.vendor = incoming.vendor
    if not target.product and incoming.product:
        target.product = incoming.product
    if not target.vendor_advisory_id and incoming.vendor_advisory_id:
        target.vendor_advisory_id = incoming.vendor_advisory_id

    if target.cvss_score is None and incoming.cvss_score is not None:
        target.cvss_score = incoming.cvss_score
        target.cvss_version = incoming.cvss_version
        target.cvss_vector = incoming.cvss_vector

    if len(incoming.description_en or "") > len(target.description_en or ""):
        target.description_en = incoming.description_en

    if incoming.kev and not target.kev:
        target.kev = dict(incoming.kev)
    if incoming.in_the_wild:
        target.in_the_wild = True

    target.merge_cwes(incoming.cwes)
    target.merge_tags(incoming.tags)
    target.merge_tags(tags_from_cwes(incoming.cwes))

    for package in incoming.affected_packages:
        if package not in target.affected_packages:
            target.affected_packages.append(package)

    target.published = _earliest(target.published, incoming.published)
    target.modified = _latest(target.modified, incoming.modified)
    target.is_new = target.is_new or incoming.is_new

    for ref in incoming.references:
        target.add_reference(ref.get("name", "參考"), ref.get("url", ""))

    for source in incoming.sources:
        target.add_source(source)


def apply_kev_index(items: list[VulnItem], kev_index: dict[str, dict[str, Any]]) -> int:
    """用完整 KEV 目錄為所有項目補上在野標記（即使該筆不是今天新增）。"""
    marked = 0
    for item in items:
        entry = kev_index.get(item.cve_id)
        if not entry:
            continue
        if not item.kev:
            item.kev = {
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "ransomware": entry.get("knownRansomwareCampaignUse"),
                "forensic_triage": entry.get("forensicTriage"),
                "name_en": entry.get("vulnerabilityName"),
                "required_action_en": entry.get("requiredAction"),
            }
        if not item.in_the_wild:
            item.in_the_wild = True
            marked += 1
        if not item.vendor and entry.get("vendorProject"):
            item.vendor = str(entry["vendorProject"]).strip()
        if not item.product and entry.get("product"):
            item.product = str(entry["product"]).strip()
        if not item.description_en and entry.get("shortDescription"):
            item.description_en = str(entry["shortDescription"]).strip()
        item.add_source("cisa_kev")
    return marked


def normalize(
    results: list[CollectResult],
    kev_index: dict[str, dict[str, Any]],
    window_from: datetime,
    window_to: datetime,
) -> tuple[list[VulnItem], dict[str, int], list[str]]:
    """合併所有來源。回傳 (items, 計數統計, warnings)。"""
    warnings: list[str] = []
    merged: dict[str, VulnItem] = {}
    scanned = 0

    for result in results:
        if not result.ok and not result.items:
            continue
        for item in result.items:
            scanned += 1
            existing = merged.get(item.cve_id)
            if existing is None:
                merged[item.cve_id] = item
            else:
                merge_into(existing, item)
        for warning in result.warnings:
            warnings.append(f"{result.name}: {warning}")

    items = list(merged.values())
    marked = apply_kev_index(items, kev_index)

    for item in items:
        item.severity = severity_for(item.cvss_score, item.severity)
        if not item.tags:
            item.auto_tags()

    log.info(
        "正規化：原始 %s 筆 → 去重後 %s 筆（KEV 補標記 %s 筆）",
        scanned,
        len(items),
        marked,
    )
    stats = {"scanned": scanned, "unique": len(items), "kev_marked": marked}
    return items, stats, warnings
