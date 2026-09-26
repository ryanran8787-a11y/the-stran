"""CISA KEV（Known Exploited Vulnerabilities）在野利用清單。"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from ..config import Settings
from ..models import VulnItem
from ..util import http_json, log, parse_date
from . import CollectResult

SOURCE = "cisa_kev"


def fetch_catalog(settings: Settings) -> list[dict[str, Any]]:
    cfg = settings.source("kev")
    url = cfg.get("url") or (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    payload = http_json(url, headers={"Accept": "application/json"})
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("KEV 回應格式非預期（找不到 vulnerabilities 陣列）")
    log.info("KEV 目錄：%s 筆（catalogVersion=%s）", len(vulns), payload.get("catalogVersion"))
    return vulns


def to_kev_dict(entry: dict[str, Any]) -> dict[str, Any]:
    """轉成 digest schema 的 kev 物件。"""
    return {
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "ransomware": entry.get("knownRansomwareCampaignUse"),
        "forensic_triage": entry.get("forensicTriage"),
        "name_en": entry.get("vulnerabilityName"),
        "required_action_en": entry.get("requiredAction"),
    }


def collect(settings: Settings, window_from: datetime, window_to: datetime) -> CollectResult:
    result = CollectResult(name=SOURCE, label=settings.source("kev").get("label", "CISA KEV"))
    catalog = fetch_catalog(settings)

    index: dict[str, dict[str, Any]] = {}
    for entry in catalog:
        cve_id = (entry.get("cveID") or "").strip().upper()
        if cve_id.startswith("CVE-"):
            index[cve_id] = entry
    result.extra["index"] = index
    result.extra["catalog_size"] = len(catalog)

    # 只挑「本窗口（含回看天數）新增」的 KEV 項目；其餘僅作為在野標記。
    cutoff = (window_to.date() - timedelta(days=max(0, settings.kev_lookback_days)))
    for cve_id, entry in index.items():
        added = parse_date(entry.get("dateAdded"))
        if added is None or added < cutoff:
            continue
        item = VulnItem(
            cve_id=cve_id,
            vendor=(entry.get("vendorProject") or "").strip(),
            product=(entry.get("product") or "").strip(),
            in_the_wild=True,
            kev=to_kev_dict(entry),
            description_en=(entry.get("shortDescription") or "").strip(),
            published=entry.get("dateAdded"),
            modified=entry.get("dateAdded"),
        )
        item.merge_cwes([c for c in (entry.get("cwes") or []) if isinstance(c, str)])
        item.add_source(SOURCE)
        item.add_reference(
            "CISA KEV",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        )
        item.add_reference("NVD", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        note = entry.get("notes") or ""
        first_note = note.split(";")[0].strip()
        if first_note.startswith("http"):
            item.add_reference("廠商公告", first_note)
        item.auto_tags()
        result.items.append(item)

    log.info("KEV 窗口內新增：%s 筆（cutoff=%s）", len(result.items), cutoff)
    return result
