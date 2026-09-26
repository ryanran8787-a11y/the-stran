"""EPSS（Exploit Prediction Scoring System）分數補充。

這是「後處理」而非獨立來源：必須先有候選 CVE 清單才能批次查詢。
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from ..config import Settings
from ..models import VulnItem
from ..util import http_json, log
from . import CollectResult

SOURCE = "epss"
DEFAULT_URL = "https://api.first.org/data/v1/epss"


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[i : i + size] for i in range(0, len(values), size)]


def apply(settings: Settings, items: list[VulnItem]) -> CollectResult:
    cfg = settings.source("epss")
    result = CollectResult(name=SOURCE, label=cfg.get("label", "EPSS"))
    if not cfg.get("enabled", False):
        result.ok = True
        result.warnings.append("disabled")
        return result

    cve_ids = sorted({item.cve_id for item in items if item.cve_id})
    if not cve_ids:
        result.warnings.append("no candidate CVEs")
        return result

    url = cfg.get("url") or DEFAULT_URL
    batch = max(1, min(int(cfg.get("batch") or 90), 500))
    by_id: dict[str, dict[str, Any]] = {}
    failed = 0
    for group in _chunks(cve_ids, batch):
        params = urllib.parse.urlencode({"cve": ",".join(group)})
        try:
            payload = http_json(f"{url}?{params}", timeout=45, retries=2)
        except Exception as exc:  # noqa: BLE001 - EPSS 只是加分項，失敗不影響日報
            failed += 1
            log.warning("EPSS 批次失敗（略過）：%s", exc)
            continue
        for row in (payload or {}).get("data") or []:
            cve = (row.get("cve") or "").upper()
            if cve:
                by_id[cve] = row

    scored = 0
    for item in items:
        row = by_id.get(item.cve_id)
        if not row:
            continue
        try:
            item.epss_score = round(float(row.get("epss")), 5)
            item.epss_percentile = round(float(row.get("percentile")), 5)
            scored += 1
        except (TypeError, ValueError):
            continue

    result.extra["scored"] = scored
    log.info("EPSS：%s/%s 筆取得分數（失敗批次 %s）", scored, len(cve_ids), failed)
    if failed:
        result.warnings.append(f"{failed} batch(es) failed")
        if failed * batch >= len(cve_ids):
            result.ok = False
            result.error = "all EPSS batches failed"
    return result
