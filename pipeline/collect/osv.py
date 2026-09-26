"""OSV.dev 補充查詢（選用，預設關閉）。

用於取得受影響的版本範圍，補強 GitHub Advisory 未提供的資訊。
"""

from __future__ import annotations

from ..config import Settings
from ..models import VulnItem
from ..util import http_json, log, truncate
from . import CollectResult

SOURCE = "osv"
DEFAULT_URL = "https://api.osv.dev/v1/vulns"


def _ranges_of(entry: dict) -> list[str]:
    out: list[str] = []
    for affected in entry.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        ecosystem = (pkg.get("ecosystem") or "").strip()
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        detail = f"{ecosystem}:{name}" if ecosystem else name
        events = []
        for rng in affected.get("ranges") or []:
            for event in (rng or {}).get("events") or []:
                if not isinstance(event, dict):
                    continue
                for key in ("introduced", "fixed", "last_affected"):
                    if event.get(key) and event[key] != "0":
                        events.append(f"{key} {event[key]}")
        label = f"{detail} ({truncate(' / '.join(events[:4]), 60)})" if events else detail
        if label not in out:
            out.append(label)
    return out[:8]


def apply(settings: Settings, items: list[VulnItem]) -> CollectResult:
    cfg = settings.source("osv")
    result = CollectResult(name=SOURCE, label="OSV")
    if not cfg.get("enabled", False):
        result.warnings.append("disabled")
        return result

    url = cfg.get("url") or DEFAULT_URL
    limit = max(0, int(cfg.get("max_lookups") or 25))
    candidates = [
        item
        for item in items
        if (item.vendor_advisory_id or "").upper().startswith("GHSA-") and not item.affected_packages
    ][:limit]

    enriched = 0
    failures = 0
    for item in candidates:
        osv_id = (item.vendor_advisory_id or "").strip()
        try:
            entry = http_json(f"{url}/{osv_id}", timeout=30, retries=1)
        except Exception as exc:  # noqa: BLE001 - 純加分項
            failures += 1
            log.debug("OSV 查詢失敗 %s：%s", osv_id, exc)
            continue
        if not isinstance(entry, dict):
            continue
        ranges = _ranges_of(entry)
        if ranges:
            item.affected_packages = ranges
            item.add_source(SOURCE)
            enriched += 1

    log.info("OSV：補充 %s 筆（查詢 %s，失敗 %s）", enriched, len(candidates), failures)
    result.extra["enriched"] = enriched
    result.items = []
    return result
