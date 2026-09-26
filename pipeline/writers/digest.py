"""輸出：每日 JSON 檔與歷史索引。"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Any

from ..config import Settings
from ..models import VulnItem
from ..util import log, read_json, to_iso, write_json

SCHEMA_VERSION = 1

INDEX_ITEM_KEYS = ("date", "kept", "kev", "critical", "in_the_wild", "generated_at", "generated_by", "top")


def build_digest(
    report_date: date,
    window_from: datetime,
    window_to: datetime,
    items: list[VulnItem],
    counts: dict[str, int],
    scanned: int,
    sources: list[dict[str, Any]],
    vendor_watch: list[dict[str, Any]],
    generated_by: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "date": report_date.isoformat(),
        "generated_at": to_iso(datetime.now(tz=window_to.tzinfo)) or "",
        "generated_by": generated_by,
        "window": {"from": to_iso(window_from) or "", "to": to_iso(window_to) or ""},
        "stats": {
            "scanned": int(scanned),
            "kept": int(counts.get("kept", len(items))),
            "kev": int(counts.get("kev", 0)),
            "critical": int(counts.get("critical", 0)),
            "in_the_wild": int(counts.get("in_the_wild", 0)),
            "sources_ok": sum(1 for s in sources if s.get("ok")),
            "sources_failed": sum(1 for s in sources if not s.get("ok")),
        },
        "sources": sources,
        "items": [item.to_dict() for item in items],
        "vendor_watch": vendor_watch,
    }


def digest_path(settings: Settings, report_date: date) -> Path:
    return Path(settings.data_dir) / "daily" / f"{report_date.isoformat()}.json"


def index_path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "index.json"


def write_digest(settings: Settings, digest: dict[str, Any]) -> Path:
    path = digest_path(settings, date.fromisoformat(digest["date"]))
    write_json(path, digest)
    log.info("已寫入 %s（%s 筆）", path, len(digest.get("items") or []))
    return path


def _index_entry(digest: dict[str, Any]) -> dict[str, Any]:
    items = digest.get("items") or []
    stats = digest.get("stats") or {}
    return {
        "date": digest.get("date"),
        "kept": stats.get("kept", len(items)),
        "kev": stats.get("kev", 0),
        "critical": stats.get("critical", 0),
        "in_the_wild": stats.get("in_the_wild", 0),
        "generated_at": digest.get("generated_at"),
        "generated_by": digest.get("generated_by"),
        "top": [str(i.get("title_short") or i.get("cve_id") or "") for i in items[:3]],
    }


def rebuild_index(settings: Settings) -> dict[str, Any]:
    """掃描 data/daily/*.json 重建索引（自我修復，不依賴既有 index.json）。"""
    daily_dir = Path(settings.data_dir) / "daily"
    entries: list[dict[str, Any]] = []
    if daily_dir.exists():
        for path in sorted(daily_dir.glob("*.json")):
            try:
                digest = read_json(path)
                if isinstance(digest, dict):
                    entries.append(_index_entry(digest))
            except Exception as exc:  # noqa: BLE001 - 壞檔不該讓建索引失敗
                log.warning("略過無法解析的日報 %s：%s", path.name, exc)

    by_date = {entry["date"]: entry for entry in entries if entry.get("date")}
    reports = [by_date[key] for key in sorted(by_date, reverse=True)]
    index = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": to_iso(datetime.now(tz=None)) or datetime.now().isoformat(timespec="seconds"),
        "total": len(reports),
        "reports": reports,
    }
    write_json(index_path(settings), index)
    log.info("索引已更新：%s 期", len(reports))
    return index
