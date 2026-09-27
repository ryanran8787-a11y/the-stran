"""NVD 收集器：優先使用官方 gzip 資料檔（免 key、無限流），失敗才退回 API。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import CACHE_DIR, Settings
from ..models import VulnItem, severity_for
from ..util import (
    RateLimiter,
    http_get,
    http_json,
    log,
    nvd_datetime,
    parse_iso,
    to_iso,
    write_json,
)
from . import CollectResult
from .nvd_parse import parse_cve_record

SOURCE = "nvd"
DEFAULT_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"


def _parse_records(vulnerabilities: list[Any]) -> list[VulnItem]:
    items: list[VulnItem] = []
    for entry in vulnerabilities or []:
        record = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(record, dict):
            continue
        item = parse_cve_record(record)
        if item is not None:
            items.append(item)
    return items


def filter_window(items: list[VulnItem], window_from: datetime, window_to: datetime) -> list[VulnItem]:
    """只保留窗口內「新發布」或「有更新」的項目。"""
    out: list[VulnItem] = []
    for item in items:
        published = parse_iso(item.published)
        modified = parse_iso(item.modified)
        if published is not None and window_from <= published < window_to:
            item.is_new = True
            out.append(item)
        elif modified is not None and window_from <= modified < window_to:
            item.is_new = False
            out.append(item)
    return out


def fetch_meta(feed_base: str) -> dict[str, Any]:
    """取 .meta 作為「上游是否有變動」的可觀測訊號。"""
    try:
        raw = http_get(f"{feed_base}/nvdcve-2.0-modified.meta", timeout=30, retries=1)
        meta: dict[str, Any] = {}
        for line in raw.decode("utf-8", "replace").splitlines():
            key, _, value = line.partition(":")
            if key.strip():
                meta[key.strip()] = value.strip()
        return meta
    except Exception as exc:  # noqa: BLE001 - 純觀測用途
        log.debug("NVD meta 取得失敗（可忽略）：%s", exc)
        return {}


def fetch_feed(feed_base: str) -> list[VulnItem]:
    url = f"{feed_base}/nvdcve-2.0-modified.json.gz"
    log.info("NVD：下載 gzip 資料檔 %s", url)
    raw = http_get(url, timeout=180, retries=2)
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        snippet = raw[:200].decode("utf-8", "replace").replace("\n", " ")
        raise ValueError(f"NVD feed 不是 JSON（{exc.msg}）：{snippet}") from exc
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("NVD feed 格式非預期")
    log.info("NVD feed：解析 %s 筆原始記錄", len(vulns))
    return _parse_records(vulns)


def fetch_api(settings: Settings, window_from: datetime, window_to: datetime) -> list[VulnItem]:
    cfg = settings.source("nvd")
    api = cfg.get("api") or DEFAULT_API
    max_pages = int(cfg.get("max_api_pages") or 12)
    headers: dict[str, str] = {"Accept": "application/json"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    limiter = RateLimiter(0.7 if settings.nvd_api_key else 6.5)

    items: list[VulnItem] = []
    start_index = 0
    page_size = 2000
    for page in range(1, max_pages + 1):
        limiter.wait()
        params = (
            f"lastModStartDate={nvd_datetime(window_from)}"
            f"&lastModEndDate={nvd_datetime(window_to)}"
            f"&resultsPerPage={page_size}&startIndex={start_index}"
        )
        log.info("NVD API：第 %s 頁（startIndex=%s）", page, start_index)
        payload = http_json(f"{api}?{params}", headers=headers, timeout=90)
        vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(vulns, list):
            raise ValueError("NVD API 格式非預期")
        items.extend(_parse_records(vulns))
        total = int(payload.get("totalResults") or 0)
        start_index += page_size
        if start_index >= total or not vulns:
            break
    log.info("NVD API：取得 %s 筆", len(items))
    return items


def fetch_by_cve(settings: Settings, cve_id: str) -> VulnItem | None:
    """單筆 NVD API 查詢（cveId），用於補齊缺失欄位。"""
    cfg = settings.source("nvd")
    api = cfg.get("api") or DEFAULT_API
    headers: dict[str, str] = {"Accept": "application/json"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    payload = http_json(f"{api}?cveId={cve_id}&resultsPerPage=1", headers=headers, timeout=60)
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not vulns:
        return None
    record = vulns[0].get("cve") if isinstance(vulns[0], dict) else None
    return parse_cve_record(record) if isinstance(record, dict) else None


def fill_missing(settings: Settings, items: list[VulnItem], cap: int | None = None) -> int:
    """補齊「缺 CVSS / 缺廠商產品」的項目。

    成因：KEV 項目若不在 NVD 的 modified 資料檔內（例如前兩天改的），
    就只有 KEV 來源，沒有分數與產品資訊 → 日報會顯示「CVSS None」。
    這裡用 NVD API 逐筆查詢補齊，並對節流與失敗做防護。
    """
    if not settings.source_enabled("nvd"):
        return 0
    targets = [
        item
        for item in items
        if item.cvss_score is None or not item.vendor or not item.product
    ]
    if not targets:
        return 0

    if cap is None:
        cap = 30 if settings.nvd_api_key else 8
    targets = targets[:max(0, cap)]

    limiter = RateLimiter(0.7 if settings.nvd_api_key else 6.5)
    filled = 0
    for item in targets:
        limiter.wait()
        try:
            parsed = fetch_by_cve(settings, item.cve_id)
        except Exception as exc:  # noqa: BLE001 - 補查失敗不影響日報
            log.warning("NVD 補查失敗 %s：%s", item.cve_id, exc)
            continue
        if parsed is None:
            continue

        changed = False
        if item.cvss_score is None and parsed.cvss_score is not None:
            item.cvss_score = parsed.cvss_score
            item.cvss_version = parsed.cvss_version
            item.cvss_vector = parsed.cvss_vector
            item.severity = severity_for(item.cvss_score, parsed.severity)
            changed = True
        if not item.vendor and parsed.vendor:
            item.vendor = parsed.vendor
            changed = True
        if not item.product and parsed.product:
            item.product = parsed.product
            changed = True
        if not item.description_en and parsed.description_en:
            item.description_en = parsed.description_en
            changed = True
        if parsed.cwes:
            before = len(item.cwes)
            item.merge_cwes(parsed.cwes)
            changed = changed or len(item.cwes) > before
        if parsed.tags:
            item.merge_tags(parsed.tags)
        if not item.published and parsed.published:
            item.published = parsed.published
        if not item.modified and parsed.modified:
            item.modified = parsed.modified
        for ref in parsed.references:
            item.add_reference(ref["name"], ref["url"])
        item.add_source("nvd")
        if changed:
            filled += 1

    log.info("NVD 補查：%s/%s 筆補齊缺失欄位", filled, len(targets))
    return filled


def collect(settings: Settings, window_from: datetime, window_to: datetime) -> CollectResult:
    cfg = settings.source("nvd")
    result = CollectResult(name=SOURCE, label=cfg.get("label", "NVD"))
    feed_base = cfg.get("feed_base") or DEFAULT_FEED_BASE

    meta = fetch_meta(feed_base)
    if meta:
        result.extra["meta"] = meta
        write_json(CACHE_DIR / "nvd-modified-meta.json", meta)
        log.info("NVD meta lastModifiedDate=%s", meta.get("lastModifiedDate"))

    raw: list[VulnItem] | None = None
    if cfg.get("prefer_feed", True):
        try:
            raw = fetch_feed(feed_base)
        except Exception as exc:  # noqa: BLE001 - 改走 API
            log.warning("NVD gzip 資料檔失敗，改用 API：%s", exc)
            result.warnings.append(f"feed failed: {exc}")
            raw = None
        if raw is not None and not raw:
            log.warning("NVD gzip 資料檔解析出 0 筆，改用 API 驗證")
            result.warnings.append("feed returned 0 records")
            raw = None

    if raw is None:
        raw = fetch_api(settings, window_from, window_to)

    result.items = filter_window(raw, window_from, window_to)
    result.extra["raw_count"] = len(raw)
    result.extra["meta_last_modified"] = meta.get("lastModifiedDate")
    log.info(
        "NVD：原始 %s 筆 → 窗口內 %s 筆（%s ~ %s）",
        len(raw),
        len(result.items),
        to_iso(window_from),
        to_iso(window_to),
    )
    if not result.items:
        result.warnings.append("窗口內沒有 NVD 變更")
    return result
