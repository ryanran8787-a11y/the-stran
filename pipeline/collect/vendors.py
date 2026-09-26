"""廠商 / 組織公告來源（RSS 2.0 與 Atom 皆可）。

這些來源只用來「補充」既有 CVE 項目的資訊（來源標記、廠商公告連結、公告編號），
並另存一份 vendor_watch 速覽；單一 feed 失敗完全不影響日報產出。
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Any

from ..config import Settings
from ..models import VulnItem
from ..util import http_get, log, parse_iso, to_iso, truncate
from . import CollectResult

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ADVISORY_PATTERNS = (
    re.compile(r"cisco-sa-[a-z0-9\-]+", re.IGNORECASE),
    re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE),
    re.compile(r"\bZDI-\d{2}-\d{3,4}\b", re.IGNORECASE),
    re.compile(r"\bAPSB\d{2}-\d{2,3}\b", re.IGNORECASE),
    re.compile(r"\bUSN-\d{4}-\d+\b", re.IGNORECASE),
    re.compile(r"\bRHSA-\d{4}:\d+\b", re.IGNORECASE),
)
MAX_WATCH_PER_FEED = 12
MAX_WATCH_TOTAL = 48


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(elem: ET.Element, names: set[str]) -> str:
    for child in elem:
        if _localname(child.tag) in names:
            text = (child.text or "").strip()
            if text:
                return text
    return ""


def _link_of(elem: ET.Element) -> str:
    for child in elem:
        if _localname(child.tag) != "link":
            continue
        href = (child.attrib.get("href") or "").strip()
        if href:
            return href
        text = (child.text or "").strip()
        if text:
            return text
    return ""


def parse_feed(raw: bytes) -> list[dict[str, str]]:
    """解析 RSS 2.0 / Atom，回傳 [{title, link, date, summary}]。"""
    root = ET.fromstring(raw)
    out: list[dict[str, str]] = []
    for elem in root.iter():
        if _localname(elem.tag) not in ("item", "entry"):
            continue
        title = _child_text(elem, {"title"})
        link = _link_of(elem) or _child_text(elem, {"guid", "id"})
        date = _child_text(elem, {"pubdate", "published", "updated", "date"})
        summary = _child_text(elem, {"description", "summary", "content"})
        if not title and not link:
            continue
        out.append(
            {
                "title": " ".join(title.split()),
                "link": link,
                "date": date,
                "summary": " ".join(summary.split()),
            }
        )
    return out


def extract_advisory_id(url: str, title: str) -> str | None:
    haystack = f"{url} {title}"
    for pattern in ADVISORY_PATTERNS:
        found = pattern.search(haystack)
        if found:
            return found.group(0)
    return None


def parse_feed_config(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    feeds = cfg.get("feeds") or []
    return [f for f in feeds if isinstance(f, dict) and f.get("enabled", True) and f.get("url")]


def collect(settings: Settings, window_from: datetime, window_to: datetime) -> CollectResult:
    cfg = settings.source("vendors")
    result = CollectResult(name="vendors", label="廠商公告")
    if not cfg.get("enabled", False):
        result.warnings.append("disabled")
        return result

    watch: list[dict[str, Any]] = []
    failures: list[str] = []
    grace = window_from - timedelta(hours=6)  # feed 時間標記常有時區/延遲落差

    for feed in parse_feed_config(cfg):
        name = str(feed.get("name") or "vendor")
        label = str(feed.get("label") or name)
        try:
            raw = http_get(str(feed["url"]), timeout=45, retries=2)
            entries = parse_feed(raw)
        except Exception as exc:  # noqa: BLE001 - 單一 feed 失敗必須被隔離
            log.warning("廠商 feed %s 失敗（已隔離）：%s", name, exc)
            failures.append(f"{name}: {type(exc).__name__}")
            continue

        kept = 0
        for entry in entries:
            published = parse_iso(entry["date"])
            if published is not None and not (grace <= published < window_to + timedelta(hours=6)):
                continue
            if published is None and kept >= 4:
                continue  # 無法判定日期者最多收 4 筆，避免舊公告灌入
            cves = sorted({m.upper() for m in CVE_RE.findall(f"{entry['title']} {entry['summary']}")})
            advisory_id = extract_advisory_id(entry["link"], entry["title"])
            if len(watch) < MAX_WATCH_TOTAL and kept < MAX_WATCH_PER_FEED and (cves or published):
                watch.append(
                    {
                        "source": name,
                        "label": label,
                        "title": truncate(entry["title"], 160),
                        "url": entry["link"] or str(feed["url"]),
                        "date": to_iso(published) or entry["date"] or None,
                        "cves": cves[:6],
                    }
                )
            for cve_id in cves[:4]:
                item = VulnItem(
                    cve_id=cve_id,
                    vendor=label,
                    product="",
                    vendor_advisory_id=advisory_id,
                    description_en=truncate(entry["title"], 300),
                    published=to_iso(published),
                    modified=to_iso(published),
                )
                item.add_source(name)
                item.add_reference(label, entry["link"] or str(feed["url"]))
                result.items.append(item)
            kept += 1

        log.info("廠商 feed %s：%s 筆（窗口內 %s 筆）", name, len(entries), kept)

    result.extra["watch"] = watch
    if failures:
        result.warnings.extend(failures)
    log.info("廠商公告：item 候選 %s 筆、速覽 %s 筆（失敗 %s）", len(result.items), len(watch), len(failures))
    return result
