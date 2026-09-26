"""GitHub Advisory Database（REST /advisories，公開端點）。

僅收錄「有對應 CVE 編號」的公告；純 GHSA-only 的公告不進日報（無 CVE 無法交叉比對）。
"""

from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta
from typing import Any

from ..config import Settings
from ..models import VulnItem, severity_for, tags_from_cwes
from ..util import http_json, log, parse_iso, to_iso, truncate
from . import CollectResult

SOURCE = "ghsa"
DEFAULT_URL = "https://api.github.com/advisories"


def _headers(settings: Settings) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


def _cve_of(entry: dict[str, Any]) -> str:
    cve_id = (entry.get("cve_id") or "").strip().upper()
    if cve_id.startswith("CVE-"):
        return cve_id
    for ident in entry.get("identifiers") or []:
        value = (ident or {}).get("value", "") if isinstance(ident, dict) else ""
        if isinstance(value, str) and value.upper().startswith("CVE-"):
            return value.upper()
    return ""


def _cvss_of(entry: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    severities = entry.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        data = severities.get(key)
        if isinstance(data, dict) and isinstance(data.get("score"), (int, float)):
            version = "4.0" if key == "cvss_v4" else "3.1"
            return float(data["score"]), version, data.get("vector_string")
    cvss = entry.get("cvss") or {}
    if isinstance(cvss.get("score"), (int, float)):
        return float(cvss["score"]), None, cvss.get("vector_string")
    return None, None, None


def _packages_of(entry: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for vuln in entry.get("vulnerabilities") or []:
        pkg = (vuln or {}).get("package") or {}
        ecosystem = (pkg.get("ecosystem") or "").strip()
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        label = f"{ecosystem}:{name}" if ecosystem else name
        ranges = (vuln or {}).get("vulnerable_version_range") or ""
        patched = (vuln or {}).get("patched_versions") or ""
        if ranges:
            label += f" ({truncate(ranges, 40)})"
        if patched:
            label += f" → 修補 {truncate(patched, 20)}"
        if label not in out:
            out.append(label)
    return out[:8]


def parse_advisory(entry: dict[str, Any]) -> VulnItem | None:
    if not isinstance(entry, dict):
        return None
    cve_id = _cve_of(entry)
    if not cve_id:
        return None
    if entry.get("withdrawn_at"):
        return None

    score, version, vector = _cvss_of(entry)
    packages = _packages_of(entry)
    cwes = [
        c.get("cwe_id")
        for c in (entry.get("cwes") or [])
        if isinstance(c, dict) and c.get("cwe_id")
    ]

    ecosystem = ""
    package_name = ""
    for vuln in entry.get("vulnerabilities") or []:
        pkg = (vuln or {}).get("package") or {}
        if pkg.get("name"):
            ecosystem = (pkg.get("ecosystem") or "").strip()
            package_name = (pkg.get("name") or "").strip()
            break

    item = VulnItem(
        cve_id=cve_id,
        vendor=ecosystem,
        product=package_name,
        vendor_advisory_id=(entry.get("ghsa_id") or "").strip() or None,
        cvss_score=score,
        cvss_version=version,
        cvss_vector=vector,
        severity=severity_for(score, (entry.get("severity") or "").upper()),
        description_en=(entry.get("description") or entry.get("summary") or "").strip(),
        affected_packages=packages,
        published=to_iso(parse_iso(entry.get("published_at"))),
        modified=to_iso(parse_iso(entry.get("updated_at"))),
        cwes=cwes,
    )
    item.merge_tags(tags_from_cwes(cwes))
    item.auto_tags()
    html_url = entry.get("html_url") or entry.get("url")
    if html_url:
        item.add_reference("GitHub Advisory", html_url)
    for ref in entry.get("references") or []:
        if isinstance(ref, str) and ref.startswith("http"):
            item.add_reference("參考", ref, limit=6)
    item.add_source(SOURCE)
    return item


def collect(settings: Settings, window_from: datetime, window_to: datetime) -> CollectResult:
    cfg = settings.source("github_advisories")
    result = CollectResult(name=SOURCE, label=cfg.get("label", "GitHub Advisory"))
    url = cfg.get("url") or DEFAULT_URL
    headers = _headers(settings)

    # GitHub 的 published 參數以「日期」為單位，往前多抓一天再精準過濾。
    date_from = (window_from - timedelta(days=1)).date().isoformat()
    date_to = window_to.date().isoformat()
    range_value = f"{date_from}..{date_to}"

    for page in range(1, 6):
        params = urllib.parse.urlencode(
            {
                "published": range_value,
                "per_page": 100,
                "page": page,
                "sort": "published",
                "direction": "desc",
            }
        )
        log.info("GitHub Advisory：第 %s 頁", page)
        payload = http_json(f"{url}?{params}", headers=headers, timeout=60)
        if not isinstance(payload, list):
            raise ValueError("GitHub /advisories 回應非預期（預期陣列）")
        for entry in payload:
            item = parse_advisory(entry)
            if item is None:
                continue
            published = parse_iso(item.published)
            modified = parse_iso(item.modified)
            if published is not None and window_from <= published < window_to:
                item.is_new = True
                result.items.append(item)
            elif modified is not None and window_from <= modified < window_to:
                item.is_new = False
                result.items.append(item)
        if len(payload) < 100:
            break

    if not settings.github_token:
        result.warnings.append("未設定 GITHUB_TOKEN，GitHub API 速率上限為 60 次/小時")
    log.info("GitHub Advisory：%s 筆具 CVE 的公告", len(result.items))
    return result
