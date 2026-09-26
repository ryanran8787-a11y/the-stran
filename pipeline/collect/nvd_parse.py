"""NVD CVE 2.0 解析工具（API 與 gzip 資料檔共用同一份解析邏輯）。"""

from __future__ import annotations

from typing import Any

from ..brands import prettify_product, prettify_vendor
from ..models import VulnItem, severity_for, tags_from_cwes
from ..util import parse_iso, to_iso

# 分數精度優先序：v4 > v3.1 > v3.0 > v2
METRIC_KEYS: tuple[tuple[str, str], ...] = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def english_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions") or []:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            return (entry.get("value") or "").strip()
    for entry in cve.get("descriptions") or []:
        if isinstance(entry, dict) and entry.get("value"):
            return (entry.get("value") or "").strip()
    return ""


def extract_metric(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None, str]:
    """回傳 (score, version, vector, baseSeverity)。

    偏好 Primary source；缺 Primary 時採用第一筆。
    """
    metrics = cve.get("metrics") or {}
    for key, version in METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        chosen = None
        for entry in entries:
            if isinstance(entry, dict) and entry.get("type") == "Primary":
                chosen = entry
                break
        if chosen is None:
            chosen = entries[0]
        if not isinstance(chosen, dict):
            continue
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        severity = (data.get("baseSeverity") or chosen.get("baseSeverity") or "").upper()
        if isinstance(score, (int, float)):
            return float(score), data.get("version") or version, vector, severity
    return None, None, None, ""


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description") or []:
            value = (desc or {}).get("value") if isinstance(desc, dict) else None
            if value and value.startswith("CWE-") and value not in out:
                out.append(value)
    return out


def extract_product(cve: dict[str, Any]) -> tuple[str, str]:
    """從 configurations 的 CPE 取出 (vendor, product)。"""
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].strip()
                    product = parts[4].strip()
                    if vendor and vendor != "*" and product and product != "*":
                        return prettify_vendor(vendor), prettify_product(product)
    return "", ""


def extract_references(cve: dict[str, Any], limit: int = 6) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for ref in cve.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not url:
            continue
        tags = ref.get("tags") or []
        name = "參考"
        if "Vendor Advisory" in tags:
            name = "廠商公告"
        elif "Exploit" in tags or "Third Party Advisory" in tags:
            name = "第三方"
        elif "Patch" in tags:
            name = "修補"
        if any(existing["url"] == url for existing in out):
            continue
        out.append({"name": name, "url": url})
        if len(out) >= limit:
            break
    return out


def parse_cve_record(cve: dict[str, Any]) -> VulnItem | None:
    """把單一 NVD CVE 記錄轉為 VulnItem。格式不符則回傳 None。"""
    if not isinstance(cve, dict):
        return None
    cve_id = (cve.get("id") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    status = (cve.get("vulnStatus") or "").lower()
    if "rejected" in status or "withdrawn" in status:
        return None

    score, version, vector, base_severity = extract_metric(cve)
    vendor, product = extract_product(cve)
    cwes = extract_cwes(cve)

    item = VulnItem(
        cve_id=cve_id,
        vendor=vendor,
        product=product,
        cvss_score=score,
        cvss_version=version,
        cvss_vector=vector,
        severity=severity_for(score, base_severity),
        description_en=english_description(cve),
        published=to_iso(parse_iso(cve.get("published"))),
        modified=to_iso(parse_iso(cve.get("lastModified"))),
        cwes=cwes,
    )
    item.merge_tags(tags_from_cwes(cwes))
    item.auto_tags()
    for ref in extract_references(cve):
        item.add_reference(ref["name"], ref["url"])
    item.add_source("nvd")
    return item
