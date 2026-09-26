"""資料模型與 CWE→標籤對應表。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .util import cve_tail, dedupe_keep_order

# ------------------------------------------------------- 封閉標籤清單
ALLOWED_TAGS: tuple[str, ...] = (
    "RCE",
    "權限提升",
    "認證繞過",
    "資訊洩漏",
    "阻斷服務",
    "沙箱逃逸",
    "接管",
    "XSS",
    "SQLi",
    "SSRF",
    "路徑穿越",
    "供應鏈",
    "反序列化",
    "記憶體破壞",
    "其他",
)

# CWE -> 標籤。刻意保守：只放高信心對應。
CWE_TAG_MAP: dict[str, str] = {
    "CWE-22": "路徑穿越",
    "CWE-23": "路徑穿越",
    "CWE-36": "路徑穿越",
    "CWE-59": "權限提升",
    "CWE-77": "RCE",
    "CWE-78": "RCE",
    "CWE-79": "XSS",
    "CWE-89": "SQLi",
    "CWE-94": "RCE",
    "CWE-95": "RCE",
    "CWE-98": "RCE",
    "CWE-119": "記憶體破壞",
    "CWE-120": "記憶體破壞",
    "CWE-121": "記憶體破壞",
    "CWE-122": "記憶體破壞",
    "CWE-125": "記憶體破壞",
    "CWE-190": "記憶體破壞",
    "CWE-200": "資訊洩漏",
    "CWE-264": "權限提升",
    "CWE-269": "權限提升",
    "CWE-276": "權限提升",
    "CWE-284": "權限提升",
    "CWE-287": "認證繞過",
    "CWE-288": "認證繞過",
    "CWE-290": "認證繞過",
    "CWE-295": "認證繞過",
    "CWE-306": "認證繞過",
    "CWE-307": "認證繞過",
    "CWE-319": "資訊洩漏",
    "CWE-352": "接管",
    "CWE-362": "權限提升",
    "CWE-367": "權限提升",
    "CWE-400": "阻斷服務",
    "CWE-416": "記憶體破壞",
    "CWE-434": "RCE",
    "CWE-476": "阻斷服務",
    "CWE-494": "供應鏈",
    "CWE-502": "反序列化",
    "CWE-522": "資訊洩漏",
    "CWE-532": "資訊洩漏",
    "CWE-611": "資訊洩漏",
    "CWE-732": "權限提升",
    "CWE-770": "阻斷服務",
    "CWE-787": "記憶體破壞",
    "CWE-798": "認證繞過",
    "CWE-829": "供應鏈",
    "CWE-841": "其他",
    "CWE-862": "權限提升",
    "CWE-863": "權限提升",
    "CWE-917": "RCE",
    "CWE-918": "SSRF",
    "CWE-1336": "RCE",
    "CWE-1357": "供應鏈",
    "CWE-1395": "供應鏈",
}

SEVERITY_FROM_SCORE: tuple[tuple[float, str], ...] = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
)

KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def severity_for(score: float | None, fallback: str = "UNKNOWN") -> str:
    if score is None:
        return fallback if fallback in KNOWN_SEVERITIES else "UNKNOWN"
    for threshold, name in SEVERITY_FROM_SCORE:
        if score >= threshold:
            return name
    return "UNKNOWN"


def tags_from_cwes(cwes: list[str]) -> list[str]:
    return dedupe_keep_order([CWE_TAG_MAP[c] for c in cwes if c in CWE_TAG_MAP])


@dataclass
class VulnItem:
    """跨來源統一後的漏洞項目，以 cve_id 為唯一識別。"""

    cve_id: str
    vendor: str = ""
    product: str = ""
    vendor_advisory_id: str | None = None
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cwes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    in_the_wild: bool = False
    kev: dict[str, Any] | None = None
    description_en: str = ""
    references: list[dict[str, str]] = field(default_factory=list)
    affected_packages: list[str] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    sources: list[str] = field(default_factory=list)
    is_new: bool = True
    # --- 提煉階段填入（LLM 或規則模板）---
    title_short: str = ""
    title_full: str = ""
    summary_zh: str = ""
    impact_zh: str = ""
    action_zh: str = ""
    generated_by: str = "template"
    risk_score: float | None = None
    rank: int | None = None

    # ---------------------------------------------------------- 累積
    def add_source(self, name: str) -> None:
        if name and name not in self.sources:
            self.sources.append(name)

    def add_reference(self, name: str, url: str, limit: int = 8) -> None:
        if not url or len(self.references) >= limit:
            return
        if any(ref.get("url") == url for ref in self.references):
            return
        self.references.append({"name": name, "url": url})

    def merge_cwes(self, cwes: list[str]) -> None:
        self.cwes = dedupe_keep_order(self.cwes + [c for c in cwes if c])

    def merge_tags(self, tags: list[str]) -> None:
        self.tags = dedupe_keep_order(self.tags + [t for t in tags if t in ALLOWED_TAGS])

    def auto_tags(self) -> None:
        """CWE 對不上時，用英文描述關鍵字補標籤（保守，寧缺勿錯）。"""
        haystack = (self.description_en or "").lower()
        if not haystack:
            return
        guessed: list[str] = []
        if "remote code execution" in haystack or "arbitrary code execution" in haystack:
            guessed.append("RCE")
        if "privilege escalation" in haystack or "escalate privileges" in haystack:
            guessed.append("權限提升")
        if "authentication bypass" in haystack or "bypass authentication" in haystack:
            guessed.append("認證繞過")
        if "denial of service" in haystack:
            guessed.append("阻斷服務")
        if "cross-site scripting" in haystack:
            guessed.append("XSS")
        if "sql injection" in haystack:
            guessed.append("SQLi")
        if "path traversal" in haystack or "directory traversal" in haystack:
            guessed.append("路徑穿越")
        if "information disclosure" in haystack or "sensitive information" in haystack:
            guessed.append("資訊洩漏")
        if "takeover" in haystack:
            guessed.append("接管")
        if "sandbox escape" in haystack:
            guessed.append("沙箱逃逸")
        self.merge_tags(guessed)

    # ---------------------------------------------------------- 查詢
    def label(self) -> str:
        """廠商 + 產品的人類可讀標籤（自動去除重複，例如 wordpress:wordpress）。"""
        vendor = (self.vendor or "").strip()
        product = (self.product or "").strip()
        if vendor and product:
            if vendor.lower() == product.lower():
                return vendor
            if product.lower().startswith(vendor.lower()):
                return product
            if vendor.lower().startswith(product.lower()):
                return vendor
        parts = [p for p in (vendor, product) if p]
        return " ".join(parts) if parts else "未標示產品"

    def tail(self) -> str:
        return cve_tail(self.cve_id)

    # ---------------------------------------------------------- 序列化
    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title_short": self.title_short,
            "title_full": self.title_full,
            "vendor": self.vendor,
            "product": self.product,
            "vendor_advisory_id": self.vendor_advisory_id,
            "severity": self.severity,
            "cvss": {
                "version": self.cvss_version,
                "score": self.cvss_score,
                "vector": self.cvss_vector,
            },
            "epss": (
                {"score": self.epss_score, "percentile": self.epss_percentile}
                if (self.epss_score is not None or self.epss_percentile is not None)
                else None
            ),
            "cwe": self.cwes,
            "tags": self.tags or ["其他"],
            "in_the_wild": self.in_the_wild,
            "kev": self.kev,
            "summary_zh": self.summary_zh,
            "impact_zh": self.impact_zh,
            "action_zh": self.action_zh,
            "description_en": self.description_en,
            "references": self.references,
            "affected_packages": self.affected_packages,
            "published": self.published,
            "modified": self.modified,
            "sources": self.sources,
            "rank": self.rank,
            "generated_by": self.generated_by,
            "risk_score": self.risk_score,
        }

    def llm_payload(self) -> dict[str, Any]:
        """送給 LLM 的精簡輸入（只給它需要的欄位，降低 token 與幻覺空間）。"""
        payload: dict[str, Any] = {
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "cvss_score": self.cvss_score,
            "in_the_wild": self.in_the_wild,
            "cwe": self.cwes,
            "description_en": self.description_en or "(no official description available)",
        }
        if self.kev:
            payload["kev_date_added"] = self.kev.get("date_added")
            payload["kev_required_action_en"] = self.kev.get("required_action_en")
        if self.affected_packages:
            payload["affected_packages"] = self.affected_packages[:6]
        return payload
