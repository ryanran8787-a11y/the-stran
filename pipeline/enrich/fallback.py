"""規則模板 fallback：LLM 不可用或輸出不合格時，仍要能產出完整日報。"""

from __future__ import annotations

from ..models import VulnItem
from ..util import truncate

IMPACT_BY_TAG: dict[str, str] = {
    "RCE": "遠端程式碼執行，攻擊者可完全控制受影響系統",
    "接管": "服務或帳號可能被完全接管",
    "權限提升": "攻擊者可將權限提升至更高層級",
    "認證繞過": "可繞過身分驗證直接存取系統",
    "資訊洩漏": "敏感資料可能外洩",
    "阻斷服務": "服務中斷，影響可用性",
    "沙箱逃逸": "可逃逸隔離機制並影響宿主環境",
    "XSS": "可於受害者瀏覽器執行惡意腳本",
    "SQLi": "可讀寫後端資料庫內容",
    "SSRF": "可誘使伺服器發送任意請求，觸及內網",
    "路徑穿越": "可讀取權限範圍外的檔案",
    "供應鏈": "影響範圍可能擴及下游使用者",
    "反序列化": "可導致遠端程式碼執行",
    "記憶體破壞": "可造成程式崩潰或程式碼執行",
    "其他": "系統可能遭未授權存取或控制",
}

ACTION_BY_TAG: dict[str, str] = {
    "RCE": "優先更新至修補版本；無法更新者請限制邊界存取或停用該介面。",
    "接管": "立即更新並檢查是否已有異常登入或帳號變更紀錄。",
    "權限提升": "套用廠商修補，並檢查本機是否出現異常提權行為。",
    "認證繞過": "更新至修補版本，並檢視存取日誌是否有異常請求。",
    "資訊洩漏": "更新至修補版本，並輪替可能受影響的憑證。",
    "阻斷服務": "更新至修補版本，並於邊界設備加上流量限制。",
    "沙箱逃逸": "更新至修補版本；高風險環境建議先隔離受影響服務。",
    "XSS": "更新至修補版本，並確認輸入輸出過濾機制。",
    "SQLi": "更新至修補版本，並檢查資料庫是否有異常查詢。",
    "SSRF": "更新至修補版本，並限制服務的對外與內網連線。",
    "路徑穿越": "更新至修補版本，並檢查檔案存取權限設定。",
    "供應鏈": "更新受影響元件，並清查相依清單是否受波及。",
    "反序列化": "更新至修補版本，避免處理不可信的序列化資料。",
    "記憶體破壞": "更新至修補版本，並啟動記憶體防護機制。",
    "其他": "依廠商公告更新至最新版本；無法更新者請評估隔離或停用該服務。",
}

DEFAULT_ACTION = "依廠商公告更新至最新修補版本；無法更新者請評估隔離或停用該服務。"


def format_score(score: float | None) -> str:
    return "" if score is None else f"{float(score):.1f}"


def build_title_short(item: VulnItem) -> str:
    """格式：{廠商} {產品} {CVE尾段序號}×{CVSS}{ 在野}"""
    title = f"{item.label()} {item.tail()}"
    score = format_score(item.cvss_score)
    if score:
        title += f"×{score}"
    if item.in_the_wild:
        title += " 在野"
    return title


def build_title_full(item: VulnItem) -> str:
    title = f"{item.label()} {item.cve_id}"
    score = format_score(item.cvss_score)
    if score:
        title += f" · CVSS {score}"
    if item.in_the_wild:
        title += " · 在野利用"
    return title


def build_summary(item: VulnItem) -> str:
    tags = "、".join(item.tags[:2]) if item.tags else "安全"
    parts = [f"{item.label()} 存在{tags}漏洞"]
    score = format_score(item.cvss_score)
    if score:
        parts.append(f"CVSS {score}")
    if item.kev:
        parts.append("已列入 CISA KEV 已知在野利用清單")
    elif item.in_the_wild:
        parts.append("已觀察到在野利用")
    if item.epss_score:
        parts.append(f"EPSS {item.epss_score:.2f}")
    return truncate("，".join(parts) + "。", 88)


def build_impact(item: VulnItem) -> str:
    for tag in item.tags:
        if tag in IMPACT_BY_TAG:
            return truncate(IMPACT_BY_TAG[tag] + "。", 46)
    return IMPACT_BY_TAG["其他"] + "。"


def build_action(item: VulnItem) -> str:
    for tag in item.tags:
        if tag in ACTION_BY_TAG:
            return truncate(ACTION_BY_TAG[tag], 54)
    return DEFAULT_ACTION


def apply_fallback(item: VulnItem) -> VulnItem:
    item.title_short = item.title_short or build_title_short(item)
    item.title_full = item.title_full or build_title_full(item)
    item.summary_zh = item.summary_zh or build_summary(item)
    item.impact_zh = item.impact_zh or build_impact(item)
    item.action_zh = item.action_zh or build_action(item)
    if item.generated_by not in ("gemini", "openai", "claude"):
        item.generated_by = "template"
    if not item.tags:
        item.tags = ["其他"]
    return item
