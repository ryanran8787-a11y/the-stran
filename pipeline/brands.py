"""廠商 / 產品名稱的正規化對照表（讓標題符合業界寫法）。"""

from __future__ import annotations

# CPE 中的 vendor -> 慣用寫法
VENDOR_NAMES: dict[str, str] = {
    "microsoft": "Microsoft",
    "cisco": "Cisco",
    "fortinet": "Fortinet",
    "paloaltonetworks": "Palo Alto Networks",
    "palo_alto_networks": "Palo Alto Networks",
    "vmware": "VMware",
    "broadcom": "Broadcom",
    "oracle": "Oracle",
    "adobe": "Adobe",
    "google": "Google",
    "apple": "Apple",
    "linux": "Linux",
    "apache": "Apache",
    "wordpress": "WordPress",
    "mikrotik": "MikroTik",
    "ivanti": "Ivanti",
    "atlassian": "Atlassian",
    "citrix": "Citrix",
    "sonicwall": "SonicWall",
    "sophos": "Sophos",
    "trendmicro": "Trend Micro",
    "n-able": "N-able",
    "nable": "N-able",
    "progress": "Progress",
    "networktigers": "NetworkTigers",
    "jetbrains": "JetBrains",
    "sap": "SAP",
    "zoho": "Zoho",
    "solarwinds": "SolarWinds",
    "juniper": "Juniper",
    "dlink": "D-Link",
    "d-link": "D-Link",
    "netgear": "NETGEAR",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "zyxel": "Zyxel",
    "synology": "Synology",
    "qnap": "QNAP",
    "samsung": "Samsung",
    "asus": "ASUS",
    "asustek": "ASUS",
    "totolink": "TOTOLINK",
    "sangoma": "Sangoma",
    "wso2": "WSO2",
    "trendmicro": "Trend Micro",
    "n-able": "N-able",
    "nable": "N-able",
    "novakon": "Novakon",
    "freebsd": "FreeBSD",
    "netbsd": "NetBSD",
    "openbsd": "OpenBSD",
    "redislabs": "Redis",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "openwrt": "OpenWrt",
    "sonicwall": "SonicWall",
    "beyondtrust": "BeyondTrust",
    "crushftp": "CrushFTP",
    "smartertools": "SmarterTools",
    "telemessage": "TeleMessage",
    "dassault": "Dassault Systèmes",
    "acronis": "Acronis",
    "servicenow": "ServiceNow",
    "dahua": "Dahua",
    "versa": "Versa",
    "ptzoptics": "PTZOptics",
    "metabase": "Metabase",
    "cleo": "Cleo",
    "reolink": "Reolink",
    "nuuo": "NUUO",
    "paessler": "Paessler",
    "hitachi": "Hitachi",
    "commvault": "Commvault",
    "geovision": "GeoVision",
    "litespeed": "LiteSpeed",
    "unitronics": "Unitronics",
    "dell": "Dell",
    "hp": "HP",
    "hpe": "HPE",
    "ibm": "IBM",
    "redhat": "Red Hat",
    "red_hat": "Red Hat",
    "suse": "SUSE",
    "ubuntu": "Ubuntu",
    "canonical": "Canonical",
    "debian": "Debian",
    "thekelleys": "Thekelleys",
    "westerndigital": "Western Digital",
    "synology_inc": "Synology",
    "sonicwall_inc": "SonicWall",
}

# CPE 中的 product -> 慣用寫法（僅收錄容易寫錯者）
PRODUCT_NAMES: dict[str, str] = {
    "routeros": "RouterOS",
    "firepower_management_center": "FMC",
    "firepower_threat_defense": "FTD",
    "adaptive_security_appliance_software": "ASA",
    "identity_services_engine": "ISE",
    "internet_information_services": "IIS",
    "exchange_server": "Exchange Server",
    "sharepoint_server": "SharePoint",
    "office": "Office",
    "n-central": "N-central",
    "ncentral": "N-central",
    "artifactory": "Artifactory",
    "forgejo": "Forgejo",
    "gitea": "Gitea",
    "gitlab": "GitLab",
    "vcenter_server": "vCenter Server",
    "esxi": "ESXi",
    "workspace_one_uem": "Workspace ONE UEM",
    "fortios": "FortiOS",
    "fortiproxy": "FortiProxy",
    "fortimanager": "FortiManager",
    "fortiweb": "FortiWeb",
    "confluence_data_center": "Confluence",
    "confluence_server": "Confluence",
    "jira_data_center": "Jira",
    "jira_server": "Jira",
    "bitbucket_server": "Bitbucket",
    "chromium": "Chromium",
    "chrome": "Chrome",
    "android": "Android",
    "safari": "Safari",
    "firefox": "Firefox",
    "kubernetes": "Kubernetes",
    "docker": "Docker",
    "jenkins": "Jenkins",
    ".net": ".NET",
    "active_directory": "Active Directory",
    "windows_server": "Windows Server",
    "ios_xe": "IOS XE",
    "ios_xe_sd_wan": "IOS XE SD-WAN",
    "ios_xr": "IOS XR",
    "nx_os": "NX-OS",
    "freepbx": "FreePBX",
    "live_update": "Live Update",
    "multiple_products": "Multiple Products",
    "commerce": "Commerce",
    "magento": "Magento",
    "freertos": "FreeRTOS",
    "openwrt": "OpenWrt",
    "broadcom_fabric_operating_system": "Fabric OS",
    "n-central_server": "N-central",
    "n-central_software": "N-central",
    "x5000r_firmware": "X5000R Firmware",
}


def prettify(value: str, mapping: dict[str, str]) -> str:
    if not value:
        return ""
    raw = value.strip()
    key = raw.lower()
    if key in mapping:
        return mapping[key]
    compact = key.replace(" ", "_")
    if compact in mapping:
        return mapping[compact]
    words = raw.replace("_", " ").replace("-", " ").split()
    if not words:
        return raw
    out: list[str] = []
    for word in words:
        if word.isupper():
            out.append(word)
        elif any(ch.isdigit() for ch in word) and any(ch.isalpha() for ch in word):
            out.append(word.upper())  # 型號：x5000r -> X5000R
        else:
            out.append(word[:1].upper() + word[1:])
    return " ".join(out)


def prettify_vendor(value: str) -> str:
    return prettify(value, VENDOR_NAMES)


def prettify_product(value: str) -> str:
    """產品名稱：先查產品表，再查廠商品牌表（例如 wordpress:wordpress）。"""
    if not value:
        return ""
    key = value.strip().lower().replace(" ", "_")
    if key in PRODUCT_NAMES:
        return PRODUCT_NAMES[key]
    if key in VENDOR_NAMES:
        return VENDOR_NAMES[key]
    return prettify(value, PRODUCT_NAMES)
