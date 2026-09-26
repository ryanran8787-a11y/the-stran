#!/usr/bin/env node
/**
 * 示範資料產生器（給沒有網路 / 不想跑完整管線的貢獻者用）。
 *
 *   node scripts/dev-seed.mjs
 *
 * 只有在 data/daily 沒有任何檔案時才會寫入，避免覆蓋真實日報。
 * 產出的資料會標記 generated_by = "seed-manual"，前端會顯示提示橫幅。
 */

import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const DAILY_DIR = path.join(ROOT, "data", "daily");
const INDEX_FILE = path.join(ROOT, "data", "index.json");

const DEMO_ITEMS = [
  {
    cve_id: "CVE-2026-87902",
    title_short: "WordPress Core 87902×9.8 在野",
    title_full: "WordPress Core CVE-2026-87902 · CVSS 9.8 · 在野利用",
    vendor: "WordPress",
    product: "Core",
    vendor_advisory_id: null,
    severity: "CRITICAL",
    cvss: { version: "3.1", score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
    epss: { score: 0.7124, percentile: 0.981 },
    cwe: ["CWE-98"],
    tags: ["RCE"],
    in_the_wild: true,
    kev: {
      date_added: "2026-09-25",
      due_date: "2026-09-28",
      ransomware: "Unknown",
      forensic_triage: "Yes",
      name_en: "WordPress Core Remote File Inclusion Vulnerability",
      required_action_en: "Apply mitigations in accordance with vendor instructions.",
    },
    summary_zh:
      "未授權攻擊者可讓頁面模板解析載入主題目錄外的本機 PHP 檔，進而達成遠端程式碼執行。",
    impact_zh: "未授權 RCE，可完全接管站台。",
    action_zh: "升級至修補版本；無法升級者請停用未使用主題並套用 WAF 規則。",
    description_en:
      "WordPress Core contains a remote file inclusion vulnerability which could allow an unauthenticated attacker to make page-template resolution include a chosen readable local .php file outside the active theme directories, leading to remote code execution.",
    references: [
      { name: "cisa_kev", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { name: "nvd", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-87902" },
    ],
    affected_packages: [],
    published: "2026-09-25T18:00:00Z",
    modified: "2026-09-25T20:11:00Z",
    sources: ["cisa_kev", "nvd"],
    rank: 1,
    generated_by: "seed-manual",
    risk_score: 14.22,
  },
  {
    cve_id: "CVE-2026-89094",
    title_short: "go code.gitea.io/gitea 89094×9.9",
    title_full: "go code.gitea.io/gitea CVE-2026-89094 · CVSS 9.9",
    vendor: "go",
    product: "code.gitea.io/gitea",
    vendor_advisory_id: "GHSA-2rmr-xw8m-22q9",
    severity: "CRITICAL",
    cvss: { version: "3.1", score: 9.9, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" },
    epss: { score: 0.3312, percentile: 0.94 },
    cwe: ["CWE-94"],
    tags: ["RCE", "沙箱逃逸"],
    in_the_wild: false,
    kev: null,
    summary_zh: "已驗證使用者可透過無界模板求值逃逸沙箱，在伺服器上執行任意程式碼。",
    impact_zh: "已驗證 RCE，可讀寫伺服器檔案。",
    action_zh: "升級至 1.2.3 以上版本。",
    description_en:
      "Forgejo before 1.2.3 allows an authenticated user to escape the sandbox through unbounded template evaluation, resulting in remote code execution on the server.",
    references: [{ name: "ghsa", url: "https://github.com/advisories/GHSA-2rmr-xw8m-22q9" }],
    affected_packages: ["go:code.gitea.io/gitea (< 1.2.3) → 修補 1.2.3"],
    published: "2026-09-25T10:00:00Z",
    modified: "2026-09-25T11:30:00Z",
    sources: ["ghsa", "nvd"],
    rank: 2,
    generated_by: "seed-manual",
    risk_score: 10.56,
  },
  {
    cve_id: "CVE-2026-67279",
    title_short: "MikroTik RouterOS 67279×9.8 在野",
    title_full: "MikroTik RouterOS CVE-2026-67279 · CVSS 9.8 · 在野利用",
    vendor: "MikroTik",
    product: "RouterOS",
    vendor_advisory_id: null,
    severity: "CRITICAL",
    cvss: { version: "3.1", score: 9.8, vector: null },
    epss: null,
    cwe: ["CWE-841"],
    tags: ["接管"],
    in_the_wild: true,
    kev: {
      date_added: "2026-09-25",
      due_date: "2026-09-28",
      ransomware: "Unknown",
      forensic_triage: "No",
      name_en: "Mikrotik RouterOS Improper Enforcement of Behavioral Workflow Vulnerability",
      required_action_en: "Apply mitigations in accordance with vendor instructions.",
    },
    summary_zh:
      "未授權用戶端可開啟工作階段通道並送出 exec 請求，可與另一個漏洞串聯達成未授權利用。",
    impact_zh: "可導致路由器被接管。",
    action_zh: "依廠商公告更新 RouterOS，並檢查是否出現異常連線。",
    description_en:
      "Mikrotik RouterOS contains an improper enforcement of behavioral workflow vulnerability that could allow an unauthenticated client to open a session channel and send an exec request.",
    references: [
      { name: "cisa_kev", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
      { name: "廠商公告", url: "https://mikrotik.com/supportsec/september-2026-vulnerability/" },
    ],
    affected_packages: [],
    published: "2026-09-25T00:00:00Z",
    modified: "2026-09-25T00:00:00Z",
    sources: ["cisa_kev", "nvd"],
    rank: 3,
    generated_by: "seed-manual",
    risk_score: 13.8,
  },
const DEMO_VENDOR_WATCH = [
  {
    source: "fortinet",
    label: "Fortinet",
    title: "FortiOS / FortiProxy — Heap buffer overflow in administrative interface",
    url: "https://www.fortiguard.com/psirt",
    date: "2026-09-25T09:00:00Z",
    cves: ["CVE-2026-71234"],
  },
  {
    source: "zdi",
    label: "Zero Day Initiative",
    title: "ZDI-26-512: Linux Kernel io_uring Privilege Escalation",
    url: "https://www.zerodayinitiative.com/advisories/published/",
    date: "2026-09-25T07:30:00Z",
    cves: [],
  },
];

function buildDigest(date) {
  const stats = {
    scanned: 1373,
    kept: DEMO_ITEMS.length,
    kev: DEMO_ITEMS.filter((item) => item.kev).length,
    critical: DEMO_ITEMS.filter((item) => item.severity === "CRITICAL").length,
    in_the_wild: DEMO_ITEMS.filter((item) => item.in_the_wild).length,
    sources_ok: 4,
    sources_failed: 0,
  };
  return {
    schema_version: 1,
    date,
    generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    generated_by: "seed-manual",
    window: { from: `${date}T22:00:00Z`, to: `${date}T22:00:00Z` },
    stats,
    sources: [
      { name: "cisa_kev", label: "CISA KEV", ok: true, items: 2, error: null },
      { name: "nvd", label: "NVD", ok: true, items: 864, error: null },
      { name: "ghsa", label: "GitHub Advisory", ok: true, items: 500, error: null },
      { name: "epss", label: "EPSS", ok: true, items: 738, error: null },
    ],
    items: DEMO_ITEMS,
    vendor_watch: DEMO_VENDOR_WATCH,
  };
}

function main() {
  if (fs.existsSync(DAILY_DIR)) {
    const existing = fs.readdirSync(DAILY_DIR).filter((name) => name.endsWith(".json"));
    if (existing.length > 0) {
      console.log(`[dev-seed] data/daily 已有 ${existing.length} 個檔案，不覆蓋。`);
      return;
    }
  }
  const today = new Date().toISOString().slice(0, 10);
  fs.mkdirSync(DAILY_DIR, { recursive: true });
  const digest = buildDigest(today);
  fs.writeFileSync(
    path.join(DAILY_DIR, `${today}.json`),
    JSON.stringify(digest, null, 2) + "\n",
    "utf8",
  );
  const index = {
    schema_version: 1,
    updated_at: digest.generated_at,
    total: 1,
    reports: [
      {
        date: today,
        kept: digest.stats.kept,
        kev: digest.stats.kev,
        critical: digest.stats.critical,
        in_the_wild: digest.stats.in_the_wild,
        generated_at: digest.generated_at,
        generated_by: digest.generated_by,
        top: digest.items.slice(0, 3).map((item) => item.title_short),
      },
    ],
  };
  fs.writeFileSync(INDEX_FILE, JSON.stringify(index, null, 2) + "\n", "utf8");
  console.log(`[dev-seed] 已寫入示範資料 ${today}（執行 python -m pipeline 會產生真實資料）`);
}

main();
