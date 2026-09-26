# Security Daily · 網安每日報

每日自動彙整 CVE / CISA KEV 在野利用清單 / GitHub Advisory / EPSS 與各大廠商安全公告，
經過「規則篩選 + LLM 提煉 + 驗證器」產生正體中文資安日報，靜態生成後部署到 Vercel。

- **線上網站**：<https://the-stran.vercel.app>
- **資料來源**：NVD（公眾領域）、CISA KEV、GitHub Advisory Database（CC-BY-4.0）、FIRST EPSS、廠商 RSS

---

## 架構

```
GitHub Actions（每日 UTC 22:00 = 台北 06:00）
  │
  ├─ 1. Collect    KEV JSON / NVD gzip feed（備援 API）/ GitHub Advisory /
  │                廠商 RSS / EPSS      ← 每個來源失敗自動隔離
  ├─ 2. Normalize  以 CVE ID 為鍵合併去重（NVD + KEV + GHSA 交叉補齊）
  ├─ 3. Score      規則篩選：CVSS ≥ 9.0 或 在野利用 或 EPSS ≥ 0.5（LLM 不參與）
  ├─ 4. Enrich     LLM 批次改寫中文標題／摘要／處置（結構化輸出）
  │                + 驗證器攔下幻覺（未知 CVE、分數不符、標題缺序號）
  │                + 任何失敗自動退回規則模板
  ├─ 5. Write      data/daily/YYYY-MM-DD.json + data/index.json
  ├─ 6. Build      next build（全站 SSG，含 /report/[date]、/cve/[id]、RSS、sitemap）
  └─ 7. Commit     git commit && git push  →  Vercel 自動部署
```

**為什麼排程放在 GitHub Actions？** Vercel Hobby 的 Cron 每天只能執行一次、Function 最長 60 秒，
跑不動「多來源抓取 + LLM 呼叫 + 建置」；GitHub Actions 公開 repo 免費且時間寬鬆。

---

## 快速開始（本機）

需求：**Node.js ≥ 20.9**、**Python ≥ 3.11**（管線零第三方依賴，不需 pip install）。

```bash
# 1) 環境變數
cp .env.example .env      # 填入 NVD_API_KEY 與 GEMINI_API_KEY

# 2) 前端相依
npm install

# 3) 產生今日日報（真實資料）
python -m pipeline --date today

# 4) 開發伺服器
npm run dev               # http://localhost:3000

# 5) 生產建置
npm run build
```

沒有網路時可以先用示範資料把站台跑起來：

```bash
node scripts/dev-seed.mjs   # 只在 data/daily 為空時寫入，並標記 generated_by="seed-manual"
```

---

## 環境變數

| 變數 | 必要 | 說明 |
| --- | --- | --- |
| `NVD_API_KEY` | 建議 | [免費申請](https://nvd.nist.gov/developers/request-an-api-key)，把 NVD API 上限從 5 次/30 秒提升到 50 次/30 秒。**資料優先用 gzip 資料檔，正常情況下不會用到 API** |
| `LLM_PROVIDER` | 是 | `gemini` / `openai` / `claude` / `none`（`none` = 純規則模板） |
| `GEMINI_API_KEY` | 是 | Gemini API key。`GEMINI_MODEL` 留空會**自動偵測**可用模型（建議留空） |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | 選用 | OpenAI 結構化輸出（`json_schema` strict） |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | 選用 | Claude（優先用 `output_config.format`，失敗退回 strict tool use） |
| `GITHUB_TOKEN` | 選用 | 提高 GitHub Advisory API 上限（60 → 5000 次/小時）。在 Actions 內用內建 `secrets.GITHUB_TOKEN` 即可 |
| `FILTER_MIN_CVSS` | 選用 | 收錄門檻，預設 `9.0` |
| `FILTER_MIN_EPSS` | 選用 | EPSS 門檻（另需 CVSS ≥ 7.0），預設 `0.5` |
| `KEV_LOOKBACK_DAYS` | 選用 | KEV 回看天數，預設 `3` |
| `LLM_BATCH_SIZE` / `LLM_MAX_ITEMS` | 選用 | LLM 批次大小（18）與成本護欄（80） |
| `NEXT_PUBLIC_SITE_URL` | 選用 | 站台網址，用於 sitemap / RSS / OG |

> `.env` 已被 `.gitignore` 忽略；CI 使用 GitHub Repository Secrets，程式會以真實環境變數優先。

---

## 管線指令

```bash
python -m pipeline --help

python -m pipeline --date today                 # 產生今日日報
python -m pipeline --date 2026-09-25            # 補跑指定日期（同日重跑會覆蓋，具冪等性）
python -m pipeline --date today --dry-run       # 只印結果，不寫檔
python -m pipeline --date today --llm none      # 不用 LLM（純規則模板）
python -m pipeline --date today --sources nvd,ghsa
python -m pipeline --min-cvss 9.5 --max-items 40
python -m pipeline --date today --allow-empty   # 即使 0 筆也回傳成功（除錯用）
```

離開代碼：`0` 成功、`1` 例外錯誤、`2` 當日 0 筆通過篩選（CI 會據此告警並開 issue）。

### 測試

```bash
python -m unittest discover -s pipeline/tests -t .   # 37 項，離線執行，不連網
```

覆蓋：NVD 解析、CPE→廠商/產品、KEV 索引標記、GHSA 解析、跨來源合併、
篩選規則、排序與 rank、**驗證器（幻覺攔截）**、模板 fallback、LLM schema 轉換、輸出入往返。

---

## 資料契約

唯一真實來源：`schema/digest.schema.json`（JSON Schema 2020-12）。
Python 端 `pipeline/models.py` 與前端 `lib/types.ts` / `lib/schema.ts` 都對齊此檔。

標題雙欄位設計（兩者並存）：

```jsonc
{
  "cve_id": "CVE-2026-20079",              // 完整編號 → 搜尋、深連結、/cve/[id]
  "title_short": "Cisco FMC 20079×10.0 在野",  // 卡片主標題：{廠商} {產品} {CVE尾號}×{CVSS}{在野}
  "title_full": "Cisco FMC CVE-2026-20079 · CVSS 10.0 · 在野利用",
  "vendor_advisory_id": "cisco-sa-...",    // 廠商自己的公告編號（若有）
  "severity": "CRITICAL",
  "cvss": { "version": "3.1", "score": 10.0, "vector": "CVSS:3.1/..." },
  "epss": { "score": 0.71, "percentile": 0.98 },
  "cwe": ["CWE-78"],
  "tags": ["RCE", "未授權利用"],            // 封閉清單，不接受自由生成
  "in_the_wild": true,
  "kev": { "date_added": "2026-09-25", "due_date": "2026-09-28", "ransomware": "Unknown" },
  "summary_zh": "…", "impact_zh": "…", "action_zh": "…",
  "description_en": "官方英文原文（保留可追溯性）",
  "sources": ["cisa_kev", "nvd"]
}
```

`data/index.json` 只存輕量索引（日期、統計、Top 3 標題），供首頁與存檔頁生成卡片。

---

## LLM 提煉與防幻覺

Prompt 本體在 `prompts/daily_digest.md`（可版控調優），規則摘要：

1. 只能使用輸入 JSON 中既有的資料，**不得新增 CVE、分數、版本**。
2. 標題格式 `{廠商} {產品} {CVE尾段序號}×{CVSS}{ 在野}`，且分數必須等於來源值。
3. `tags` 只能從 **15 個封閉標籤**中挑選。
4. 一次批次 18 筆，只輸出 JSON。

`pipeline/verify.py` 會逐筆交叉檢查：

| 類型 | 判定 | 處理 |
| --- | --- | --- |
| 硬性 | 未知／重複 CVE、標題缺序號、標題分數與來源不符、標題缺「在野」、空標題 | **丟棄該筆 LLM 文字，改用規則模板** |
| 軟性 | 標籤不在封閉清單、欄位過長、缺 `title_full` | 修剪後仍採用 |

也就是說：**LLM 只能影響文字，不能影響事實**。任何一筆失敗都只影響該筆，不會影響整期。

---

## 部署（Vercel + GitHub Actions）

### 1. 建立 GitHub repo 並推送

```bash
git init
git add .
git commit -m "feat: security daily digest site"
git branch -M main
git remote add origin https://github.com/ryanran8787-a11y/the-stran.git
git push -u origin main
```

### 2. 設定 Repository Secrets

Repo → Settings → Secrets and variables → Actions → New repository secret：

- `NVD_API_KEY`
- `GEMINI_API_KEY`（或 `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`）

> `GITHUB_TOKEN` 是 Actions 內建的，不需要手動新增，workflow 已經把它傳給管線以提高
> GitHub Advisory API 速率上限。

### 3. 連結 Vercel

1. Vercel → Add New → Project → 匯入 `the-stran`
2. Framework 會自動偵測為 Next.js，**不需要修改任何設定**
3. （可選）在 Vercel 設定環境變數 `NEXT_PUBLIC_SITE_URL=https://<你的網域>`
4. 之後每次 `git push`（包含每日 bot 的 commit）都會自動部署

### 4. 排程

`.github/workflows/daily.yml` 每天 UTC 22:00（台北 06:00）執行；也可在 Actions 頁面用
`workflow_dispatch` 手動觸發並指定日期補跑。

- 只需**公開 repo**：GitHub-hosted runner 免費且無分鐘數上限
- 若資料有變更才會 commit（`git diff --cached --quiet` 判斷），避免空 commit 觸發多餘部署
- 任何失敗都會自動開一個 `daily-alert` label 的 issue（同一時間只會有一個未結案告警）
- 每次執行都會把最新一期摘要寫入 GitHub Actions 的 Step Summary

---

## 目錄結構

```
├─ .github/workflows/daily.yml   每日排程：測試 → 抓取 → 建置 → commit
├─ app/                          Next.js App Router（全站 SSG）
│  ├─ page.tsx                   首頁 = 最新一期
│  ├─ report/[date]/page.tsx     每日一期（generateStaticParams）
│  ├─ archive/page.tsx           歷史存檔
│  ├─ cve/[id]/page.tsx          單一 CVE 詳情（可分享深連結）
│  ├─ feed.xml/route.ts          RSS 2.0
│  ├─ feed.json/route.ts         JSON Feed 1.1
│  ├─ sitemap.ts / robots.ts     SEO
│  └─ globals.css                Vercel 風格設計語彙（自動深淺色）
├─ components/                   SiteHeader / StatsBar / VulnCard /
│                                FilterableList（前端搜尋篩選）/ ArchiveCard …
├─ lib/                          types / schema（執行期驗證）/ data（SSG 讀檔）/ format
├─ pipeline/                     Python 資料管線（零第三方依賴）
│  ├─ collect/                   kev / nvd / nvd_parse / github_advisories /
│  │                             vendors（RSS）/ epss / osv
│  ├─ enrich/                    gemini / openai / claude / prompt / schemas / fallback
│  ├─ normalize.py               跨來源合併去重 + KEV 標記
│  ├─ score.py                   規則評分與篩選
│  ├─ verify.py                  防幻覺驗證器
│  ├─ writers/digest.py          輸出 JSON 與索引
│  └─ tests/                     37 項離線單元測試 + fixtures
├─ config/sources.json           來源開關 / 端點 / 節流設定
├─ prompts/daily_digest.md       LLM Prompt
├─ schema/digest.schema.json     資料契約（唯一真實來源）
├─ data/daily/*.json             每日日報（版控即歷史）
└─ scripts/dev-seed.mjs          離線示範資料
```

---

## 設計取捨與已知限制

- **過濾不交給 LLM**：篩選是確定性的規則（CVSS／KEV／EPSS），LLM 只負責改寫文字。
  這讓成本可控（一天 2~5 次批次呼叫）且結果可稽核。
- **只收有 CVE 編號的項目**：純 GHSA-only 的公告因無法與 NVD／KEV 交叉比對而略過
  （仍會出現在「廠商公告速覽」區塊）。
- **NVD 優先讀 gzip 資料檔**：`nvdcve-2.0-modified.json.gz` 免金鑰、無速率限制；
  API 僅作為備援。注意該檔同時有「傳輸層 gzip」與「檔案本身 .gz」兩層壓縮，程式已處理。
- **廠商來源以 RSS/Atom 為主**：不用 HTML 爬蟲，避免版型變動造成脆弱性。
  CISA Alerts RSS 對非瀏覽器請求回應 403，預設停用。
- **Vercel Hobby 僅限非商業用途**；若要營利需升級 Pro。
- 資料為自動彙整，實際處置請以廠商官方公告為準。

---

## 授權與資料來源

程式碼：本專案自行撰寫。資料來源授權：
NVD（美國政府公眾領域）、CISA KEV（美國政府公開資料）、
GitHub Advisory Database（CC-BY-4.0）、FIRST EPSS（公開資料）、各廠商公告（著作權屬原廠）。
