export default function SiteFooter() {
  return (
    <footer className="mt-16 border-t">
      <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
        <div className="grid gap-6 sm:grid-cols-3">
          <div>
            <div className="text-[15px] font-semibold tracking-tight">Security Daily</div>
            <p className="mt-2 text-[13px] leading-relaxed" style={{ color: "var(--muted)" }}>
              自動彙整 CVE / CISA KEV / GitHub Advisory / EPSS 與廠商公告，
              以規則篩選 + LLM 提煉成正體中文資安日報。
            </p>
          </div>
          <div>
            <div className="text-[12px] font-medium uppercase tracking-wide" style={{ color: "var(--muted-2)" }}>
              資料來源
            </div>
            <ul className="mt-2 space-y-1 text-[13px]">
              <li>
                <a className="link-quiet" href="https://nvd.nist.gov" target="_blank" rel="noreferrer">
                  NVD（公眾領域）
                </a>
              </li>
              <li>
                <a
                  className="link-quiet"
                  href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                  target="_blank"
                  rel="noreferrer"
                >
                  CISA KEV
                </a>
              </li>
              <li>
                <a
                  className="link-quiet"
                  href="https://github.com/advisories"
                  target="_blank"
                  rel="noreferrer"
                >
                  GitHub Advisory Database（CC-BY-4.0）
                </a>
              </li>
              <li>
                <a className="link-quiet" href="https://www.first.org/epss/" target="_blank" rel="noreferrer">
                  FIRST EPSS
                </a>
              </li>
            </ul>
          </div>
          <div>
            <div className="text-[12px] font-medium uppercase tracking-wide" style={{ color: "var(--muted-2)" }}>
              說明
            </div>
            <p className="mt-2 text-[13px] leading-relaxed" style={{ color: "var(--muted)" }}>
              標題格式為「廠商 產品 CVE尾號×CVSS（在野）」。所有分數與編號皆直接來自上游資料，
              LLM 僅負責改寫文字，並經驗證器交叉檢查。
            </p>
          </div>
        </div>
        <div className="mt-8 flex flex-wrap items-center gap-x-4 gap-y-2 border-t pt-6 text-[12px]" style={{ color: "var(--muted-2)" }}>
          <span>© {new Date().getFullYear()} the-stran</span>
          <a className="link-quiet" href="/feed.xml">
            RSS
          </a>
          <a className="link-quiet" href="/feed.json">
            JSON Feed
          </a>
          <a className="link-quiet" href="/sitemap.xml">
            Sitemap
          </a>
          <span className="ml-auto">資料為自動彙整，實際處置請以廠商官方公告為準。</span>
        </div>
      </div>
    </footer>
  );
}
