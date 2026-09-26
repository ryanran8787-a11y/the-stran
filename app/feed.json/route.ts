import { getAllReports, getLatestReport } from "@/lib/data";

export const dynamic = "force-static";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://the-stran.vercel.app";
const MAX_ITEMS = 60;
const MAX_DAYS = 7;

export function GET() {
  const latest = getLatestReport();
  const reports = getAllReports().slice(0, MAX_DAYS);

  const items: Record<string, unknown>[] = [];
  for (const digest of reports) {
    for (const item of digest.items) {
      if (items.length >= MAX_ITEMS) break;
      items.push({
        id: `${digest.date}-${item.cve_id}`,
        url: `${SITE}/cve/${item.cve_id}`,
        title: item.title_short,
        content_text: [item.summary_zh, item.impact_zh, item.action_zh].filter(Boolean).join("\n"),
        date_published: item.published ?? `${digest.date}T00:00:00Z`,
        date_modified: item.modified ?? undefined,
        tags: item.tags,
        _cve: item.cve_id,
        _severity: item.severity,
        _in_the_wild: item.in_the_wild,
      });
    }
  }

  const payload = {
    version: "https://jsonfeed.org/version/1.1",
    title: "Security Daily · 網安每日報",
    home_page_url: SITE,
    feed_url: `${SITE}/feed.json`,
    description: "每日高危漏洞與在野利用情報（CVE / CISA KEV / GitHub Advisory / EPSS）",
    language: "zh-TW",
    authors: [{ name: "Security Daily" }],
    items,
  };

  return new Response(JSON.stringify(payload, null, 2), {
    headers: {
      "Content-Type": "application/feed+json; charset=utf-8",
      "Cache-Control": "public, max-age=0, s-maxage=3600",
    },
  });
}
