import { getAllReports, getLatestReport } from "@/lib/data";

export const dynamic = "force-static";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://the-stran.vercel.app";
const MAX_ITEMS = 60;
const MAX_DAYS = 7;

function escapeXml(value: string): string {
  return (value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function pubDate(iso: string | null, fallbackDate: string): string {
  const parsed = iso ? new Date(iso) : new Date(`${fallbackDate}T00:00:00Z`);
  const valid = Number.isNaN(parsed.getTime()) ? new Date(`${fallbackDate}T00:00:00Z`) : parsed;
  return valid.toUTCString();
}

export function GET() {
  const latest = getLatestReport();
  const reports = getAllReports().slice(0, MAX_DAYS);

  const entries: string[] = [];
  for (const digest of reports) {
    for (const item of digest.items) {
      if (entries.length >= MAX_ITEMS) break;
      const url = `${SITE}/cve/${item.cve_id}`;
      const description = [item.summary_zh, item.impact_zh && `衝擊：${item.impact_zh}`, item.action_zh && `處置：${item.action_zh}`]
        .filter(Boolean)
        .join("\n");
      entries.push(
        [
          "    <item>",
          `      <title>${escapeXml(item.title_short)}</title>`,
          `      <link>${escapeXml(url)}</link>`,
          `      <guid isPermaLink="false">${escapeXml(`${digest.date}-${item.cve_id}`)}</guid>`,
          `      <pubDate>${pubDate(item.published, digest.date)}</pubDate>`,
          `      <category>${escapeXml(item.tags.join(", ") || "其他")}</category>`,
          `      <description>${escapeXml(description)}</description>`,
          "    </item>",
        ].join("\n"),
      );
    }
  }

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    "  <channel>",
    "    <title>Security Daily · 網安每日報</title>",
    `    <link>${SITE}</link>`,
    "    <description>每日高危漏洞與在野利用情報（CVE / CISA KEV / GitHub Advisory / EPSS）</description>",
    "    <language>zh-TW</language>",
    `    <lastBuildDate>${pubDate(latest?.generated_at ?? null, latest?.date ?? "1970-01-01")}</lastBuildDate>`,
    `    <atom:link href="${SITE}/feed.xml" rel="self" type="application/rss+xml" />`,
    entries.join("\n"),
    "  </channel>",
    "</rss>",
    "",
  ]
    .filter(Boolean)
    .join("\n");

  return new Response(xml, {
    headers: {
      "Content-Type": "application/rss+xml; charset=utf-8",
      "Cache-Control": "public, max-age=0, s-maxage=3600",
    },
  });
}
