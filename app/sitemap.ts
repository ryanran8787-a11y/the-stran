import type { MetadataRoute } from "next";

import { getAllCves, getIndex, listReportDates } from "@/lib/data";

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://the-stran.vercel.app";
const MAX_CVE_URLS = 2000;

export default function sitemap(): MetadataRoute.Sitemap {
  const dates = listReportDates();
  const latest = dates[0];
  const index = getIndex();

  const entries: MetadataRoute.Sitemap = [
    {
      url: SITE,
      lastModified: latest ? `${latest}T00:00:00Z` : undefined,
      changeFrequency: "daily",
      priority: 1,
    },
    {
      url: `${SITE}/archive`,
      lastModified: latest ? `${latest}T00:00:00Z` : undefined,
      changeFrequency: "daily",
      priority: 0.8,
    },
  ];

  for (const date of dates) {
    entries.push({
      url: `${SITE}/report/${date}`,
      lastModified: `${date}T00:00:00Z`,
      changeFrequency: "never",
      priority: 0.9,
    });
  }

  let count = 0;
  for (const [cveId, record] of getAllCves()) {
    if (count >= MAX_CVE_URLS) break;
    count += 1;
    entries.push({
      url: `${SITE}/cve/${cveId}`,
      lastModified: `${record.date}T00:00:00Z`,
      changeFrequency: "never",
      priority: 0.6,
    });
  }

  void index;
  return entries;
}
