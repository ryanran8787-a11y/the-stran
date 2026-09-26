import type { Metadata } from "next";

import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";

import "./globals.css";

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://the-stran.vercel.app";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "Security Daily · 網安每日報",
    template: "%s · Security Daily",
  },
  description:
    "每日自動彙整 CVE / CISA KEV 在野利用清單 / GitHub Advisory / EPSS 與各大廠商安全公告，經規則篩選與 LLM 提煉成正體中文資安日報。",
  keywords: ["CVE", "CISA KEV", "資安日報", "漏洞", "在野利用", "CVSS", "EPSS", "security advisory"],
  openGraph: {
    type: "website",
    locale: "zh_TW",
    siteName: "Security Daily",
    title: "Security Daily · 網安每日報",
    description: "每日高危漏洞與在野利用情報，自動彙整並以正體中文呈現。",
  },
  twitter: { card: "summary_large_image" },
  robots: { index: true, follow: true },
  alternates: {
    types: {
      "application/rss+xml": "/feed.xml",
      "application/feed+json": "/feed.json",
    },
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-Hant">
      <body className="min-h-screen antialiased">
        <SiteHeader />
        <main className="mx-auto max-w-5xl px-4 pt-8 sm:px-6">{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}
