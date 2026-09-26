import type { Metadata } from "next";
import { notFound } from "next/navigation";

import FilterableList from "@/components/FilterableList";
import ReportHeader, { SourcesTable } from "@/components/ReportHeader";
import StatsBar from "@/components/StatsBar";
import VendorWatch from "@/components/VendorWatch";
import { getIndex, getReport, listReportDates, nextDate, previousDate } from "@/lib/data";

export const dynamic = "force-static";

export function generateStaticParams() {
  return listReportDates().map((date) => ({ date }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ date: string }>;
}): Promise<Metadata> {
  const { date } = await params;
  const digest = getReport(date);
  if (!digest) return { title: `${date} 資安日報` };
  const wild = digest.stats.in_the_wild > 0 ? ` · 在野利用 ${digest.stats.in_the_wild} 筆` : "";
  return {
    title: `${date} 資安日報`,
    description: `收錄 ${digest.stats.kept} 筆高危漏洞（掃描 ${digest.stats.scanned} 筆），其中 KEV ${digest.stats.kev} 筆${wild}。`,
    alternates: { canonical: `/report/${date}` },
    openGraph: {
      title: `${date} 資安日報 · Security Daily`,
      description: `${digest.items
        .slice(0, 3)
        .map((item) => item.title_short)
        .join("、")}`,
    },
  };
}

export default async function ReportPage({ params }: { params: Promise<{ date: string }> }) {
  const { date } = await params;
  const digest = getReport(date);
  if (!digest) notFound();

  const index = getIndex();
  const editionEntry = index.reports.find((entry) => entry.date === date);
  const edition = editionEntry ? index.reports.length - index.reports.indexOf(editionEntry) : null;

  return (
    <>
      <ReportHeader
        digest={digest}
        edition={edition}
        prev={previousDate(date)}
        next={nextDate(date)}
      />
      <div className="mt-6">
        <StatsBar stats={digest.stats} />
      </div>
      <FilterableList items={digest.items} today={digest.date} />
      <VendorWatch entries={digest.vendor_watch} />
      <SourcesTable digest={digest} />
    </>
  );
}
