import Link from "next/link";

import ArchiveCard from "@/components/ArchiveCard";
import FilterableList from "@/components/FilterableList";
import ReportHeader, { SourcesTable } from "@/components/ReportHeader";
import StatsBar from "@/components/StatsBar";
import VendorWatch from "@/components/VendorWatch";
import { getIndex, getLatestReport } from "@/lib/data";

export const dynamic = "force-static";

export default function HomePage() {
  const digest = getLatestReport();
  const index = getIndex();

  if (!digest) {
    return (
      <section className="py-20 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">還沒有資料</h1>
        <p className="mt-3 text-[14px]" style={{ color: "var(--muted)" }}>
          執行 <code className="mono">python -m pipeline --date today</code> 產生第一期日報，
          或到 GitHub Actions 手動觸發 <code className="mono">daily</code> workflow。
        </p>
        <p className="mt-4">
          <Link className="btn" href="/archive">
            查看存檔
          </Link>
        </p>
      </section>
    );
  }

  const previousEdition = index.reports.find((entry) => entry.date < digest.date) ?? null;

  return (
    <>
      <ReportHeader digest={digest} edition={index.total} prev={previousEdition?.date ?? null} next={null} />
      <div className="mt-6">
        <StatsBar stats={digest.stats} />
      </div>
      <FilterableList items={digest.items} today={digest.date} />
      <VendorWatch entries={digest.vendor_watch} />
      {index.reports.length > 1 ? (
        <section className="mt-10">
          <h2 className="text-[13px] font-medium uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
            近期存檔
          </h2>
          <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {index.reports.slice(1, 7).map((entry) => (
              <ArchiveCard key={entry.date} entry={entry} />
            ))}
          </div>
          <p className="mt-3 text-[13px]">
            <Link className="link-quiet" href="/archive">
              查看全部 {index.reports.length} 期 →
            </Link>
          </p>
        </section>
      ) : null}
      <SourcesTable digest={digest} />
    </>
  );
}
