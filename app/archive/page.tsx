import type { Metadata } from "next";

import ArchiveCard from "@/components/ArchiveCard";
import { getIndex } from "@/lib/data";

export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "歷史存檔",
  description: "所有已發佈的網安每日報存檔，可依日期瀏覽每日高危漏洞與在野利用情報。",
  alternates: { canonical: "/archive" },
};

export default function ArchivePage() {
  const index = getIndex();

  if (index.reports.length === 0) {
    return (
      <section className="py-20 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">尚無存檔</h1>
        <p className="mt-3 text-[14px]" style={{ color: "var(--muted)" }}>
          執行管線後即會出現每日存檔。
        </p>
      </section>
    );
  }

  const totalKept = index.reports.reduce((sum, entry) => sum + entry.kept, 0);
  const totalWild = index.reports.reduce((sum, entry) => sum + entry.in_the_wild, 0);
  const totalKev = index.reports.reduce((sum, entry) => sum + entry.kev, 0);

  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">歷史存檔</h1>
      <p className="mt-2 text-[13.5px]" style={{ color: "var(--muted)" }}>
        共 {index.reports.length} 期 · 累計收錄 <span className="mono">{totalKept}</span> 筆 ·
        在野利用 <span className="mono">{totalWild}</span> 筆 · KEV{" "}
        <span className="mono">{totalKev}</span> 筆
      </p>
      <p className="mt-1 text-[12px]" style={{ color: "var(--muted-2)" }}>
        索引更新於 {index.updated_at || "—"}
      </p>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {index.reports.map((entry) => (
          <ArchiveCard key={entry.date} entry={entry} />
        ))}
      </div>
    </>
  );
}
