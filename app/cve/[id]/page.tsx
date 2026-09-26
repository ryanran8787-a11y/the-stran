import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import ReportHeader from "@/components/ReportHeader";
import VulnCard from "@/components/VulnCard";
import { getAllCves, getReport } from "@/lib/data";
import { formatDateTime, nvdUrl, sourceLabel, vendorProduct } from "@/lib/format";

export const dynamic = "force-static";

export function generateStaticParams() {
  return Array.from(getAllCves().keys()).map((id) => ({ id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const record = getAllCves().get(id.toUpperCase());
  if (!record) return { title: `${id} 漏洞資訊` };
  return {
    title: `${record.item.title_short}`,
    description: `${record.item.cve_id}｜${vendorProduct(record.item)}｜${record.item.summary_zh}`,
    alternates: { canonical: `/cve/${record.item.cve_id}` },
  };
}

export default async function CvePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const record = getAllCves().get(id.toUpperCase());
  if (!record) notFound();

  const digest = getReport(record.date);
  const item = record.item;

  return (
    <>
      <p className="text-[13px]">
        <Link className="link-quiet" href={`/report/${record.date}`}>
          ← 回到 {record.date} 日報
        </Link>
      </p>

      <h1 className="mt-4 text-xl font-semibold tracking-tight sm:text-2xl">{item.title_full}</h1>

      <dl className="card mt-4 grid grid-cols-2 gap-x-4 gap-y-3 p-4 sm:grid-cols-4">
        <div>
          <dt className="text-[11px] uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
            CVE
          </dt>
          <dd className="mono mt-0.5 text-[13px]">
            <a href={nvdUrl(item.cve_id)} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>
              {item.cve_id}
            </a>
          </dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
            廠商 / 產品
          </dt>
          <dd className="mt-0.5 text-[13px]">{vendorProduct(item)}</dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
            來源
          </dt>
          <dd className="mt-0.5 text-[13px]">{item.sources.map(sourceLabel).join(" · ")}</dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
            首次收錄
          </dt>
          <dd className="mt-0.5 text-[13px]">{formatDateTime(item.published)}</dd>
        </div>
      </dl>

      <div className="mt-4">
        <VulnCard item={item} today={digest?.date ?? record.date} />
      </div>

      {digest ? (
        <p className="mt-4 text-[12.5px]" style={{ color: "var(--muted-2)" }}>
          本頁資料取自 {record.date} 日報（該期共收錄 {digest.stats.kept} 筆）。同一 CVE
          若在後續期別再次出現，本頁顯示的是最新一次收錄的版本。
        </p>
      ) : null}
    </>
  );
}
