import { formatDateTime } from "@/lib/format";
import type { VendorWatchEntry } from "@/lib/types";

export default function VendorWatch({ entries }: { entries: VendorWatchEntry[] }) {
  if (entries.length === 0) return null;

  return (
    <section className="mt-10">
      <h2 className="text-[13px] font-medium uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
        廠商公告速覽
      </h2>
      <p className="mt-1 text-[12.5px]" style={{ color: "var(--muted)" }}>
        當日抓取到的廠商 / 組織公告。未達 CVSS 或未取得分數者不列入上方日報，但在這裡保留線索。
      </p>
      <ul className="card mt-3 divide-y overflow-hidden">
        {entries.map((entry) => (
          <li key={`${entry.source}-${entry.url}`} className="px-4 py-3">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="chip shrink-0">{entry.label}</span>
              <a
                className="zh text-[13.5px] font-medium hover:underline"
                href={entry.url}
                target="_blank"
                rel="noreferrer"
              >
                {entry.title}
              </a>
              <span className="ml-auto shrink-0 text-[12px]" style={{ color: "var(--muted-2)" }}>
                {formatDateTime(entry.date)}
              </span>
            </div>
            {entry.cves.length > 0 ? (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {entry.cves.map((cve) => (
                  <a key={cve} className="mono text-[11.5px]" style={{ color: "var(--accent)" }} href={`/cve/${cve}`}>
                    {cve}
                  </a>
                ))}
              </div>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}
