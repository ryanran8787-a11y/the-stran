import Link from "next/link";

import { formatDateTime, weekdayZh } from "@/lib/format";
import type { IndexEntry } from "@/lib/types";

export default function ArchiveCard({ entry }: { entry: IndexEntry }) {
  return (
    <Link
      href={`/report/${entry.date}`}
      className="card group block p-4 transition-colors hover:bg-[var(--card-hover)]"
    >
      <div className="flex items-baseline gap-2">
        <span className="mono text-[15px] font-semibold tracking-tight">{entry.date}</span>
        <span className="text-[12px]" style={{ color: "var(--muted-2)" }}>
          {weekdayZh(entry.date)}
        </span>
        {entry.in_the_wild > 0 ? (
          <span
            className="ml-auto shrink-0 rounded-full px-2 py-[1px] text-[11px]"
            style={{ background: "var(--danger-soft)", color: "var(--sev-critical)" }}
          >
            在野 {entry.in_the_wild}
          </span>
        ) : null}
      </div>

      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[12px]" style={{ color: "var(--muted)" }}>
        <span>
          收錄 <span className="mono">{entry.kept}</span>
        </span>
        <span>
          重大 <span className="mono">{entry.critical}</span>
        </span>
        <span>
          KEV <span className="mono">{entry.kev}</span>
        </span>
      </div>

      {entry.top.length > 0 ? (
        <ul className="mt-2.5 space-y-1 text-[12.5px]" style={{ color: "var(--muted)" }}>
          {entry.top.map((title, index) => (
            <li key={`${entry.date}-${index}`} className="zh truncate">
              · {title}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-2.5 text-[12.5px]" style={{ color: "var(--muted-2)" }}>
          當日無符合門檻的項目。
        </p>
      )}

      {entry.generated_at ? (
        <div className="mt-3 border-t pt-2 text-[11px]" style={{ color: "var(--muted-2)" }}>
          產生於 {formatDateTime(entry.generated_at)}
        </div>
      ) : null}
    </Link>
  );
}
