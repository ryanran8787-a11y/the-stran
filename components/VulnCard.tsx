import {
  dueCountdown,
  epssText,
  formatDateTime,
  nvdUrl,
  scoreText,
  severityBarClass,
  sourceLabel,
  vendorProduct,
} from "@/lib/format";
import type { VulnItem } from "@/lib/types";

import { InTheWildBadge, KevBadge } from "./SeverityBadge";

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
        {label}
      </dt>
      <dd className="mt-0.5 text-[12.5px]">{value}</dd>
    </div>
  );
}

export default function VulnCard({ item, today }: { item: VulnItem; today: string }) {
  const countdown = dueCountdown(item.kev?.due_date ?? null, today);
  const epss = epssText(item);

  return (
    <article className="card relative overflow-hidden">
      <div className={`absolute inset-y-0 left-0 w-[3px] ${severityBarClass(item.severity)}`} />

      <div className="py-4 pl-5 pr-4 sm:pl-6 sm:pr-5">
        <div className="flex items-start gap-2">
          <h3 className="zh text-[15px] font-semibold leading-snug tracking-tight">
            {item.title_short}
          </h3>
          <div className="ml-auto flex shrink-0 items-center gap-1.5">
            {item.in_the_wild ? <InTheWildBadge compact /> : null}
            <span className="mono text-[13px] font-semibold tabular-nums">{scoreText(item)}</span>
          </div>
        </div>

        <div
          className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]"
          style={{ color: "var(--muted)" }}
        >
          <span>{vendorProduct(item)}</span>
          <a className="mono link-quiet" href={nvdUrl(item.cve_id)} target="_blank" rel="noreferrer">
            {item.cve_id}
          </a>
          {item.vendor_advisory_id ? (
            <span className="mono" style={{ color: "var(--muted-2)" }}>
              {item.vendor_advisory_id}
            </span>
          ) : null}
          {item.kev ? <KevBadge>KEV{countdown ? ` · ${countdown}` : ""}</KevBadge> : null}
        </div>

        <p className="zh mt-3 text-[13.5px] leading-relaxed">{item.summary_zh}</p>

        {item.tags.length > 0 ? (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {item.tags.map((tag) => (
              <span key={tag} className="chip">
                {tag}
              </span>
            ))}
          </div>
        ) : null}

        {item.impact_zh || item.action_zh ? (
          <div className="mt-3 space-y-1.5 border-t pt-3 text-[13px]">
            {item.impact_zh ? (
              <p className="zh">
                <span className="font-medium" style={{ color: "var(--muted-2)" }}>
                  衝擊　
                </span>
                {item.impact_zh}
              </p>
            ) : null}
            {item.action_zh ? (
              <p className="zh">
                <span className="font-medium" style={{ color: "var(--muted-2)" }}>
                  處置　
                </span>
                {item.action_zh}
              </p>
            ) : null}
          </div>
        ) : null}
      </div>
    </article>
  );
}
