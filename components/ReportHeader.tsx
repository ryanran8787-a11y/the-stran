import Link from "next/link";

import { formatDateZh, formatWindow, sourceLabel, weekdayZh } from "@/lib/format";
import type { Digest } from "@/lib/types";

function Pill({ children, tone = "quiet" }: { children: React.ReactNode; tone?: "quiet" | "accent" }) {
  return (
    <span
      className="inline-flex items-center rounded-full border px-2.5 py-[2px] text-[12px]"
      style={
        tone === "accent"
          ? {
              color: "var(--accent)",
              background: "var(--accent-soft)",
              borderColor: "color-mix(in srgb, var(--accent) 35%, transparent)",
            }
          : { color: "var(--muted)" }
      }
    >
      {children}
    </span>
  );
}

export default function ReportHeader({
  digest,
  edition,
  prev,
  next,
}: {
  digest: Digest;
  edition: number | null;
  prev: string | null;
  next: string | null;
}) {
  const isSeed = digest.generated_by.startsWith("seed");
  const generator = digest.generated_by === "template" ? "規則模板" : digest.generated_by;

  return (
    <section>
      <div className="flex flex-wrap items-end gap-x-3 gap-y-1">
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
          {formatDateZh(digest.date)}
        </h1>
        <span className="pb-1 text-[13px]" style={{ color: "var(--muted)" }}>
          {weekdayZh(digest.date)}
        </span>
        {edition ? (
          <span className="pb-1 text-[13px]" style={{ color: "var(--muted-2)" }}>
            第 {edition} 期
          </span>
        ) : null}
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
        <Pill>資料窗 {formatWindow(digest.window.from, digest.window.to)}</Pill>
        <Pill tone="accent">提煉：{generator}</Pill>
        {digest.stats.in_the_wild > 0 ? <Pill tone="accent">在野利用 {digest.stats.in_the_wild}</Pill> : null}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2 text-[13px]">
        <Link className="btn" href="/archive">
          歷史存檔
        </Link>
        {next ? (
          <Link className="btn" href={`/report/${next}`}>
            ← {next}
          </Link>
        ) : null}
        {prev ? (
          <Link className="btn" href={`/report/${prev}`}>
            {prev} →
          </Link>
        ) : null}
        <Link className="btn" href="/feed.xml">
          RSS 訂閱
        </Link>
      </div>

      {isSeed ? (
        <div
          className="mt-4 rounded-lg border px-3 py-2 text-[12.5px]"
          style={{ background: "var(--accent-soft)", color: "var(--accent)" }}
        >
          本頁是初始示範資料。執行 <code className="mono">python -m pipeline --date today</code>{" "}
          後會被真實資料取代（示範資料不會出現在正式站台）。
        </div>
      ) : null}
    </section>
  );
}

export function SourcesTable({ digest }: { digest: Digest }) {
  if (digest.sources.length === 0) return null;
  return (
    <section className="mt-10">
      <h2 className="text-[13px] font-medium uppercase tracking-wider" style={{ color: "var(--muted-2)" }}>
        本期來源狀態
      </h2>
      <div className="card mt-3 divide-y overflow-hidden">
        {digest.sources.map((source) => (
          <div key={source.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-[13px]">
            <span
              className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
              style={{ background: source.ok ? "var(--accent)" : "var(--sev-critical)" }}
            />
            <span className="font-medium">{source.label || sourceLabel(source.name)}</span>
            <span className="mono" style={{ color: "var(--muted-2)" }}>
              {source.name}
            </span>
            <span className="ml-auto mono tabular-nums" style={{ color: "var(--muted)" }}>
              {source.items} 筆
            </span>
            {!source.ok && source.error ? (
              <span className="w-full text-[12px]" style={{ color: "var(--sev-critical)" }}>
                {source.error}
              </span>
            ) : null}
          </div>
        ))}
      </div>
      <p className="mt-2 text-[12px]" style={{ color: "var(--muted-2)" }}>
        單一來源失敗會被隔離，不影響整期產出；失敗會在 GitHub Actions 記錄中留下警告。
      </p>
    </section>
  );
}
