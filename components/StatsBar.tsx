import type { DigestStats } from "@/lib/types";

function Stat({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: string | number;
  hint?: string;
  accent?: boolean;
}) {
  return (
    <div className="border-l px-3 py-1 first:border-l-0 first:pl-0 sm:px-4">
      <div
        className="text-[11px] font-medium uppercase tracking-wider"
        style={{ color: "var(--muted-2)" }}
      >
        {label}
      </div>
      <div
        className="mono mt-0.5 text-xl font-semibold tabular-nums sm:text-2xl"
        style={accent ? { color: "var(--sev-critical)" } : undefined}
      >
        {value}
      </div>
      {hint ? (
        <div className="mt-0.5 text-[11px]" style={{ color: "var(--muted-2)" }}>
          {hint}
        </div>
      ) : null}
    </div>
  );
}

export default function StatsBar({ stats }: { stats: DigestStats }) {
  return (
    <div className="card flex flex-wrap items-stretch overflow-hidden">
      <div className="flex flex-1 flex-wrap">
        <Stat label="掃描" value={stats.scanned} hint="上游變更筆數" />
        <Stat label="入選" value={stats.kept} hint="通過高危篩選" />
        <Stat label="在野利用" value={stats.in_the_wild} accent={stats.in_the_wild > 0} />
        <Stat label="KEV" value={stats.kev} accent={stats.kev > 0} hint="CISA 已知被利用" />
        <Stat label="重大" value={stats.critical} hint="CVSS ≥ 9.0" />
      </div>
      <div
        className="flex w-full items-center border-t px-4 py-2 text-[11px] sm:w-auto sm:border-l sm:border-t-0"
        style={{ color: "var(--muted-2)" }}
      >
        來源 {stats.sources_ok} 成功
        {stats.sources_failed > 0 ? ` · ${stats.sources_failed} 失敗` : ""}
      </div>
    </div>
  );
}
