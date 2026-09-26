import { severityLabel, severityTextClass } from "@/lib/format";
import type { Severity } from "@/lib/types";

export function InTheWildBadge({ compact = false }: { compact?: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-[1px] text-[11px] font-medium"
      style={{
        background: "var(--danger-soft)",
        color: "var(--sev-critical)",
        border: "1px solid color-mix(in srgb, var(--sev-critical) 35%, transparent)",
      }}
      title="已知在野利用（In the Wild）"
    >
      <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: "var(--sev-critical)" }} />
      {compact ? "在野" : "在野利用"}
    </span>
  );
}

export function KevBadge({ children }: { children: React.ReactNode }) {
  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-[1px] text-[11px] font-medium"
      style={{
        background: "var(--accent-soft)",
        color: "var(--accent)",
        border: "1px solid color-mix(in srgb, var(--accent) 35%, transparent)",
      }}
    >
      {children}
    </span>
  );
}

export default function SeverityBadge({
  severity,
  score,
}: {
  severity: Severity;
  score: number | null;
}) {
  return (
    <span className={`mono inline-flex items-baseline gap-1 text-[13px] font-semibold ${severityTextClass(severity)}`}>
      {score === null ? "—" : score.toFixed(1)}
      <span className="text-[10px] font-medium" style={{ color: "var(--muted-2)" }}>
        {severityLabel(severity)}
      </span>
    </span>
  );
}
