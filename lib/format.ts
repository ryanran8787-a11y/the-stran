import type { Severity, VulnItem } from "./types";

const WEEKDAYS = ["日", "一", "二", "三", "四", "五", "六"];

export function formatDateZh(date: string): string {
  const [year, month, day] = date.split("-");
  return `${year} 年 ${Number(month)} 月 ${Number(day)} 日`;
}

export function weekdayZh(date: string): string {
  const parsed = new Date(`${date}T00:00:00Z`);
  return `星期${WEEKDAYS[parsed.getUTCDay()]}`;
}

export function formatWindow(from: string, to: string): string {
  const start = new Date(from);
  const end = new Date(to);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "";
  const fmt = (value: Date) =>
    new Intl.DateTimeFormat("zh-TW", {
      timeZone: "Asia/Taipei",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(value);
  return `${fmt(start)} – ${fmt(end)}（台北時間）`;
}

export function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return new Intl.DateTimeFormat("zh-TW", {
    timeZone: "Asia/Taipei",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(parsed);
}

export function scoreText(item: VulnItem): string {
  const score = item.cvss.score;
  if (score === null || score === undefined) return "N/A";
  return score.toFixed(1);
}

export function epssText(item: VulnItem): string | null {
  const score = item.epss?.score;
  if (score === null || score === undefined) return null;
  return score.toFixed(3);
}

export function severityLabel(severity: Severity): string {
  switch (severity) {
    case "CRITICAL":
      return "重大";
    case "HIGH":
      return "高";
    case "MEDIUM":
      return "中";
    case "LOW":
      return "低";
    default:
      return "未知";
  }
}

const SEVERITY_BAR: Record<Severity, string> = {
  CRITICAL: "bg-[var(--sev-critical)]",
  HIGH: "bg-[var(--sev-high)]",
  MEDIUM: "bg-[var(--sev-medium)]",
  LOW: "bg-[var(--sev-low)]",
  UNKNOWN: "bg-[var(--border)]",
};

const SEVERITY_TEXT: Record<Severity, string> = {
  CRITICAL: "text-[var(--sev-critical)]",
  HIGH: "text-[var(--sev-high)]",
  MEDIUM: "text-[var(--sev-medium)]",
  LOW: "text-[var(--sev-low)]",
  UNKNOWN: "text-[var(--muted)]",
};

export function severityBarClass(severity: Severity): string {
  return SEVERITY_BAR[severity] ?? SEVERITY_BAR.UNKNOWN;
}

export function severityTextClass(severity: Severity): string {
  return SEVERITY_TEXT[severity] ?? SEVERITY_TEXT.UNKNOWN;
}

/** KEV 到期倒數（相對天數）。 */
export function dueCountdown(dueDate: string | null, today: string): string | null {
  if (!dueDate) return null;
  const due = new Date(`${dueDate}T00:00:00Z`).getTime();
  const now = new Date(`${today}T00:00:00Z`).getTime();
  if (Number.isNaN(due) || Number.isNaN(now)) return null;
  const days = Math.round((due - now) / 86_400_000);
  if (days > 1) return `剩 ${days} 天`;
  if (days === 1) return "剩 1 天";
  if (days === 0) return "今天到期";
  return `逾期 ${Math.abs(days)} 天`;
}

export function sourceLabel(name: string): string {
  const labels: Record<string, string> = {
    cisa_kev: "CISA KEV",
    nvd: "NVD",
    ghsa: "GitHub",
    osv: "OSV",
    epss: "EPSS",
    cisco: "Cisco",
    fortinet: "Fortinet",
    zdi: "ZDI",
    cisa_alerts: "CISA",
    jenkins: "Jenkins",
    vendors: "廠商公告",
  };
  return labels[name] ?? name;
}

export function vendorProduct(item: VulnItem): string {
  const vendor = item.vendor?.trim() ?? "";
  const product = item.product?.trim() ?? "";
  if (!vendor && !product) return "未標示";
  if (!product) return vendor;
  if (!vendor) return product;
  if (vendor.toLowerCase() === product.toLowerCase()) return vendor;
  return `${vendor} · ${product}`;
}

export function nvdUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}
