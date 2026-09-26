import type {
  Digest,
  DigestIndex,
  DigestStats,
  Kev,
  SourceStatus,
  VendorWatchEntry,
  VulnItem,
} from "./types";

/**
 * 極輕量的執行期驗證器（刻意不引入 zod）。
 * 目的：資料檔壞掉時「明確報錯」，而不是讓頁面渲染出 undefined。
 */

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]);

export class DigestValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DigestValidationError";
  }
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DigestValidationError(`${label} 必須是物件`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

function parseKev(value: unknown): Kev | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  return {
    date_added: asNullableString(raw.date_added),
    due_date: asNullableString(raw.due_date),
    ransomware: asNullableString(raw.ransomware),
    forensic_triage: asNullableString(raw.forensic_triage),
    name_en: asNullableString(raw.name_en),
    required_action_en: asNullableString(raw.required_action_en),
  };
}

function parseItem(value: unknown, index: number): VulnItem {
  const raw = asRecord(value, `items[${index}]`);
  const cveId = asString(raw.cve_id);
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
    throw new DigestValidationError(`items[${index}].cve_id 格式錯誤：${String(raw.cve_id)}`);
  }
  const cvss = asRecord(raw.cvss ?? {}, `items[${index}].cvss`);
  const severity = asString(raw.severity, "UNKNOWN").toUpperCase();
  const epssRaw = raw.epss;
  const tags = asStringArray(raw.tags);

  return {
    cve_id: cveId,
    title_short: asString(raw.title_short, cveId),
    title_full: asString(raw.title_full, cveId),
    vendor: asString(raw.vendor),
    product: asString(raw.product),
    vendor_advisory_id: asNullableString(raw.vendor_advisory_id),
    severity: (SEVERITIES.has(severity) ? severity : "UNKNOWN") as VulnItem["severity"],
    cvss: {
      version: asNullableString(cvss.version),
      score: asNumber(cvss.score),
      vector: asNullableString(cvss.vector),
    },
    epss:
      typeof epssRaw === "object" && epssRaw !== null
        ? {
            score: asNumber((epssRaw as Record<string, unknown>).score),
            percentile: asNumber((epssRaw as Record<string, unknown>).percentile),
          }
        : null,
    cwe: asStringArray(raw.cwe),
    tags: tags.length > 0 ? tags : ["其他"],
    in_the_wild: raw.in_the_wild === true,
    kev: parseKev(raw.kev),
    summary_zh: asString(raw.summary_zh),
    impact_zh: asString(raw.impact_zh),
    action_zh: asString(raw.action_zh),
    description_en: asString(raw.description_en),
    references: Array.isArray(raw.references)
      ? raw.references
          .map((entry) => asRecord(entry, "reference"))
          .filter((entry) => typeof entry.url === "string")
          .map((entry) => ({ name: asString(entry.name, "參考"), url: String(entry.url) }))
      : [],
    affected_packages: asStringArray(raw.affected_packages),
    published: asNullableString(raw.published),
    modified: asNullableString(raw.modified),
    sources: asStringArray(raw.sources),
    rank: asNumber(raw.rank),
    generated_by: asString(raw.generated_by, "template"),
    risk_score: asNumber(raw.risk_score),
  };
}

function parseSources(value: unknown): SourceStatus[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry, index) => {
    const raw = asRecord(entry, `sources[${index}]`);
    return {
      name: asString(raw.name, `source-${index}`),
      label: asString(raw.label, asString(raw.name, "source")),
      ok: raw.ok !== false,
      items: asNumber(raw.items) ?? 0,
      error: asNullableString(raw.error),
    };
  });
}

function parseStats(value: unknown): DigestStats {
  const raw = asRecord(value ?? {}, "stats");
  return {
    scanned: asNumber(raw.scanned) ?? 0,
    kept: asNumber(raw.kept) ?? 0,
    kev: asNumber(raw.kev) ?? 0,
    critical: asNumber(raw.critical) ?? 0,
    in_the_wild: asNumber(raw.in_the_wild) ?? 0,
    sources_ok: asNumber(raw.sources_ok) ?? 0,
    sources_failed: asNumber(raw.sources_failed) ?? 0,
  };
}

function parseVendorWatch(value: unknown): VendorWatchEntry[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry, index) => {
    const raw = asRecord(entry, `vendor_watch[${index}]`);
    return {
      source: asString(raw.source, "vendor"),
      label: asString(raw.label, "廠商公告"),
      title: asString(raw.title),
      url: asString(raw.url, "#"),
      date: asNullableString(raw.date),
      cves: asStringArray(raw.cves),
    };
  });
}

export function parseDigest(value: unknown): Digest {
  const raw = asRecord(value, "digest");
  const date = asString(raw.date);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new DigestValidationError(`digest.date 格式錯誤：${String(raw.date)}`);
  }
  const window = asRecord(raw.window ?? {}, "window");
  const items = Array.isArray(raw.items) ? raw.items.map(parseItem) : [];
  return {
    schema_version: asNumber(raw.schema_version) ?? 1,
    date,
    generated_at: asString(raw.generated_at),
    generated_by: asString(raw.generated_by, "template"),
    window: { from: asString(window.from), to: asString(window.to) },
    stats: parseStats(raw.stats),
    sources: parseSources(raw.sources),
    items,
    vendor_watch: parseVendorWatch(raw.vendor_watch),
  };
}

export function parseIndex(value: unknown): DigestIndex {
  const raw = asRecord(value, "index");
  const reports = Array.isArray(raw.reports)
    ? raw.reports.map((entry) => {
        const record = asRecord(entry, "index.reports[]");
        return {
          date: asString(record.date),
          kept: asNumber(record.kept) ?? 0,
          kev: asNumber(record.kev) ?? 0,
          critical: asNumber(record.critical) ?? 0,
          in_the_wild: asNumber(record.in_the_wild) ?? 0,
          generated_at: asNullableString(record.generated_at),
          generated_by: asNullableString(record.generated_by),
          top: asStringArray(record.top),
        };
      })
    : [];
  return {
    schema_version: asNumber(raw.schema_version) ?? 1,
    updated_at: asString(raw.updated_at),
    total: asNumber(raw.total) ?? reports.length,
    reports,
  };
}
