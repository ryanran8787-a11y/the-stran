export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface Cvss {
  version: string | null;
  score: number | null;
  vector: string | null;
}

export interface Epss {
  score: number | null;
  percentile: number | null;
}

export interface Kev {
  date_added: string | null;
  due_date: string | null;
  ransomware: string | null;
  forensic_triage: string | null;
  name_en?: string | null;
  required_action_en?: string | null;
}

export interface Reference {
  name: string;
  url: string;
}

export interface VulnItem {
  cve_id: string;
  title_short: string;
  title_full: string;
  vendor: string;
  product: string;
  vendor_advisory_id: string | null;
  severity: Severity;
  cvss: Cvss;
  epss: Epss | null;
  cwe: string[];
  tags: string[];
  in_the_wild: boolean;
  kev: Kev | null;
  summary_zh: string;
  impact_zh: string;
  action_zh: string;
  description_en: string;
  references: Reference[];
  affected_packages: string[];
  published: string | null;
  modified: string | null;
  sources: string[];
  rank: number | null;
  generated_by: string;
  risk_score: number | null;
}

export interface SourceStatus {
  name: string;
  label: string;
  ok: boolean;
  items: number;
  error: string | null;
}

export interface DigestStats {
  scanned: number;
  kept: number;
  kev: number;
  critical: number;
  in_the_wild: number;
  sources_ok: number;
  sources_failed: number;
}

export interface VendorWatchEntry {
  source: string;
  label: string;
  title: string;
  url: string;
  date: string | null;
  cves: string[];
}

export interface Digest {
  schema_version: number;
  date: string;
  generated_at: string;
  generated_by: string;
  window: { from: string; to: string };
  stats: DigestStats;
  sources: SourceStatus[];
  items: VulnItem[];
  vendor_watch: VendorWatchEntry[];
}

export interface IndexEntry {
  date: string;
  kept: number;
  kev: number;
  critical: number;
  in_the_wild: number;
  generated_at: string | null;
  generated_by: string | null;
  top: string[];
}

export interface DigestIndex {
  schema_version: number;
  updated_at: string;
  total: number;
  reports: IndexEntry[];
}
