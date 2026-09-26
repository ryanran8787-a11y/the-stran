import fs from "node:fs";
import path from "node:path";

import { parseDigest, parseIndex } from "./schema";
import type { Digest, DigestIndex, VulnItem } from "./types";

/**
 * 建置期資料讀取（SSG）。所有頁面在 `next build` 時就把 JSON 讀完，
 * 產生純靜態 HTML，不需要任何執行期檔案存取。
 */

const DATA_DIR = path.join(process.cwd(), "data");
const DAILY_DIR = path.join(DATA_DIR, "daily");
const INDEX_FILE = path.join(DATA_DIR, "index.json");

let digestCache: Map<string, Digest> | null = null;

function readJsonFile(file: string): unknown {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function listReportDates(): string[] {
  if (!fs.existsSync(DAILY_DIR)) return [];
  return fs
    .readdirSync(DAILY_DIR)
    .filter((name) => /^\d{4}-\d{2}-\d{2}\.json$/.test(name))
    .map((name) => name.replace(/\.json$/, ""))
    .sort()
    .reverse();
}

function loadAll(): Map<string, Digest> {
  if (digestCache) return digestCache;
  const cache = new Map<string, Digest>();
  for (const date of listReportDates()) {
    try {
      const digest = parseDigest(readJsonFile(path.join(DAILY_DIR, `${date}.json`)));
      cache.set(digest.date, digest);
    } catch (error) {
      // 單一期壞檔不可讓整個站台建置失敗
      console.error(`[data] 略過無法解析的日報 ${date}.json：`, error);
    }
  }
  digestCache = cache;
  return cache;
}

export function getReport(date: string): Digest | null {
  return loadAll().get(date) ?? null;
}

export function getLatestReport(): Digest | null {
  const dates = listReportDates();
  return dates.length > 0 ? getReport(dates[0]) : null;
}

export function getAllReports(): Digest[] {
  return Array.from(loadAll().values()).sort((a, b) => (a.date < b.date ? 1 : -1));
}

export function getIndex(): DigestIndex {
  if (fs.existsSync(INDEX_FILE)) {
    try {
      return parseIndex(readJsonFile(INDEX_FILE));
    } catch (error) {
      console.error("[data] index.json 解析失敗，改由日報檔重建：", error);
    }
  }
  const reports = getAllReports().map((digest) => ({
    date: digest.date,
    kept: digest.stats.kept,
    kev: digest.stats.kev,
    critical: digest.stats.critical,
    in_the_wild: digest.stats.in_the_wild,
    generated_at: digest.generated_at,
    generated_by: digest.generated_by,
    top: digest.items.slice(0, 3).map((item) => item.title_short || item.cve_id),
  }));
  return {
    schema_version: 1,
    updated_at: reports[0]?.generated_at ?? "",
    total: reports.length,
    reports,
  };
}

export interface CveRecord {
  date: string;
  item: VulnItem;
}

/** CVE → 最新一期（供 /cve/[id] 詳情頁與 sitemap 使用）。 */
export function getAllCves(): Map<string, CveRecord> {
  const map = new Map<string, CveRecord>();
  for (const digest of getAllReports()) {
    for (const item of digest.items) {
      if (!map.has(item.cve_id)) {
        map.set(item.cve_id, { date: digest.date, item });
      }
    }
  }
  return map;
}

export function previousDate(date: string): string | null {
  const dates = listReportDates();
  const index = dates.indexOf(date);
  return index >= 0 && index + 1 < dates.length ? dates[index + 1] : null;
}

export function nextDate(date: string): string | null {
  const dates = listReportDates();
  const index = dates.indexOf(date);
  return index > 0 ? dates[index - 1] : null;
}
