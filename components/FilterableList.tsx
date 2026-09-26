"use client";

import { useMemo, useState } from "react";

import type { VulnItem } from "@/lib/types";

import TagChip from "./TagChip";
import VulnCard from "./VulnCard";

const SEVERITY_OPTIONS = [
  { value: "CRITICAL", label: "重大" },
  { value: "HIGH", label: "高" },
  { value: "MEDIUM", label: "中" },
  { value: "LOW", label: "低" },
];

type SortKey = "rank" | "cvss" | "epss";

function scoreOf(item: VulnItem): number {
  return item.cvss.score ?? -1;
}

export default function FilterableList({ items, today }: { items: VulnItem[]; today: string }) {
  const [query, setQuery] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [tags, setTags] = useState<string[]>([]);
  const [vendor, setVendor] = useState("");
  const [wildOnly, setWildOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [sort, setSort] = useState<SortKey>("rank");

  const allTags = useMemo(() => {
    const counter = new Map<string, number>();
    for (const item of items) {
      for (const tag of item.tags) counter.set(tag, (counter.get(tag) ?? 0) + 1);
    }
    return Array.from(counter.entries())
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([tag]) => tag);
  }, [items]);

  const allVendors = useMemo(() => {
    const set = new Set<string>();
    for (const item of items) if (item.vendor) set.add(item.vendor);
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [items]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const result = items.filter((item) => {
      if (wildOnly && !item.in_the_wild) return false;
      if (kevOnly && !item.kev) return false;
      if (severities.length > 0 && !severities.includes(item.severity)) return false;
      if (tags.length > 0 && !tags.some((tag) => item.tags.includes(tag))) return false;
      if (vendor && item.vendor !== vendor) return false;
      if (needle) {
        const haystack = [
          item.title_short,
          item.cve_id,
          item.vendor,
          item.product,
          item.summary_zh,
          item.impact_zh,
          item.action_zh,
          item.description_en,
          item.vendor_advisory_id ?? "",
          item.tags.join(" "),
          item.cwe.join(" "),
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });

    if (sort === "cvss") {
      result.sort((a, b) => scoreOf(b) - scoreOf(a) || a.cve_id.localeCompare(b.cve_id));
    } else if (sort === "epss") {
      result.sort(
        (a, b) => (b.epss?.score ?? -1) - (a.epss?.score ?? -1) || scoreOf(b) - scoreOf(a),
      );
    } else {
      result.sort((a, b) => (a.rank ?? 999) - (b.rank ?? 999));
    }
    return result;
  }, [items, query, severities, tags, vendor, wildOnly, kevOnly, sort]);

  const active =
    query.length > 0 || severities.length > 0 || tags.length > 0 || vendor.length > 0 || wildOnly || kevOnly;

  function toggle(list: string[], value: string, setter: (next: string[]) => void) {
    setter(list.includes(value) ? list.filter((entry) => entry !== value) : [...list, value]);
  }

  function reset() {
    setQuery("");
    setSeverities([]);
    setTags([]);
    setVendor("");
    setWildOnly(false);
    setKevOnly(false);
    setSort("rank");
  }

  return (
    <section className="mt-6">
      <div className="card p-3 sm:p-4">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜尋 CVE、廠商、產品、關鍵字…"
            aria-label="搜尋漏洞"
            className="min-w-[220px] flex-1 rounded-lg border px-3 py-1.5 text-[13px] outline-none"
            style={{ background: "var(--bg)", color: "var(--fg)" }}
          />
          <select
            value={vendor}
            onChange={(event) => setVendor(event.target.value)}
            aria-label="篩選廠商"
            className="rounded-lg border px-2 py-1.5 text-[13px]"
            style={{ background: "var(--bg)", color: "var(--fg)" }}
          >
            <option value="">全部廠商</option>
            {allVendors.map((entry) => (
              <option key={entry} value={entry}>
                {entry}
              </option>
            ))}
          </select>
          <select
            value={sort}
            onChange={(event) => setSort(event.target.value as SortKey)}
            aria-label="排序方式"
            className="rounded-lg border px-2 py-1.5 text-[13px]"
            style={{ background: "var(--bg)", color: "var(--fg)" }}
          >
            <option value="rank">依風險排序</option>
            <option value="cvss">依 CVSS</option>
            <option value="epss">依 EPSS</option>
          </select>
          <button type="button" className="btn" aria-pressed={wildOnly} onClick={() => setWildOnly(!wildOnly)}>
            只在野
          </button>
          <button type="button" className="btn" aria-pressed={kevOnly} onClick={() => setKevOnly(!kevOnly)}>
            只 KEV
          </button>
          {active ? (
            <button type="button" className="btn" onClick={reset}>
              清除
            </button>
          ) : null}
        </div>

        <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
          {SEVERITY_OPTIONS.map((option) => (
            <button
              key={option.value}
              type="button"
              className="btn"
              aria-pressed={severities.includes(option.value)}
              onClick={() => toggle(severities, option.value, setSeverities)}
            >
              {option.label}
            </button>
          ))}
          {allTags.length > 0 ? (
            <span className="mx-1 h-4 w-px" style={{ background: "var(--border)" }} />
          ) : null}
          {allTags.map((tag) => (
            <button
              key={tag}
              type="button"
              aria-pressed={tags.includes(tag)}
              onClick={() => toggle(tags, tag, setTags)}
              className="border-none bg-transparent p-0"
            >
              <TagChip tag={tag} active={tags.includes(tag)} />
            </button>
          ))}
        </div>
      </div>

      <div className="mt-3 flex items-center gap-3 text-[12px]" style={{ color: "var(--muted-2)" }}>
        <span>
          顯示 <span className="mono">{filtered.length}</span> / {items.length} 筆
        </span>
        {active ? <span>· 已套用篩選</span> : null}
      </div>

      {filtered.length === 0 ? (
        <div className="card mt-3 p-8 text-center text-[13px]" style={{ color: "var(--muted)" }}>
          沒有符合條件的項目。試著放寬篩選，或清除搜尋字串。
        </div>
      ) : (
        <div className="mt-3 space-y-3">
          {filtered.map((item) => (
            <VulnCard key={item.cve_id} item={item} today={today} />
          ))}
        </div>
      )}
    </section>
  );
}
