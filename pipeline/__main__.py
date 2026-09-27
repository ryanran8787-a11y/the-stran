"""CLI 進入點：python -m pipeline --date today --llm gemini"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from .collect import CollectResult, kev_index_of, run_safely
from .collect import epss as epss_source
from .collect import github_advisories, kev, nvd, osv, vendors
from .config import Settings
from .enrich_llm import enrich_items
from .normalize import normalize
from .score import select
from .util import log, report_date_from_arg, setup_logging, to_iso, window_for
from .writers import build_digest, rebuild_index, write_digest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline",
        description="網安每日報資料管線（標準庫實作，零第三方依賴）",
    )
    parser.add_argument("--date", default="today", help="報告日期 YYYY-MM-DD（today / yesterday）")
    parser.add_argument("--hours", type=int, default=24, help="資料窗口長度（小時，預設 24）")
    parser.add_argument(
        "--llm",
        default=None,
        help="LLM provider：gemini / openai / claude / none（預設讀取 LLM_PROVIDER）",
    )
    parser.add_argument("--min-cvss", type=float, default=None, help="覆寫 CVSS 收錄門檻")
    parser.add_argument("--min-epss", type=float, default=None, help="覆寫 EPSS 收錄門檻")
    parser.add_argument("--max-items", type=int, default=None, help="覆寫 LLM 最多處理筆數")
    parser.add_argument("--sources", default="", help="只執行指定來源（逗號分隔）")
    parser.add_argument("--dry-run", action="store_true", help="只印出結果，不寫檔")
    parser.add_argument("--allow-empty", action="store_true", help="即使 0 筆也回傳成功")
    parser.add_argument("-v", "--verbose", action="store_true", help="顯示 debug 訊息")
    return parser.parse_args(argv)


def apply_overrides(settings: Settings, args: argparse.Namespace) -> None:
    if args.llm:
        settings.llm_provider = args.llm.lower()
    if args.min_cvss is not None:
        settings.min_cvss = args.min_cvss
    if args.min_epss is not None:
        settings.min_epss = args.min_epss
    if args.max_items is not None:
        settings.llm_max_items = max(0, args.max_items)


def collector_plan(names: set[str]) -> list[tuple[str, str, object]]:
    return [
        ("kev", "CISA KEV", kev.collect),
        ("nvd", "NVD", nvd.collect),
        ("github_advisories", "GitHub Advisory", github_advisories.collect),
        ("vendors", "廠商公告", vendors.collect),
    ]


def run(args: argparse.Namespace) -> int:
    settings = Settings.load()
    apply_overrides(settings, args)

    report_date = report_date_from_arg(args.date)
    window_from, window_to = window_for(report_date, hours=max(1, args.hours))
    log.info(
        "報告日期 %s；資料窗口 %s ~ %s",
        report_date.isoformat(),
        to_iso(window_from),
        to_iso(window_to),
    )

    wanted = {name.strip() for name in args.sources.split(",") if name.strip()}
    results: list[CollectResult] = []

    for key, label, fn in collector_plan(wanted):
        if wanted and key not in wanted:
            continue
        if not settings.source_enabled(key):
            log.info("來源 %s 已停用（config/sources.json）", key)
            continue
        results.append(run_safely(fn, settings, window_from, window_to, key, label))

    kev_index = kev_index_of(results)
    log.info("KEV 目錄索引：%s 筆 CVE", len(kev_index))

    items, norm_stats, warnings = normalize(results, kev_index, window_from, window_to)

    # 補齊缺分數 / 缺廠商產品的項目（KEV-only 類最容易缺）
    if settings.source_enabled("nvd") and (not wanted or "nvd" in wanted):
        from .collect import nvd as nvd_source

        filled = nvd_source.fill_missing(settings, items)
        if filled:
            norm_stats["filled"] = filled

    if settings.source_enabled("epss") and (not wanted or "epss" in wanted):
        results.append(epss_source.apply(settings, items))
    if settings.source_enabled("osv") and (not wanted or "osv" in wanted):
        results.append(osv.apply(settings, items))

    kept, counts = select(items, settings.min_cvss, settings.min_epss)

    enrich_stats = enrich_items(settings, kept, args.llm)
    generated_by = enrich_stats.get("provider") or "template"

    vendor_watch: list[dict] = []
    for result in results:
        if result.name == "vendors":
            vendor_watch = list(result.extra.get("watch") or [])

    digest = build_digest(
        report_date=report_date,
        window_from=window_from,
        window_to=window_to,
        items=kept,
        counts=counts,
        scanned=norm_stats.get("scanned", 0),
        sources=[result.status() for result in results],
        vendor_watch=vendor_watch,
        generated_by=generated_by,
    )

    if args.dry_run:
        log.info("[dry-run] 不寫入檔案。統計：%s", digest["stats"])
    else:
        write_digest(settings, digest)
        rebuild_index(settings)

    print_summary(digest, warnings, enrich_stats)
    if not kept and not args.allow_empty:
        log.error("本次沒有任何項目通過篩選（0 筆），回傳失敗碼 2")
        return 2
    return 0


def print_summary(digest: dict, warnings: list[str], enrich_stats: dict) -> None:
    stats = digest.get("stats") or {}
    log.info("=" * 62)
    log.info("掃描 %s 筆 → 收錄 %s 筆", stats.get("scanned"), stats.get("kept"))
    log.info(
        "其中 KEV %s 筆、在野利用 %s 筆、CRITICAL %s 筆",
        stats.get("kev"),
        stats.get("in_the_wild"),
        stats.get("critical"),
    )
    log.info("來源：成功 %s、失敗 %s", stats.get("sources_ok"), stats.get("sources_failed"))
    if enrich_stats.get("provider"):
        log.info(
            "提煉：%s（LLM %s 筆 / 模板 %s 筆，失敗批次 %s）",
            enrich_stats["provider"],
            enrich_stats.get("llm"),
            enrich_stats.get("template"),
            enrich_stats.get("failed_batches"),
        )
        if enrich_stats.get("hard_violations"):
            log.warning("被攔下的硬性違規：%s", enrich_stats["hard_violations"][:8])
    else:
        log.info("提煉：規則模板（未使用 LLM）")
    for item in (digest.get("items") or [])[:10]:
        marker = "在野" if item.get("in_the_wild") else "    "
        score = (item.get("cvss") or {}).get("score")
        log.info("  [%s] %s | CVSS %s", marker, item.get("title_short"), score)
    total = len(digest.get("items") or [])
    if total > 10:
        log.info("  ...（其餘 %s 筆）", total - 10)
    for warning in warnings[:12]:
        log.warning("警告：%s", warning)
    log.info("=" * 62)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    try:
        return run(args)
    except KeyboardInterrupt:
        log.error("使用者中止")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI 最外層防護
        log.exception("管線執行失敗：%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
