"""端到端離線測試：解析 → 正規化 → 篩選 → 驗證 → 輸出。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.collect import CollectResult  # noqa: E402
from pipeline.collect.github_advisories import parse_advisory  # noqa: E402
from pipeline.collect.kev import to_kev_dict  # noqa: E402
from pipeline.collect.nvd import filter_window  # noqa: E402
from pipeline.collect.nvd_parse import parse_cve_record  # noqa: E402
from pipeline.config import Settings  # noqa: E402
from pipeline.enrich.fallback import build_title_full, build_title_short  # noqa: E402
from pipeline.enrich.schemas import (  # noqa: E402
    LLM_OUTPUT_SCHEMA,
    to_gemini_schema,
    to_openai_strict,
)
from pipeline.models import ALLOWED_TAGS, VulnItem, severity_for, tags_from_cwes  # noqa: E402
from pipeline.normalize import apply_kev_index, normalize  # noqa: E402
from pipeline.score import passes_filter, select  # noqa: E402
from pipeline.util import (  # noqa: E402
    cve_tail,
    parse_iso,
    report_date_from_arg,
    truncate,
    window_for,
)
from pipeline.verify import verify_output  # noqa: E402
from pipeline.writers.digest import build_digest, rebuild_index, write_digest  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
WINDOW_FROM = datetime(2026, 9, 24, 22, 0, tzinfo=timezone.utc)
WINDOW_TO = datetime(2026, 9, 25, 22, 0, tzinfo=timezone.utc)


def load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestUtil(unittest.TestCase):
    def test_parse_iso_variants(self) -> None:
        self.assertEqual(
            parse_iso("2026-09-25T18:00:00Z"), datetime(2026, 9, 25, 18, 0, tzinfo=timezone.utc)
        )
        self.assertEqual(parse_iso("2026-09-25"), datetime(2026, 9, 25, tzinfo=timezone.utc))
        self.assertIsNone(parse_iso("not-a-date"))
        self.assertIsNone(parse_iso(None))

    def test_window_is_utc_22_anchor(self) -> None:
        start, end = window_for(date(2026, 9, 25))
        self.assertEqual(end, datetime(2026, 9, 25, 22, 0, tzinfo=timezone.utc))
        self.assertEqual(start, datetime(2026, 9, 24, 22, 0, tzinfo=timezone.utc))

    def test_window_longer(self) -> None:
        start, _ = window_for(date(2026, 9, 25), hours=72)
        self.assertEqual(start, datetime(2026, 9, 22, 22, 0, tzinfo=timezone.utc))

    def test_cve_tail(self) -> None:
        self.assertEqual(cve_tail("CVE-2026-87902"), "87902")
        self.assertEqual(cve_tail("CVE-1999-0001"), "0001")

    def test_truncate(self) -> None:
        self.assertEqual(truncate("abc", 10), "abc")
        self.assertTrue(truncate("a" * 50, 10).endswith("…"))
        self.assertEqual(len(truncate("a" * 50, 10)), 10)

    def test_report_date_arg(self) -> None:
        self.assertEqual(report_date_from_arg("2026-09-25"), date(2026, 9, 25))


class TestNvdParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = load_fixture("nvd_modified.json")
        self.item = parse_cve_record(self.payload["vulnerabilities"][0]["cve"])

    def test_parses_core_fields(self) -> None:
        self.assertIsNotNone(self.item)
        assert self.item is not None
        self.assertEqual(self.item.cve_id, "CVE-2026-87902")
        self.assertEqual(self.item.cvss_score, 9.8)
        self.assertEqual(self.item.cvss_version, "3.1")
        self.assertEqual(self.item.severity, "CRITICAL")
        self.assertEqual(self.item.cwes, ["CWE-98"])
        self.assertIn("RCE", self.item.tags)

    def test_vendor_and_product_from_cpe(self) -> None:
        assert self.item is not None
        self.assertEqual(self.item.vendor, "WordPress")
        self.assertEqual(self.item.product, "WordPress")

    def test_reference_named_vendor_advisory(self) -> None:
        assert self.item is not None
        names = {ref["name"] for ref in self.item.references}
        self.assertIn("廠商公告", names)

    def test_rejected_status_skipped(self) -> None:
        record = dict(self.payload["vulnerabilities"][0]["cve"])
        record["vulnStatus"] = "Rejected"
        self.assertIsNone(parse_cve_record(record))

    def test_non_cve_skipped(self) -> None:
        self.assertIsNone(parse_cve_record({"id": "GHSA-xxxx"}))

class TestKevAndGhsa(unittest.TestCase):
    def test_kev_dict_fields(self) -> None:
        payload = load_fixture("kev_catalog.json")
        entry = payload["vulnerabilities"][0]
        kev = to_kev_dict(entry)
        self.assertEqual(kev["date_added"], "2026-09-25")
        self.assertEqual(kev["due_date"], "2026-09-28")
        self.assertEqual(kev["ransomware"], "Unknown")
        self.assertIn("Mikrotik", kev["name_en"])

    def test_kev_index_marks_in_the_wild(self) -> None:
        item = VulnItem(cve_id="CVE-2026-67279", cvss_score=9.8)
        index = {"CVE-2026-67279": load_fixture("kev_catalog.json")["vulnerabilities"][0]}
        marked = apply_kev_index([item], index)
        self.assertEqual(marked, 1)
        self.assertTrue(item.in_the_wild)
        self.assertIsNotNone(item.kev)
        self.assertEqual(item.vendor, "MikroTik")
        self.assertIn("cisa_kev", item.sources)

    def test_ghsa_parsing(self) -> None:
        entry = load_fixture("ghsa_advisories.json")[0]
        item = parse_advisory(entry)
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item.cve_id, "CVE-2026-89094")
        self.assertEqual(item.cvss_score, 9.9)
        self.assertEqual(item.vendor_advisory_id, "GHSA-2rmr-xw8m-22q9")
        self.assertEqual(item.vendor, "go")
        self.assertEqual(item.product, "code.gitea.io/gitea")
        self.assertIn("RCE", item.tags)
        self.assertTrue(any("1.2.3" in pkg for pkg in item.affected_packages))

    def test_ghsa_without_cve_skipped(self) -> None:
        entry = dict(load_fixture("ghsa_advisories.json")[0])
        entry["cve_id"] = None
        entry["identifiers"] = [{"type": "GHSA", "value": "GHSA-2rmr-xw8m-22q9"}]
        self.assertIsNone(parse_advisory(entry))

    def test_ghsa_withdrawn_skipped(self) -> None:
        entry = dict(load_fixture("ghsa_advisories.json")[0])
        entry["withdrawn_at"] = "2026-09-26T00:00:00Z"
        self.assertIsNone(parse_advisory(entry))


class TestNormalizeAndScore(unittest.TestCase):
    def _items(self) -> list[VulnItem]:
        nvd_item = parse_cve_record(load_fixture("nvd_modified.json")["vulnerabilities"][0]["cve"])
        assert nvd_item is not None
        ghsa_item = parse_advisory(load_fixture("ghsa_advisories.json")[0])
        assert ghsa_item is not None
        return [nvd_item, ghsa_item]

    def test_merge_same_cve_keeps_best_fields(self) -> None:
        nvd_item, ghsa_item = self._items()
        kev_result = CollectResult(
            name="kev",
            label="CISA KEV",
            items=[
                VulnItem(
                    cve_id="CVE-2026-87902",
                    vendor="WordPress",
                    product="Core",
                    in_the_wild=True,
                    kev=to_kev_dict(load_fixture("kev_catalog.json")["vulnerabilities"][0]),
                    sources=["cisa_kev"],
                    description_en="short desc",
                )
            ],
        )
        nvd_result = CollectResult(name="nvd", label="NVD", items=[nvd_item])
        ghsa_result = CollectResult(name="ghsa", label="GitHub Advisory", items=[ghsa_item])
        items, stats, warnings = normalize([kev_result, nvd_result, ghsa_result], {}, WINDOW_FROM, WINDOW_TO)

        self.assertEqual(len(items), 2)
        merged = next(i for i in items if i.cve_id == "CVE-2026-87902")
        self.assertEqual(merged.cvss_score, 9.8)  # 從 NVD 補上
        self.assertEqual(merged.product, "Core")  # KEV 較精確的名稱優先
        self.assertTrue(merged.in_the_wild)
        self.assertIn("nvd", merged.sources)
        self.assertIn("cisa_kev", merged.sources)
        self.assertGreater(len(merged.description_en), 50)  # 取較長描述
        self.assertEqual(stats["scanned"], 3)

    def test_filter_rules(self) -> None:
        self.assertTrue(passes_filter(VulnItem(cve_id="CVE-2026-1", cvss_score=9.8), 9.0, 0.5)[0])
        self.assertFalse(passes_filter(VulnItem(cve_id="CVE-2026-1", cvss_score=8.9), 9.0, 0.5)[0])
        self.assertTrue(
            passes_filter(VulnItem(cve_id="CVE-2026-1", cvss_score=5.0, kev={"date_added": "x"}), 9.0, 0.5)[0]
        )
        # 無 CVSS、無 KEV、無 EPSS（僅廠商公告）→ 不收錄
        vendor_only = VulnItem(cve_id="CVE-2026-1", sources=["vendors"])
        self.assertFalse(passes_filter(vendor_only, 9.0, 0.5)[0])
        # 高分但門檻更高 → 不收錄
        self.assertFalse(passes_filter(VulnItem(cve_id="CVE-2026-1", cvss_score=9.9), 9.95, 0.99)[0])
        epss_ok = VulnItem(cve_id="CVE-2026-1", cvss_score=8.0, epss_score=0.9)
        self.assertTrue(passes_filter(epss_ok, 9.0, 0.5)[0])
        epss_low_cvss = VulnItem(cve_id="CVE-2026-1", cvss_score=5.0, epss_score=0.9)
        self.assertFalse(passes_filter(epss_low_cvss, 9.0, 0.5)[0])

    def test_select_orders_kev_first_and_ranks(self) -> None:
        plain = VulnItem(cve_id="CVE-2026-1000", cvss_score=9.1, severity="CRITICAL")
        kev_item = VulnItem(cve_id="CVE-2026-2000", cvss_score=8.0, kev={"date_added": "2026-09-25"})
        wild = VulnItem(cve_id="CVE-2026-3000", cvss_score=9.9, severity="CRITICAL", in_the_wild=True)
        kept, counts = select([plain, kev_item, wild], 9.0, 0.5)
        self.assertEqual([i.cve_id for i in kept], ["CVE-2026-2000", "CVE-2026-3000", "CVE-2026-1000"])
        self.assertEqual([i.rank for i in kept], [1, 2, 3])
        self.assertEqual(counts["kept"], 3)
        self.assertEqual(counts["kev"], 1)
        self.assertEqual(counts["in_the_wild"], 1)


class TestVerify(unittest.TestCase):
    def setUp(self) -> None:
        item = parse_cve_record(load_fixture("nvd_modified.json")["vulnerabilities"][0]["cve"])
        assert item is not None
        self.item = item
        self.by_id = {item.cve_id: item}

    def _good_entry(self) -> dict:
        return {
            "cve_id": "CVE-2026-87902",
            "title_short": "WordPress 87902×9.8",
            "title_full": "WordPress CVE-2026-87902 · CVSS 9.8",
            "tags": ["RCE"],
            "summary_zh": "未授權攻擊者可讓頁面模板解析載入主題目錄外的 PHP 檔，導致遠端程式碼執行。",
            "impact_zh": "未授權 RCE，可完全接管站台。",
            "action_zh": "升級至修補版本。",
        }

    def test_accepts_valid_entry(self) -> None:
        accepted, hard, _ = verify_output({"items": [self._good_entry()]}, self.by_id)
        self.assertIn("CVE-2026-87902", accepted)
        self.assertEqual(hard, [])

    def test_rejects_unknown_cve(self) -> None:
        entry = self._good_entry()
        entry["cve_id"] = "CVE-2026-99999"
        accepted, hard, _ = verify_output({"items": [entry]}, self.by_id)
        self.assertEqual(accepted, {})
        self.assertTrue(any("unknown_cve" in reason for reason in hard))

    def test_rejects_score_mismatch(self) -> None:
        entry = self._good_entry()
        entry["title_short"] = "WordPress 87902×8.8"
        accepted, hard, _ = verify_output({"items": [entry]}, self.by_id)
        self.assertEqual(accepted, {})
        self.assertTrue(any("title_score_mismatch" in reason for reason in hard))

    def test_rejects_missing_tail(self) -> None:
        entry = self._good_entry()
        entry["title_short"] = "WordPress ×9.8"
        accepted, hard, _ = verify_output({"items": [entry]}, self.by_id)
        self.assertEqual(accepted, {})
        self.assertTrue(any("title_missing_tail" in reason for reason in hard))

    def test_rejects_missing_in_the_wild_marker(self) -> None:
        wild = VulnItem(cve_id="CVE-2026-67279", cvss_score=9.8, in_the_wild=True)
        entry = {
            "cve_id": "CVE-2026-67279",
            "title_short": "MikroTik RouterOS 67279×9.8",
            "title_full": "MikroTik RouterOS CVE-2026-67279",
            "tags": ["接管"],
            "summary_zh": "測試",
            "impact_zh": "測試",
            "action_zh": "測試",
        }
        accepted, hard, _ = verify_output({"items": [entry]}, {"CVE-2026-67279": wild})
        self.assertEqual(accepted, {})
        self.assertTrue(any("title_missing_in_the_wild" in reason for reason in hard))

    def test_unknown_tag_is_soft_violation(self) -> None:
        entry = self._good_entry()
        entry["tags"] = ["不存在的標籤", "RCE"]
        accepted, hard, soft = verify_output({"items": [entry]}, self.by_id)
        self.assertIn("CVE-2026-87902", accepted)
        self.assertEqual(hard, [])
        self.assertTrue(any("unknown_tag" in reason for reason in soft))
        self.assertEqual(accepted["CVE-2026-87902"]["tags"], ["RCE"])

    def test_duplicate_cve_flagged(self) -> None:
        entry = self._good_entry()
        accepted, hard, _ = verify_output({"items": [entry, dict(entry)]}, self.by_id)
        self.assertEqual(len(accepted), 1)
        self.assertTrue(any("duplicate_cve" in reason for reason in hard))

    def test_missing_output_shape(self) -> None:
        self.assertEqual(verify_output(None, self.by_id)[1], ["output_not_object"])
        self.assertEqual(verify_output({}, self.by_id)[1], ["output_missing_items"])


class TestFallbackEnrichment(unittest.TestCase):
    def test_title_formats(self) -> None:
        item = parse_cve_record(load_fixture("nvd_modified.json")["vulnerabilities"][0]["cve"])
        assert item is not None
        item.in_the_wild = True
        self.assertEqual(build_title_short(item), "WordPress 87902×9.8 在野")
        self.assertEqual(build_title_full(item), "WordPress CVE-2026-87902 · CVSS 9.8 · 在野利用")

    def test_title_without_score(self) -> None:
        item = VulnItem(cve_id="CVE-2026-12345", vendor="Forgejo", product="")
        self.assertEqual(build_title_short(item), "Forgejo 12345")

    def test_apply_enrichment_falls_back_per_item(self) -> None:
        from pipeline.verify import apply_enrichment

        good = VulnItem(cve_id="CVE-2026-1", vendor="Cisco", product="FMC", cvss_score=10.0)
        bad = VulnItem(cve_id="CVE-2026-2", vendor="Forgejo", cvss_score=9.9)
        accepted = {
            "CVE-2026-1": {
                "title_short": "Cisco FMC 1×10.0",
                "title_full": "Cisco FMC CVE-2026-1 · CVSS 10.0",
                "tags": ["RCE"],
                "summary_zh": "LLM 摘要",
                "impact_zh": "LLM 衝擊",
                "action_zh": "LLM 處置",
            }
        }
        stats = apply_enrichment([good, bad], accepted, "gemini")
        self.assertEqual(stats, {"llm": 1, "template": 1})
        self.assertEqual(good.generated_by, "gemini")
        self.assertEqual(good.title_short, "Cisco FMC 1×10.0")
        self.assertEqual(bad.generated_by, "template")
        self.assertEqual(bad.title_short, "Forgejo 2×9.9")
        self.assertTrue(bad.summary_zh)


class TestWriters(unittest.TestCase):
    def test_digest_and_index_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(data_dir=Path(tmp))
            item = parse_cve_record(load_fixture("nvd_modified.json")["vulnerabilities"][0]["cve"])
            assert item is not None
            item.in_the_wild = True
            item.title_short = build_title_short(item)
            item.title_full = build_title_full(item)
            item.rank = 1

            digest = build_digest(
                report_date=date(2026, 9, 25),
                window_from=WINDOW_FROM,
                window_to=WINDOW_TO,
                items=[item],
                counts={"kept": 1, "kev": 0, "critical": 1, "in_the_wild": 1},
                scanned=42,
                sources=[{"name": "nvd", "label": "NVD", "ok": True, "items": 1, "error": None}],
                vendor_watch=[],
                generated_by="template",
            )
            path = write_digest(settings, digest)
            self.assertTrue(path.exists())
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["schema_version"], 1)
            self.assertEqual(stored["stats"]["scanned"], 42)
            self.assertEqual(stored["items"][0]["cve_id"], "CVE-2026-87902")

            index = rebuild_index(settings)
            self.assertEqual(index["total"], 1)
            self.assertEqual(index["reports"][0]["date"], "2026-09-25")
            self.assertEqual(index["reports"][0]["top"], ["WordPress 87902×9.8 在野"])

    def test_index_sorted_desc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(data_dir=Path(tmp))
            for day in ("2026-09-23", "2026-09-25", "2026-09-24"):
                digest = build_digest(
                    report_date=date.fromisoformat(day),
                    window_from=WINDOW_FROM,
                    window_to=WINDOW_TO,
                    items=[],
                    counts={"kept": 0},
                    scanned=0,
                    sources=[],
                    vendor_watch=[],
                    generated_by="template",
                )
                write_digest(settings, digest)
            index = rebuild_index(settings)
            self.assertEqual(
                [entry["date"] for entry in index["reports"]],
                ["2026-09-25", "2026-09-24", "2026-09-23"],
            )


class TestLlmSchemas(unittest.TestCase):
    def test_gemini_schema_uppercases_types(self) -> None:
        schema = to_gemini_schema(json.loads(json.dumps(LLM_OUTPUT_SCHEMA)))
        self.assertEqual(schema["type"], "OBJECT")
        self.assertEqual(schema["properties"]["items"]["type"], "ARRAY")
        inner = schema["properties"]["items"]["items"]
        self.assertEqual(inner["type"], "OBJECT")
        self.assertEqual(inner["propertyOrdering"][0], "cve_id")
        self.assertIn("RCE", inner["properties"]["tags"]["items"]["enum"])

    def test_allowed_tags_are_closed_set(self) -> None:
        schema = to_gemini_schema(json.loads(json.dumps(LLM_OUTPUT_SCHEMA)))
        enum = schema["properties"]["items"]["items"]["properties"]["tags"]["items"]["enum"]
        self.assertEqual(list(ALLOWED_TAGS), enum)

    def test_openai_strict_requires_all_properties(self) -> None:
        schema = to_openai_strict(json.loads(json.dumps(LLM_OUTPUT_SCHEMA)))
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertFalse(schema["additionalProperties"])
        inner = schema["properties"]["items"]["items"]
        self.assertEqual(set(inner["required"]), set(inner["properties"]))

    def test_severity_mapping(self) -> None:
        self.assertEqual(severity_for(9.0), "CRITICAL")
        self.assertEqual(severity_for(7.5), "HIGH")
        self.assertEqual(severity_for(5.0), "MEDIUM")
        self.assertEqual(severity_for(None), "UNKNOWN")
        self.assertEqual(severity_for(None, "HIGH"), "HIGH")

    def test_cwe_to_tag_mapping(self) -> None:
        self.assertEqual(tags_from_cwes(["CWE-78"]), ["RCE"])
        self.assertEqual(tags_from_cwes(["CWE-918", "CWE-79"]), ["SSRF", "XSS"])
        self.assertEqual(tags_from_cwes(["CWE-9999"]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
