from __future__ import annotations

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.matcher import (
    Component,
    apply_exploitation_evidence,
    evaluate_identifier_item,
    evaluate_item,
    extract_identifiers,
    parse_cpe,
    token_similarity,
    version_is_affected,
)
from app.spreadsheet_io import build_components


def euvd_item(
    *,
    product: str = "Requests",
    vendor: str = "psf",
    version: str = "< 2.32.0",
) -> dict:
    return {
        "id": "EUVD-TEST-1",
        "aliases": "CVE-TEST-1",
        "baseScore": 7.5,
        "baseScoreVersion": "3.1",
        "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Test record",
        "enisaIdProduct": [
            {
                "product": {
                    "name": product,
                    "vendor": {"name": vendor},
                },
                "product_version": version,
            }
        ],
    }


class VendorMatchingTests(unittest.TestCase):
    def test_vendor_acronym_is_recognized(self) -> None:
        self.assertEqual(token_similarity("Python Software Foundation", "psf"), 1.0)

    def test_different_vendors_are_not_treated_as_equal(self) -> None:
        self.assertLess(token_similarity("Python Software Foundation", "Apache"), 0.55)


class VersionMatchingTests(unittest.TestCase):
    def test_exclusive_upper_bound(self) -> None:
        self.assertTrue(version_is_affected("2.31.0", "< 2.32.0")[0])
        self.assertFalse(version_is_affected("2.32.0", "< 2.32.0")[0])

    def test_inclusive_range(self) -> None:
        self.assertTrue(version_is_affected("6.1", "0 <=6.3")[0])
        self.assertFalse(version_is_affected("6.4", "0 <=6.3")[0])

    def test_unstructured_expression_requires_review(self) -> None:
        self.assertIsNone(version_is_affected("1.0", "selected legacy releases")[0])

    def test_inclusive_range_through(self) -> None:
        self.assertTrue(version_is_affected("2.0", "1.0 through 3.0")[0])
        self.assertFalse(version_is_affected("4.0", "1.0 through 3.0")[0])

    def test_inclusive_lower_bound(self) -> None:
        self.assertTrue(version_is_affected("3.5", ">=3.0")[0])
        self.assertFalse(version_is_affected("2.9", ">=3.0")[0])

    def test_all_versions_marker(self) -> None:
        self.assertTrue(version_is_affected("1.0", "all versions")[0])
        self.assertTrue(version_is_affected("9.9", "*")[0])

    def test_exact_version(self) -> None:
        self.assertTrue(version_is_affected("2.3.1", "2.3.1")[0])
        self.assertFalse(version_is_affected("2.3.2", "2.3.1")[0])


class CpeParsingTests(unittest.TestCase):
    def test_parse_well_formed_cpe_23(self) -> None:
        parsed = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        self.assertEqual(parsed["vendor"], "apache")
        self.assertEqual(parsed["name"], "log4j")
        self.assertEqual(parsed["version"], "2.14.1")

    def test_underscore_decoded_as_space(self) -> None:
        parsed = parse_cpe(
            "cpe:2.3:a:python_software_foundation:python:3.10:*:*:*:*:*:*:*"
        )
        self.assertEqual(parsed["vendor"], "python software foundation")
        self.assertEqual(parsed["name"], "python")

    def test_wildcard_or_dash_version_is_blank(self) -> None:
        self.assertEqual(
            parse_cpe("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")["version"], ""
        )
        self.assertEqual(
            parse_cpe("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*")["version"], ""
        )

    def test_non_cpe_string_returns_empty(self) -> None:
        self.assertEqual(
            parse_cpe("not a cpe"), {"name": "", "version": "", "vendor": ""}
        )


class ItemEvaluationTests(unittest.TestCase):
    def test_exact_product_version_and_vendor_acronym_confirms(self) -> None:
        component = Component(
            row_number=2,
            name="requests",
            version="2.31.0",
            vendor="Python Software Foundation",
        )
        result = evaluate_item(component, euvd_item())
        self.assertIsNotNone(result)
        self.assertEqual(result["match_status"], "已匹配")
        self.assertEqual(result["confidence"], 100)

    def test_wrong_product_is_rejected(self) -> None:
        component = Component(
            row_number=2,
            name="requests",
            version="2.31.0",
            vendor="Python Software Foundation",
        )
        self.assertIsNone(evaluate_item(component, euvd_item(product="Other Product")))

    def test_vendor_mismatch_is_kept_for_review(self) -> None:
        component = Component(
            row_number=2,
            name="requests",
            version="2.31.0",
            vendor="Apache",
        )
        result = evaluate_item(component, euvd_item())
        self.assertIsNotNone(result)
        self.assertEqual(result["match_status"], "需复核")


class IdentifierMatchingTests(unittest.TestCase):
    def test_multiple_cves_are_normalized_and_deduplicated(self) -> None:
        value = "cve-2021-44228;\nCVE-2024-35195, CVE-2021-44228"
        self.assertEqual(
            extract_identifiers(value, "cve"),
            ["CVE-2021-44228", "CVE-2024-35195"],
        )

    def test_component_deduplication_keeps_different_cves(self) -> None:
        parsed = {
            "header_row": 1,
            "rows": [
                {"组件": "requests", "版本": "2.31.0", "CVE": "CVE-2024-35195"},
                {"组件": "requests", "版本": "2.31.0", "CVE": "CVE-2023-32681"},
            ],
        }
        components = build_components(
            parsed,
            {"name": "组件", "version": "版本", "cve": "CVE"},
            10,
        )
        self.assertEqual(len(components), 2)

    def test_exact_identifier_mapping_is_not_rejected_by_product_mismatch(self) -> None:
        component = Component(
            row_number=2,
            name="customer-wrapper",
            version="1.0",
            cve_ids="CVE-2021-44228",
        )
        item = euvd_item(product="Log4j", vendor="Apache", version="< 2.15.0")
        item["id"] = "EUVD-2021-34768"
        item["aliases"] = "CVE-2021-44228"
        result = evaluate_identifier_item(
            component,
            item,
            "CVE-2021-44228",
            "SBOM CVE→EUVD 官方映射",
        )
        self.assertEqual(result["mapping_status"], "EUVD精确匹配")
        self.assertEqual(result["component_applicability"], "待人工核验")

    def test_exact_identifier_checks_all_matching_version_ranges(self) -> None:
        component = Component(
            row_number=2,
            name="requests",
            version="2.31.0",
            vendor="Python Software Foundation",
            cve_ids="CVE-2024-35195",
        )
        item = euvd_item(version="< 2.0.0")
        item["enisaIdProduct"].append(
            {
                "product": {
                    "name": "Requests",
                    "vendor": {"name": "psf"},
                },
                "product_version": ">= 2.30.0, < 2.32.0",
            }
        )
        result = evaluate_identifier_item(
            component,
            item,
            "CVE-2024-35195",
            "SBOM CVE→EUVD 官方映射",
        )
        self.assertEqual(
            result["component_applicability"], "受影响版本条件命中"
        )
        self.assertEqual(result["affected_versions"], ">= 2.30.0, < 2.32.0")

    def test_kev_entry_creates_review_signal_not_automatic_reporting(self) -> None:
        candidate = {
            "euvd_id": "EUVD-2021-34768",
            "source_identifier": "CVE-2021-44228",
            "alternative_ids": "CVE-2021-44228",
            "component_applicability": "受影响版本条件命中",
        }
        result = apply_exploitation_evidence(
            candidate,
            {"exploitedSince": "Dec 10, 2021"},
            {
                "CVE-2021-44228": {
                    "dateAdded": "2021-12-10",
                    "sources": ["cisa_kev", "eu_kev"],
                }
            },
            {"evidence_checked_at": "2026-07-28T00:00:00+00:00"},
        )
        self.assertEqual(result["exploitation_status"], "KEV已知利用信号")
        self.assertEqual(result["art14_readiness"], "紧急人工评估")
        self.assertIn("未准备", result["srp_readiness"])

    def test_not_listed_never_claims_not_exploited(self) -> None:
        candidate = {
            "euvd_id": "EUVD-2024-1565",
            "source_identifier": "CVE-2024-35195",
            "alternative_ids": "CVE-2024-35195",
            "component_applicability": "受影响版本条件命中",
        }
        result = apply_exploitation_evidence(candidate, {}, {}, {})
        self.assertIn("不代表未被利用", result["exploitation_status"])
        self.assertTrue(result["cra_review_required"])


if __name__ == "__main__":
    unittest.main()
