from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.spreadsheet_io import build_components, read_sbom


class CycloneDxEvidenceTests(unittest.TestCase):
    def _read_payload(self, payload: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.cdx.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return read_sbom(path)

    def test_import_preserves_document_identity_metadata_and_component_evidence(self) -> None:
        metadata = {
            "timestamp": "2026-08-04T08:00:00Z",
            "authors": [{"name": "SBOM Team", "email": "sbom@example.test"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "controlled-generator",
                        "version": "2.0.0",
                    }
                ]
            },
        }
        hashes = [{"alg": "SHA-256", "content": "a" * 64}]
        dependencies = [
            {"ref": "product:1", "dependsOn": ["pkg:pypi/httpx@0.28.1"]},
            {"ref": "pkg:pypi/httpx@0.28.1", "dependsOn": []},
        ]
        components = [
            {
                "type": "application",
                "bom-ref": "product:1",
                "supplier": {"name": "Example Manufacturer"},
                "name": "EUVD Dependency Workbench",
                "version": "2.2.0",
                "purl": "pkg:generic/euvd-dependency-workbench@2.2.0",
                "cpe": "cpe:2.3:a:example:euvd-workbench:2.2.0:*:*:*:*:*:*:*",
                "hashes": hashes,
            },
            {
                "type": "library",
                "bom-ref": "pkg:pypi/httpx@0.28.1",
                "publisher": "Encode OSS Ltd",
                "name": "httpx",
                "version": "0.28.1",
                "purl": "pkg:pypi/httpx@0.28.1",
                "hashes": [{"alg": "SHA-512", "content": "b" * 128}],
            },
        ]
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
            "version": 4,
            "metadata": metadata,
            "components": components,
            "dependencies": dependencies,
            "vulnerabilities": [
                {
                    "id": "CVE-2025-0001",
                    "affects": [{"ref": "pkg:pypi/httpx@0.28.1"}],
                }
            ],
        }

        parsed = self._read_payload(payload)

        self.assertEqual(parsed["spec_version"], "1.7")
        self.assertEqual(parsed["serial_number"], payload["serialNumber"])
        self.assertEqual(parsed["bom_version"], 4)
        self.assertEqual(
            parsed["document_identity"],
            {
                "bom_format": "CycloneDX",
                "spec_version": "1.7",
                "serial_number": payload["serialNumber"],
                "bom_version": 4,
            },
        )
        self.assertEqual(parsed["sbom_metadata"], metadata)
        self.assertEqual(parsed["dependencies"], dependencies)
        self.assertEqual(parsed["source_components"], components)
        self.assertEqual(parsed["source_document"]["metadata"], metadata)
        self.assertEqual(parsed["source_document"]["components"], components)
        self.assertEqual(parsed["source_document"]["dependencies"], dependencies)
        self.assertEqual(parsed["rows"][1]["CVE"], "CVE-2025-0001")

        summary = parsed["pre7_evidence_summary"]
        self.assertFalse(summary["automatic_conformity_decision"])
        self.assertNotIn("conformity_status", summary)
        rq06 = summary["requirements"]["PRE-7-RQ-06"]
        self.assertEqual(
            rq06["evidence_observations"],
            {
                "author_present": True,
                "bom_version_present": True,
                "timestamp_present": True,
                "authors": metadata["authors"],
                "bom_version": 4,
                "timestamp": metadata["timestamp"],
                "tools": metadata["tools"],
                "tools_present": True,
            },
        )
        self.assertEqual(rq06["evidence_gaps"], [])

        rq07 = summary["requirements"]["PRE-7-RQ-07"]
        self.assertEqual(rq07["coverage_counts"]["component_count"], 2)
        self.assertEqual(rq07["coverage_counts"]["with_dependency_entry"], 2)
        self.assertEqual(rq07["coverage_counts"]["with_hashes"], 2)
        first_item = rq07["items"][0]
        self.assertEqual(first_item["bom_ref"], "product:1")
        self.assertEqual(first_item["purl"], components[0]["purl"])
        self.assertEqual(first_item["cpe"], components[0]["cpe"])
        self.assertEqual(first_item["hashes"], hashes)
        self.assertEqual(
            first_item["dependency_relationship"]["depends_on"],
            ["pkg:pypi/httpx@0.28.1"],
        )

        built = build_components(parsed, parsed["mapping"], max_components=10)
        self.assertEqual([item.name for item in built], ["EUVD Dependency Workbench", "httpx"])
        self.assertEqual(built[1].cve_ids, "CVE-2025-0001")

    def test_nested_components_are_preserved_and_included_in_evidence_summary(self) -> None:
        nested_component = {
            "type": "library",
            "bom-ref": "nested:1",
            "group": "Example Group",
            "name": "nested-library",
            "version": "1.0",
            "purl": "pkg:generic/nested-library@1.0",
        }
        parent_component = {
            "type": "application",
            "bom-ref": "parent:1",
            "supplier": {"name": "Example Manufacturer"},
            "name": "parent",
            "version": "1.0",
            "components": [nested_component],
        }
        parsed = self._read_payload(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": "urn:uuid:nested",
                "version": 1,
                "metadata": {
                    "timestamp": "2026-08-04T08:00:00Z",
                    "authors": [{"name": "SBOM Team"}],
                },
                "components": [parent_component],
                "dependencies": [
                    {"ref": "parent:1", "dependsOn": ["nested:1"]},
                    {"ref": "nested:1", "dependsOn": []},
                ],
            }
        )

        self.assertEqual(parsed["source_components"], [parent_component])
        items = parsed["pre7_evidence_summary"]["requirements"]["PRE-7-RQ-07"]["items"]
        self.assertEqual([item["bom_ref"] for item in items], ["parent:1", "nested:1"])
        self.assertEqual(
            items[1]["source_path"],
            "$.components[0].components[0]",
        )
        self.assertEqual(
            [row["组件名称"] for row in parsed["rows"]],
            ["parent", "nested-library"],
        )
        built = build_components(parsed, parsed["mapping"], max_components=10)
        self.assertEqual([item.name for item in built], ["parent", "nested-library"])

    def test_missing_or_malformed_fields_create_observations_not_conformity_status(self) -> None:
        parsed = self._read_payload(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"type": "library", "name": "incomplete"}],
                "metadata": "invalid-metadata-shape",
                "dependencies": "invalid-dependency-shape",
            }
        )

        self.assertEqual(parsed["sbom_metadata"], "invalid-metadata-shape")
        self.assertEqual(parsed["dependencies"], "invalid-dependency-shape")
        self.assertTrue(any("metadata 不是对象" in warning for warning in parsed["warnings"]))
        self.assertTrue(any("dependencies 不是数组" in warning for warning in parsed["warnings"]))

        summary = parsed["pre7_evidence_summary"]
        self.assertFalse(summary["automatic_conformity_decision"])
        self.assertNotIn("conformity_status", summary)
        rq06 = summary["requirements"]["PRE-7-RQ-06"]
        self.assertEqual(len(rq06["evidence_gaps"]), 3)
        rq07 = summary["requirements"]["PRE-7-RQ-07"]
        self.assertEqual(rq07["coverage_counts"]["component_count"], 1)
        self.assertEqual(rq07["coverage_counts"]["with_name"], 1)
        self.assertEqual(rq07["coverage_counts"]["with_version"], 0)
        self.assertIn("version", rq07["items"][0]["missing_observations"])

    def test_duplicate_refs_and_unresolved_vulnerability_refs_are_warnings(self) -> None:
        parsed = self._read_payload(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {"type": "library", "bom-ref": "duplicate", "name": "one"},
                    {"type": "library", "bom-ref": "duplicate", "name": "two"},
                ],
                "vulnerabilities": [
                    {"id": "CVE-2025-0002", "affects": [{"ref": "missing"}]}
                ],
            }
        )

        self.assertTrue(any("bom-ref 重复: duplicate" in warning for warning in parsed["warnings"]))
        self.assertTrue(any("affects ref" in warning and "missing" in warning for warning in parsed["warnings"]))


if __name__ == "__main__":
    unittest.main()
