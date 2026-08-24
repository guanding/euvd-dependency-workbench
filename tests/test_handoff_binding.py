"""Tests for SBOM Workbench handoff receipt binding (Plan A).

The receipt from offline-sbom-evidence-workbench's ``euvd_handoff.py`` carries
boundary declarations (classification / direction / reverse_fact_write /
authority_boundary / kev_boundary / monitoring purpose / cyclonedx_sha256).
``_extract_handoff_binding`` must surface them as audit-only ``evidence``
(``fields`` stays empty so the prefill chain is unaffected) and reject any
boundary mismatch fail-closed (ValueError -> HTTP 400 in upload_preview).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from app.spreadsheet_io import read_sbom


CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:test-handoff",
    "version": 1,
    "metadata": {"timestamp": "2026-08-04T00:00:00Z"},
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/fastapi@0.140.7",
            "name": "fastapi",
            "version": "0.140.7",
            "purl": "pkg:pypi/fastapi@0.140.7",
        }
    ],
}


def _receipt(cyclonedx_sha256: str, **overrides) -> dict:
    base = {
        "schema_version": "1.1",
        "classification": "SELF_TEST_NOT_CUSTOMER_EVIDENCE",
        "source_run_id": "selftest-run-test",
        "source_binding_status": "CALLER_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
        "source_profile_id": None,
        "source_root_completion_sha256": None,
        "source_relative_name": "raw.cyclonedx.json",
        "cyclonedx_spec_version": "1.7",
        "cyclonedx_sha256": cyclonedx_sha256,
        "component_record_count": 2,
        "purl_coverage": {"with_purl": 1, "total": 2},
        "version_coverage": {"with_version": 1, "total": 2},
        "target_endpoint": "http://127.0.0.1:8090",
        "direction": "SBOM_TO_EUVD_ONLY",
        "reverse_fact_write": False,
        "automatic_art14_decision": False,
        "automatic_vulnerability_confirmation": False,
        "monitoring_purpose": "PERIODIC_COMPONENT_RESCAN_CANDIDATE_ONLY",
        "version_applicability_boundary": "MANUAL_REVIEW_REQUIRED",
        "kev_boundary": "KEV_PRESENCE_IS_PRIORITIZATION_ONLY_ABSENCE_IS_NOT_NON_EXPLOITATION_PROOF",
        "authority_boundary": "NO_SBOM_FACT_RELEASE_CONFORMITY_OR_REPORTING_AUTHORITY",
    }
    base.update(overrides)
    if "handoff_id" not in overrides:
        identity = {
            "source_run_id": base["source_run_id"],
            "source_binding_status": base["source_binding_status"],
            "source_profile_id": base["source_profile_id"],
            "source_root_completion_sha256": base["source_root_completion_sha256"],
            "cyclonedx_sha256": cyclonedx_sha256,
            "endpoint": "http://127.0.0.1:8090",
            "direction": "SBOM_TO_EUVD_ONLY",
            "contract_version": "1.1",
        }
        base["handoff_id"] = "euvd-" + hashlib.sha256(
            json.dumps(
                identity,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return base


class HandoffBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_pair(self, receipt_overrides: dict | None = None) -> Path:
        # cyclonedx stem "sbom" -> receipt "sbom.receipt.json" (matches
        # _extract_handoff_binding's {stem}.receipt.json lookup).
        cdx_path = self.dir / "sbom.json"
        payload = json.dumps(CYCLONEDX).encode("utf-8")
        cdx_path.write_bytes(payload)
        overrides = dict(receipt_overrides or {})
        sha = overrides.pop("cyclonedx_sha256", hashlib.sha256(payload).hexdigest())
        receipt_path = self.dir / "sbom.receipt.json"
        receipt_path.write_text(
            json.dumps(_receipt(sha, **overrides)),
            encoding="utf-8",
        )
        return cdx_path

    def test_valid_receipt_populates_evidence_only(self) -> None:
        result = read_sbom(self._write_pair())
        binding = result["metadata_binding"]
        self.assertIsNotNone(binding)
        # Identity whitelist: a receipt carries no product identity, so fields
        # stays empty and the prefill chain is unaffected.
        self.assertEqual(binding["fields"], {})
        self.assertEqual(binding["evidence"]["classification"], "SELF_TEST_NOT_CUSTOMER_EVIDENCE")
        self.assertEqual(binding["evidence"]["direction"], "SBOM_TO_EUVD_ONLY")
        self.assertEqual(
            binding["evidence"]["source_binding_status"],
            "CALLER_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
        )
        self.assertFalse(binding["evidence"]["automatic_vulnerability_confirmation"])
        self.assertEqual(
            binding["evidence"]["monitoring_purpose"],
            "PERIODIC_COMPONENT_RESCAN_CANDIDATE_ONLY",
        )
        self.assertEqual(
            binding["evidence"]["source_reverification_status"],
            "NOT_REVERIFIED_BY_EUVD_INTAKE",
        )
        self.assertEqual(binding["source_sheet"], "receipt.json")

    def test_no_receipt_keeps_binding_none(self) -> None:
        # Regression: a plain CycloneDX upload without a co-located receipt
        # must behave exactly as before (metadata_binding is None).
        cdx_path = self.dir / "sbom.json"
        cdx_path.write_bytes(json.dumps(CYCLONEDX).encode("utf-8"))
        result = read_sbom(cdx_path)
        self.assertIsNone(result["metadata_binding"])

    def test_direction_mismatch_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_sbom(self._write_pair({"direction": "BIDIRECTIONAL"}))

    def test_reverse_fact_write_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_sbom(self._write_pair({"reverse_fact_write": True}))

    def test_cyclonedx_sha256_mismatch_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_sbom(self._write_pair({"cyclonedx_sha256": "0" * 64}))

    def test_classification_mismatch_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_sbom(self._write_pair({"classification": "CUSTOMER_RELEASED_EVIDENCE"}))

    def test_authority_boundary_mismatch_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_sbom(self._write_pair({"authority_boundary": "wrong"}))

    def test_kev_boundary_mismatch_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_sbom(self._write_pair({"kev_boundary": "wrong"}))

    def test_old_schema_and_missing_phase1_boundary_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "schema_version"):
            read_sbom(self._write_pair({"schema_version": "1.0"}))
        cdx_path = self._write_pair()
        receipt_path = self.dir / "sbom.receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        del receipt["monitoring_purpose"]
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "1.1 合同"):
            read_sbom(cdx_path)

    def test_automatic_confirmation_and_version_escalation_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "automatic_vulnerability_confirmation"):
            read_sbom(
                self._write_pair({"automatic_vulnerability_confirmation": True})
            )

    def test_target_source_binding_and_handoff_identity_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "target_endpoint"):
            read_sbom(
                self._write_pair({"target_endpoint": "http://127.0.0.1:8091"})
            )
        with self.assertRaisesRegex(ValueError, "handoff_id"):
            read_sbom(self._write_pair({"handoff_id": "euvd-" + "0" * 64}))
        with self.assertRaisesRegex(ValueError, "verified-root"):
            read_sbom(
                self._write_pair(
                    {
                        "source_profile_id": "m3a-source-directory",
                        "source_root_completion_sha256": "0" * 64,
                    }
                )
            )
        with self.assertRaisesRegex(ValueError, "人工复核"):
            read_sbom(
                self._write_pair(
                    {"version_applicability_boundary": "AUTO_CONFIRMED"}
                )
            )


if __name__ == "__main__":
    unittest.main()
