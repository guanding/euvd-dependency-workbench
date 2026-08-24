from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from app.art14 import (
    SRP_FIELD_PROFILE,
    build_srp_portal_fields,
    srp_readiness,
    write_srp_submission_package_zip,
)


class SrpAssistedReportingTests(unittest.TestCase):
    @staticmethod
    def _ready_early_warning_case() -> dict:
        return {
            "id": "case-assisted-srp",
            "case_type": "actively_exploited_vulnerability",
            "project_name": "Example Gateway",
            "project_version": "3.2.0",
            "software_build": "build-42",
            "component_name": "example-component",
            "component_version": "1.0.0",
            "cve_id": "CVE-2026-12345",
            "euvd_id": "EUVD-2026-12345",
            "workflow_status": "approved",
            "art14_decision": "reportable",
            "awareness_at": "2026-08-20T08:00:00+00:00",
            "awareness_confirmed_by": "Authorized Manufacturer",
            "submission_receipts": [],
            "evidence": [
                {
                    "id": "evidence-1",
                    "source_ref": "IR-2026-1",
                    "sha256": "a" * 64,
                    "description": "Product-bound exploitation evidence",
                }
            ],
            "approvals": [
                {"stage": "technical", "decision": "reportable"},
                {"stage": "compliance", "decision": "reportable"},
            ],
            "srp_fields": {
                "reporter": "Assigned Representative",
                "manufacturer_name": "Example GmbH",
                "title": "Actively exploited gateway vulnerability",
                "product_type": "Default",
                "member_states_where_available": "DE, FR",
            },
        }

    def test_versioned_profile_matches_enisa_q16_shape(self) -> None:
        self.assertEqual(
            SRP_FIELD_PROFILE["id"], "enisa-cra-srp-q16-2026-08-03"
        )
        self.assertEqual(len(SRP_FIELD_PROFILE["fields"]), 39)
        self.assertEqual(
            [item["id"] for item in SRP_FIELD_PROFILE["unnumbered_rows"]],
            ["i-final-description"],
        )
        self.assertFalse(SRP_FIELD_PROFILE["api_available"])
        self.assertIsNone(SRP_FIELD_PROFILE["portal_url"])
        self.assertEqual(
            {item["id"] for item in SRP_FIELD_PROFILE["fields"]},
            {
                *(str(value) for value in range(1, 13)),
                *(f"v{value}" for value in range(13, 27)),
                *(f"i{value}" for value in range(13, 26)),
            },
        )

    def test_profile_stage_codes_match_captured_enisa_q16(self) -> None:
        expected = {
            "1": "XCC",
            "2": "XXX",
            "3": "AAA",
            "4": "AAA",
            "5": "AAA",
            "6": "AAA",
            "7": "XCC",
            "8": "XCC",
            "9": "OCC",
            "10": "OCC",
            "11": "ICC",
            "12": "XCC",
            "v13": "OCC",
            "v14": "OCC",
            "v15": "OXC",
            "v16": "OXC",
            "v17": "OXC",
            "v18": "OXC",
            "v19": "OXC",
            "v20": "OIC",
            "v21": "OOX",
            "v22": "OOX",
            "v23": "OOX",
            "v24": "OOX",
            "v25": "OOI",
            "v26": "OOX",
            "i13": "XCC",
            "i14": "OXC",
            "i15": "OXC",
            "i16": "OXC",
            "i17": "OXC",
            "i18": "OXC",
            "i19": "OXC",
            "i20": "OIC",
            "i21": "OOX",
            "i22": "---",
            "i23": "OOX",
            "i24": "OOX",
            "i25": "OOX",
        }
        actual = {
            item["id"]: "".join(
                item[stage] or "-"
                for stage in ("early-warning", "notification", "final-report")
            )
            for item in SRP_FIELD_PROFILE["fields"]
        }
        self.assertEqual(actual, expected)
        unnumbered = SRP_FIELD_PROFILE["unnumbered_rows"][0]
        self.assertEqual(
            "".join(
                unnumbered[stage]
                for stage in ("early-warning", "notification", "final-report")
            ),
            "OOX",
        )

    def test_portal_projection_keeps_automated_and_human_fields_distinct(self) -> None:
        fields = build_srp_portal_fields(
            self._ready_early_warning_case(), "early-warning"
        )
        by_id = {item["id"]: item for item in fields}
        self.assertEqual(len(fields), 26)
        self.assertEqual(by_id["7"]["status"], "X")
        self.assertEqual(by_id["7"]["value"], "Example GmbH")
        self.assertTrue(by_id["3"]["portal_automated"])
        self.assertFalse(by_id["7"]["portal_automated"])
        self.assertIn("v13", by_id)
        self.assertNotIn("i13", by_id)
        notification = next(
            item
            for item in build_srp_portal_fields(
                self._ready_early_warning_case(), "notification"
            )
            if item["id"] == "7"
        )
        self.assertEqual(notification["status"], "C")
        incident_fields = build_srp_portal_fields(
            {
                "case_type": "severe_incident",
                "project_name": "Example Gateway",
                "srp_fields": {
                    "incident_detailed_description": "Complete incident timeline"
                },
            },
            "final-report",
        )
        incident_by_id = {item["id"]: item for item in incident_fields}
        self.assertEqual(
            incident_by_id["i-final-description"]["value"],
            "Complete incident timeline",
        )
        self.assertEqual(incident_by_id["i-final-description"]["status"], "X")
        self.assertEqual(incident_by_id["i22"]["status"], "D")
        self.assertIsNone(incident_by_id["i22"]["q16_stage_code"])

    def test_complete_package_is_hash_bound_and_never_claims_submission(self) -> None:
        case = self._ready_early_warning_case()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "srp-package.zip"
            returned = write_srp_submission_package_zip(
                target, case, "early-warning"
            )
            self.assertFalse(returned["automatic_submission"])
            self.assertFalse(returned["official_submission_performed"])
            self.assertIsNone(returned["official_submission_receipt"])

            with zipfile.ZipFile(target) as archive:
                names = set(archive.namelist())
                self.assertEqual(
                    names,
                    {
                        "SRP_DRAFT.json",
                        "SRP_DRAFT.xlsx",
                        "SRP_DRAFT.html",
                        "PORTAL_FIELD_CHECKLIST.md",
                        "HUMAN_REVIEW_AND_SUBMISSION.md",
                        "EVIDENCE_INDEX.json",
                        "PACKAGE_MANIFEST.json",
                        "SHA256SUMS",
                    },
                )
                manifest = json.loads(archive.read("PACKAGE_MANIFEST.json"))
                self.assertTrue(manifest["human_confirmation_required"])
                self.assertFalse(manifest["official_submission_performed"])
                for item in manifest["files"]:
                    self.assertEqual(
                        hashlib.sha256(archive.read(item["path"])).hexdigest(),
                        item["sha256"],
                    )
                for line in archive.read("SHA256SUMS").decode("utf-8").splitlines():
                    digest, name = line.split("  ", 1)
                    self.assertEqual(
                        hashlib.sha256(archive.read(name)).hexdigest(), digest
                    )
                checklist = archive.read("PORTAL_FIELD_CHECKLIST.md").decode(
                    "utf-8"
                )
                self.assertIn("Q16 ID", checklist)
                self.assertIn("官方 SRP 中点击 Submit", checklist)
                draft = json.loads(archive.read("SRP_DRAFT.json"))
                self.assertTrue(draft["draft_only"])
                self.assertFalse(draft["automatic_submission"])
                self.assertFalse(draft["human_confirmation"]["confirmed"])

    def test_both_notification_types_can_prepare_all_three_stage_packages(self) -> None:
        vulnerability_case = self._ready_early_warning_case()
        vulnerability_case["corrective_measure_available_at"] = (
            "2026-08-21T08:00:00+00:00"
        )
        vulnerability_case["srp_fields"].update(
            {
                "general_information": "Product-bound vulnerability summary",
                "vulnerability_nature": "Input validation weakness",
                "exploit_nature": "Remote exploitation",
                "corrective_measures_taken": "Temporary access restriction",
                "user_measures": "Restrict external access",
                "full_vulnerability_description": "Complete technical analysis",
                "vulnerability_severity": "High",
                "vulnerability_impact": "Loss of integrity",
                "security_update_details": "Update 3.2.1",
            }
        )
        incident_case = self._ready_early_warning_case()
        incident_case.update(
            {
                "id": "case-assisted-srp-incident",
                "case_type": "severe_incident",
                "severe_incident_criteria": {
                    "availability_authenticity_integrity_confidentiality_impact": True,
                    "malicious_code_introduction": False,
                    "rationale": "Confirmed severe integrity impact",
                },
            }
        )
        incident_case["srp_fields"].update(
            {
                "incident_suspected_unlawful_or_malicious": "yes",
                "incident_general_nature": "Compromise of update channel",
                "incident_detected_at": "2026-08-20T07:30:00+00:00",
                "incident_occurred_at": "2026-08-20T06:00:00+00:00",
                "incident_initial_assessment": "Integrity impact confirmed",
                "incident_corrective_measures_taken": "Channel disabled",
                "incident_user_measures": "Disconnect affected devices",
                "incident_detailed_description": "Complete incident timeline",
                "incident_severity": "Severe",
                "incident_impact": "Update integrity compromised",
                "incident_likely_threat_or_root_cause": "Credential compromise",
                "incident_applied_and_ongoing_mitigation_measures": (
                    "Credential rotation and forensic monitoring"
                ),
            }
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case in (vulnerability_case, incident_case):
                for stage in ("early-warning", "notification", "final-report"):
                    target = root / f"{case['id']}-{stage}.zip"
                    payload = write_srp_submission_package_zip(target, case, stage)
                    self.assertEqual(payload["stage"], stage)
                    self.assertTrue(payload["readiness"]["material_ready"])
                    with zipfile.ZipFile(target) as archive:
                        draft = json.loads(archive.read("SRP_DRAFT.json"))
                        self.assertEqual(draft["case_type"], case["case_type"])
                        self.assertEqual(draft["stage"], stage)

    def test_portal_submission_requires_previous_official_receipts(self) -> None:
        case = self._ready_early_warning_case()
        notification = srp_readiness(case, "notification")
        self.assertTrue(notification["material_ready"] is False)
        # Fill the 72h fields so only the official Early Warning receipt remains.
        case["srp_fields"].update(
            {
                "general_information": "General information",
                "vulnerability_nature": "Input validation weakness",
                "exploit_nature": "Remote exploitation",
                "corrective_measures_taken": "Temporary block rule",
                "user_measures": "Restrict external access",
            }
        )
        notification = srp_readiness(case, "notification")
        self.assertTrue(notification["material_ready"])
        self.assertFalse(notification["portal_submission_ready"])
        self.assertEqual(
            notification["missing_prerequisite_receipts"], ["early-warning"]
        )
        case["submission_receipts"] = [
            {
                "stage": "early-warning",
                "submitted_at": "2026-08-20T09:00:00+00:00",
            }
        ]
        self.assertTrue(srp_readiness(case, "notification")["portal_submission_ready"])

    def test_incomplete_case_cannot_generate_complete_package(self) -> None:
        case = self._ready_early_warning_case()
        case["srp_fields"] = {}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "尚未就绪"):
                write_srp_submission_package_zip(
                    Path(directory) / "blocked.zip", case, "early-warning"
                )

    def test_frontend_requires_human_confirmation_and_has_no_submit_api(self) -> None:
        root = Path(__file__).resolve().parents[1]
        html = (root / "app" / "static" / "index.html").read_text(
            encoding="utf-8"
        )
        script = (root / "app" / "static" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('id="downloadSrpPackageButton"', html)
        self.assertIn('id="srpHumanConfirmation"', html)
        self.assertIn('id="openSrpPortalButton"', html)
        self.assertIn("不会代替您在官方门户点击 Submit", html)
        self.assertIn(
            "readiness.portal_submission_ready && elements.srpHumanConfirmation.checked",
            script,
        )
        self.assertIn("/package.zip", script)
        self.assertIn("window.open(target", script)
        self.assertNotIn("automaticSrpSubmission", script)
        self.assertNotIn("fetch(\"https://", script)


if __name__ == "__main__":
    unittest.main()
