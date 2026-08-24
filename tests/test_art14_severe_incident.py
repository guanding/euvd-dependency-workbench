from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.art14 import build_srp_payload, deadline_status, srp_readiness
from app.evidence_package import _cra_judgment
from app.workflow_store import WorkflowStore


NOW = datetime.now(timezone.utc).replace(microsecond=0)


class SevereIncidentWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = WorkflowStore(Path(self.temporary.name) / "workbench.sqlite3")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _qualified_case(self) -> dict:
        case = self.store.create_manual_case(
            {
                "case_type": "severe_incident",
                "project_name": "Customer Gateway",
                "project_version": "3.0",
                "vulnerability_summary": "Production service security incident",
            },
            "analyst",
        )
        case = self.store.update_case(
            case["id"],
            {
                "applicability_status": "known_affected",
                "applicability_justification": "Incident telemetry is bound to this build.",
                "product_risk_summary": "Important product function unavailable.",
                "mitigation_summary": "Affected service isolated.",
                "initial_assessment_completed_at": (NOW - timedelta(hours=2)).isoformat(),
                "severe_incident_criteria": {
                    "availability_authenticity_integrity_confidentiality_impact": True,
                    "malicious_code_introduction": False,
                    "rationale": "The incident disrupted an important product function.",
                },
                "srp_fields": {
                    "manufacturer_name": "Example GmbH",
                    "title": "Severe security incident",
                    "product_type": "Default",
                    "member_states_where_available": "DE, FR",
                    "incident_suspected_unlawful_or_malicious": "unknown",
                    "incident_general_nature": "Availability disruption",
                    "incident_detected_at": "2025-08-18T09:00:00+00:00",
                    "incident_occurred_at": "2025-08-18T08:45:00+00:00",
                    "incident_initial_assessment": "Product service unavailable",
                    "incident_corrective_measures_taken": "Service isolated",
                    "incident_user_measures": "Use fallback channel",
                    "incident_detailed_description": "Detailed incident timeline",
                    "incident_severity": "High",
                    "incident_impact": "Important product function unavailable",
                    "incident_likely_threat_or_root_cause": "Root cause under analysis",
                    "incident_applied_and_ongoing_mitigation_measures": "Service isolated; root-cause containment continues.",
                },
            },
            "analyst",
        )
        case = self.store.add_evidence(
            case["id"],
            {
                "source_type": "incident_record",
                "source_ref": "IR-2026-0818",
                "retrieved_at": (NOW - timedelta(hours=1)).isoformat(),
                "sha256": "b" * 64,
                "description": "Signed incident timeline and service impact record.",
                "product_relevance": "Bound to Customer Gateway build 3.0.",
            },
            "analyst",
        )
        case = self.store.confirm_awareness(
            case["id"],
            (NOW - timedelta(hours=1)).isoformat(),
            "Authorized Manufacturer [manufacturer-id]",
            True,
            "Initial product and impact assessment reached reasonable certainty.",
            [case["evidence"][0]["id"]],
        )
        case = self.store.review_case(
            case["id"],
            "technical",
            "Technical",
            "technical-id",
            "reportable",
            "Art.14(5) impact criterion and product binding are supported.",
        )
        return self.store.review_case(
            case["id"],
            "compliance",
            "Compliance",
            "compliance-id",
            "reportable",
            "Independent review agrees with the severe-incident assessment.",
        )

    def test_incident_reportable_does_not_require_exploitation_flags(self) -> None:
        case = self._qualified_case()
        self.assertEqual(case["case_type"], "severe_incident")
        self.assertEqual(case["art14_decision"], "reportable")
        self.assertEqual(case["workflow_status"], "approved")
        self.assertEqual(case["exploitation_evidence_status"], "not_assessed")

    def test_existing_database_is_migrated_without_reclassifying_old_cases(self) -> None:
        legacy = self.store.create_manual_case(
            {"project_name": "Existing Product"},
            "analyst",
        )
        with sqlite3.connect(self.store.path) as connection:
            connection.execute("ALTER TABLE cases DROP COLUMN case_type")
            connection.execute(
                "ALTER TABLE cases DROP COLUMN severe_incident_criteria_json"
            )
            connection.execute("DELETE FROM schema_migrations WHERE version=3")

        migrated = WorkflowStore(self.store.path)
        self.assertEqual(
            migrated.get_case(legacy["id"])["case_type"],
            "actively_exploited_vulnerability",
        )
        incident = migrated.create_manual_case(
            {"case_type": "severe_incident", "project_name": "New Incident"},
            "analyst",
        )
        self.assertEqual(incident["case_type"], "severe_incident")
        self.assertEqual(incident["severe_incident_criteria"], {})

    def test_incident_requires_art14_5_criterion_and_rationale(self) -> None:
        case = self.store.create_manual_case(
            {"case_type": "severe_incident", "project_name": "Gateway"},
            "analyst",
        )
        case = self.store.update_case(
            case["id"],
            {
                "applicability_status": "known_affected",
                "applicability_justification": "Product-bound incident.",
                "initial_assessment_completed_at": (NOW - timedelta(hours=1)).isoformat(),
            },
            "analyst",
        )
        case = self.store.add_evidence(
            case["id"],
            {
                "source_ref": "IR-1",
                "sha256": "c" * 64,
                "description": "Incident record.",
                "product_relevance": "Gateway production build.",
            },
            "analyst",
        )
        case = self.store.confirm_awareness(
            case["id"],
            (NOW - timedelta(minutes=30)).isoformat(),
            "Manufacturer",
            True,
            "Product impact confirmed.",
            [case["evidence"][0]["id"]],
        )
        with self.assertRaisesRegex(ValueError, r"Art.14\(5\)"):
            self.store.review_case(
                case["id"],
                "technical",
                "Technical",
                "technical-id",
                "reportable",
                "proposal",
            )

    def test_incident_rejects_vulnerability_only_srp_fields(self) -> None:
        case = self.store.create_manual_case(
            {"case_type": "severe_incident", "project_name": "Gateway"},
            "analyst",
        )
        with self.assertRaisesRegex(ValueError, "不适用于当前案件类型"):
            self.store.update_case(
                case["id"],
                {"srp_fields": {"vulnerability_nature": "not an incident field"}},
                "analyst",
            )

    def test_incident_srp_profile_fields_and_manual_receipt_order(self) -> None:
        case = self._qualified_case()
        self.assertTrue(srp_readiness(case, "early-warning")["ready"])
        self.assertTrue(srp_readiness(case, "notification")["ready"])
        self.assertTrue(srp_readiness(case, "final-report")["ready"])
        incomplete = {**case, "srp_fields": dict(case["srp_fields"])}
        incomplete["srp_fields"].pop("incident_detected_at")
        self.assertIn(
            "incident_detected_at",
            srp_readiness(incomplete, "notification")["missing_fields"],
        )
        payload = build_srp_payload(case, "final-report")
        self.assertEqual(payload["schema_profile"]["id"], "enisa-cra-srp-q16-2026-08-03")
        self.assertEqual(payload["submission_mode"], "manual_only")
        self.assertIsNone(payload["vulnerability"])
        self.assertEqual(payload["incident"]["severity"], "High")
        self.assertEqual(
            payload["incident"]["detected_at"],
            "2025-08-18T09:00:00+00:00",
        )

        with self.assertRaisesRegex(ValueError, "前序"):
            self.store.mark_submitted(
                case["id"],
                "Manufacturer",
                "notification",
                (NOW - timedelta(minutes=10)).isoformat(),
                "SRP-N-001",
            )
        case = self.store.mark_submitted(
            case["id"],
            "Manufacturer",
            "early-warning",
            (NOW - timedelta(minutes=20)).isoformat(),
            "SRP-EW-001",
        )
        case = self.store.mark_submitted(
            case["id"],
            "Manufacturer",
            "notification",
            (NOW - timedelta(minutes=10)).isoformat(),
            "SRP-N-001",
        )
        deadlines = deadline_status(case, now=NOW)
        self.assertIsNotNone(deadlines["final_report_1m"]["due_at"])
        self.assertEqual(
            deadlines["final_report"]["due_at"],
            deadlines["final_report_1m"]["due_at"],
        )
        judgment = _cra_judgment(case)
        self.assertEqual(judgment["reporting"]["submission_mode"], "manual_only")
        self.assertEqual(
            [item["stage"] for item in judgment["reporting"]["submission_receipts"]],
            ["early-warning", "notification"],
        )
        self.assertEqual(
            judgment["reporting"]["srp_schema_profile"]["id"],
            "enisa-cra-srp-q16-2026-08-03",
        )

    def test_incident_srp_dates_and_boolean_criteria_fail_closed(self) -> None:
        case = self.store.create_manual_case(
            {"case_type": "severe_incident", "project_name": "Gateway"},
            "analyst",
        )
        with self.assertRaisesRegex(ValueError, "必须是布尔值"):
            self.store.update_case(
                case["id"],
                {
                    "severe_incident_criteria": {
                        "malicious_code_introduction": "false",
                        "rationale": "typed input required",
                    }
                },
                "analyst",
            )
        with self.assertRaisesRegex(ValueError, "必须包含时区"):
            self.store.update_case(
                case["id"],
                {"srp_fields": {"incident_detected_at": "2026-08-18T09:00:00"}},
                "analyst",
            )
        with self.assertRaisesRegex(ValueError, "yes、no 或 unknown"):
            self.store.update_case(
                case["id"],
                {
                    "srp_fields": {
                        "incident_suspected_unlawful_or_malicious": "maybe"
                    }
                },
                "analyst",
            )
        with self.assertRaisesRegex(ValueError, "不能晚于检测时间"):
            self.store.update_case(
                case["id"],
                {
                    "srp_fields": {
                        "incident_occurred_at": "2025-08-18T10:00:00+00:00",
                        "incident_detected_at": "2025-08-18T09:00:00+00:00",
                    }
                },
                "analyst",
            )


class SevereIncidentDeadlineTests(unittest.TestCase):
    def test_one_calendar_month_uses_notification_receipt_anchor(self) -> None:
        notification = datetime(2027, 1, 31, 10, 0, tzinfo=timezone.utc)
        result = deadline_status(
            {
                "case_type": "severe_incident",
                "awareness_at": "2027-01-30T10:00:00+00:00",
                "awareness_confirmed_by": "manufacturer",
                "submission_receipts": [
                    {
                        "stage": "notification",
                        "submitted_at": notification.isoformat(),
                    }
                ],
            },
            now=notification,
        )
        self.assertEqual(
            result["final_report_1m"]["due_at"],
            "2027-02-28T10:00:00+00:00",
        )


if __name__ == "__main__":
    unittest.main()
