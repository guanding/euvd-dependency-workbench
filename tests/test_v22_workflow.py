from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.art14 import build_srp_payload, deadline_status, srp_readiness
from app.vex import build_csaf_vex, build_cyclonedx_vex, parse_vex_bytes
from app.workflow_store import WorkflowStore


NOW = datetime.now(timezone.utc).replace(microsecond=0)


class WorkflowStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = WorkflowStore(Path(self.temporary.name) / "workbench.sqlite3")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manual_case(self) -> dict:
        return self.store.create_manual_case(
            {
                "project_name": "Customer Gateway",
                "project_version": "2.2.0",
                "software_build": "GW-220-20260728",
                "component_name": "example-lib",
                "component_version": "1.0.0",
                "cve_id": "CVE-2026-12345",
                "euvd_id": "EUVD-2026-12345",
            },
            "analyst",
        )

    def _qualify_reportable_case(self) -> dict:
        case = self._manual_case()
        case = self.store.update_case(
            case["id"],
            {
                "applicability_status": "known_affected",
                "applicability_justification": "该构建包含并可达受影响函数。",
                "exploitation_evidence_status": "reliable_evidence",
                "exploitation_evidence_summary": "制造商事件响应记录确认实际利用。",
                "product_risk_summary": "未经授权代码执行风险。",
                "initial_assessment_completed_at": (NOW - timedelta(hours=1)).isoformat(),
                "corrective_measure_available_at": (NOW - timedelta(minutes=30)).isoformat(),
            },
            "analyst",
        )
        case = self.store.add_evidence(
            case["id"],
            {
                "source_type": "incident_record",
                "source_ref": "IR-2026-071",
                "retrieved_at": NOW.isoformat(),
                "sha256": "a" * 64,
                "description": "事件记录确认恶意行为者在未经许可的客户系统中实际利用。",
                "product_relevance": "网关 GW-220 构建中的同一组件和可达路径。",
                "reliable_malicious_exploitation": "yes",
                "malicious_actor_confirmed": True,
                "without_permission_confirmed": True,
                "actual_exploitation_confirmed": True,
            },
            "analyst",
        )
        evidence_id = case["evidence"][0]["id"]
        return self.store.confirm_awareness(
            case["id"],
            (NOW - timedelta(minutes=45)).isoformat(),
            "Authorized Manufacturer [local-profile]",
            True,
            "制造商完成产品相关性与事件证据的初步评估后达到合理确定。",
            [evidence_id],
        )

    def test_awareness_is_manual_and_requires_initial_assessment_and_evidence(self) -> None:
        case = self._manual_case()
        with self.assertRaisesRegex(ValueError, "初步评估"):
            self.store.confirm_awareness(
                case["id"],
                NOW.isoformat(),
                "manufacturer",
                True,
                "manual assessment",
                ["missing"],
            )
        case = self.store.update_case(
            case["id"],
            {"initial_assessment_completed_at": NOW.isoformat()},
            "analyst",
        )
        with self.assertRaisesRegex(ValueError, "未来"):
            self.store.confirm_awareness(
                case["id"],
                (NOW + timedelta(days=1)).isoformat(),
                "manufacturer",
                True,
                "manual assessment",
                ["missing"],
            )

    def test_reportable_requires_structured_evidence(self) -> None:
        case = self._manual_case()
        case = self.store.update_case(
            case["id"],
            {
                "applicability_status": "known_affected",
                "applicability_justification": "affected",
                "exploitation_evidence_status": "reliable_evidence",
                "initial_assessment_completed_at": NOW.isoformat(),
            },
            "analyst",
        )
        evidence = self.store.add_evidence(
            case["id"],
            {
                "description": "Only a public KEV signal.",
                "reliable_malicious_exploitation": "unknown",
            },
            "analyst",
        )
        case = self.store.confirm_awareness(
            case["id"],
            NOW.isoformat(),
            "manufacturer",
            True,
            "manual confirmation",
            [evidence["evidence"][0]["id"]],
        )
        with self.assertRaisesRegex(ValueError, "结构化证据"):
            self.store.review_case(
                case["id"],
                "technical",
                "Technical Reviewer",
                str(uuid.uuid4()),
                "reportable",
                "proposal",
            )

    def test_two_distinct_reviewers_are_required_for_final_decision(self) -> None:
        case = self._qualify_reportable_case()
        technical = self.store.create_reviewer(
            "Technical Reviewer", "technical", "technical-pin-2026"
        )
        compliance = self.store.create_reviewer(
            "Compliance Reviewer", "compliance", "compliance-pin-2026"
        )
        case = self.store.review_case(
            case["id"],
            "technical",
            technical["display_name"],
            technical["id"],
            "reportable",
            "产品适用性与实际恶意利用证据成立。",
        )
        self.assertEqual(case["art14_decision"], "not_assessed")
        self.assertEqual(case["workflow_status"], "technical_review")
        with self.assertRaisesRegex(ValueError, "不同"):
            self.store.review_case(
                case["id"],
                "compliance",
                technical["display_name"],
                technical["id"],
                "reportable",
                "same account",
            )
        case = self.store.review_case(
            case["id"],
            "compliance",
            compliance["display_name"],
            compliance["id"],
            "reportable",
            "独立复核同意技术结论。",
        )
        self.assertEqual(case["art14_decision"], "reportable")
        self.assertEqual(case["workflow_status"], "approved")

    def test_disagreement_does_not_create_final_decision(self) -> None:
        case = self._qualify_reportable_case()
        case = self.store.review_case(
            case["id"],
            "technical",
            "Technical",
            "tech-id",
            "reportable",
            "technical view",
        )
        case = self.store.review_case(
            case["id"],
            "compliance",
            "Compliance",
            "compliance-id",
            "needs_more_information",
            "evidence gap",
        )
        self.assertEqual(case["art14_decision"], "not_assessed")
        self.assertEqual(case["workflow_status"], "compliance_review")

    def test_stage_receipts_are_unique_and_auditable(self) -> None:
        case = self._qualify_reportable_case()
        case = self.store.review_case(
            case["id"], "technical", "Tech", "tech-id", "reportable", "agree"
        )
        case = self.store.review_case(
            case["id"], "compliance", "Compliance", "comp-id", "reportable", "agree"
        )
        case = self.store.mark_submitted(
            case["id"],
            "Manufacturer",
            "early-warning",
            NOW.isoformat(),
            "SRP-EW-001",
        )
        self.assertEqual(case["reporting_stage"], "early_warning_submitted")
        self.assertEqual(len(case["submission_receipts"]), 1)
        with self.assertRaisesRegex(ValueError, "已登记"):
            self.store.mark_submitted(
                case["id"],
                "Manufacturer",
                "early-warning",
                NOW.isoformat(),
                "SRP-EW-002",
            )

    def test_new_build_or_sbom_hash_reopens_prior_open_decision(self) -> None:
        job_one = {
            "id": str(uuid.uuid4()),
            "project_name": "Gateway",
            "project_version": "1.0",
            "software_build": "build-1",
            "source_sha256": "1" * 64,
            "file_name": "gateway.cdx.json",
            "result": {
                "matches": [
                    {
                        "component_name": "lib",
                        "component_version": "1.0",
                        "source_identifier": "CVE-2026-12345",
                        "euvd_id": "EUVD-2026-12345",
                    }
                ]
            },
        }
        case = self.store.create_case_from_finding(job_one, 0, "analyst")
        self.assertEqual(case["sbom_sha256"], "1" * 64)
        self.store.register_sbom_snapshot(
            {
                **job_one,
                "id": str(uuid.uuid4()),
                "software_build": "build-2",
                "source_sha256": "2" * 64,
            }
        )
        case = self.store.get_case(case["id"])
        self.assertEqual(case["workflow_status"], "draft")
        self.assertEqual(case["reporting_stage"], "reopened")
        self.assertIn("SBOM", case["stale_reason"])

    def test_known_not_affected_requires_reason(self) -> None:
        case = self._manual_case()
        with self.assertRaisesRegex(ValueError, "技术理由"):
            self.store.update_case(
                case["id"],
                {
                    "applicability_status": "known_not_affected",
                    "applicability_justification": "",
                },
                "analyst",
            )


class Art14AndSrpTests(unittest.TestCase):
    def test_deadlines_follow_awareness_and_corrective_measure(self) -> None:
        aware = datetime(2026, 9, 11, 8, 0, tzinfo=timezone.utc)
        corrective = datetime(2026, 9, 12, 9, 0, tzinfo=timezone.utc)
        result = deadline_status(
            {
                "awareness_at": aware.isoformat(),
                "awareness_confirmed_by": "manufacturer",
                "corrective_measure_available_at": corrective.isoformat(),
            },
            now=aware,
        )
        self.assertEqual(
            result["early_warning_24h"]["due_at"],
            (aware + timedelta(hours=24)).isoformat(timespec="seconds"),
        )
        self.assertEqual(
            result["notification_72h"]["due_at"],
            (aware + timedelta(hours=72)).isoformat(timespec="seconds"),
        )
        self.assertEqual(
            result["final_report_14d"]["due_at"],
            (corrective + timedelta(days=14)).isoformat(timespec="seconds"),
        )

    def test_q16_stage_matrix_and_manual_submission_boundary(self) -> None:
        case = {
            "id": "case-1",
            "project_name": "Gateway",
            "project_version": "1.0",
            "software_build": "build-1",
            "workflow_status": "approved",
            "art14_decision": "reportable",
            "awareness_at": NOW.isoformat(),
            "awareness_confirmed_by": "manufacturer",
            "corrective_measure_available_at": NOW.isoformat(),
            "srp_fields": {
                "manufacturer_name": "Example GmbH",
                "title": "Actively exploited vulnerability",
                "product_type": "Default",
                "member_states_where_available": "DE, FR",
                "general_information": "Initial assessment",
                "vulnerability_nature": "Memory corruption",
                "exploit_nature": "Remote malicious exploitation",
                "corrective_measures_taken": "Security update issued",
                "user_measures": "Install update",
                "full_vulnerability_description": "Full description",
                "vulnerability_severity": "High",
                "vulnerability_impact": "Remote code execution",
                "security_update_details": "Version 1.0.1",
            },
        }
        self.assertTrue(srp_readiness(case, "early-warning")["ready"])
        self.assertTrue(srp_readiness(case, "notification")["ready"])
        self.assertTrue(srp_readiness(case, "final-report")["ready"])
        payload = build_srp_payload(case, "final-report")
        self.assertTrue(payload["draft_only"])
        self.assertFalse(payload["automatic_submission"])


class VexTests(unittest.TestCase):
    def test_cyclonedx_known_not_affected_without_reason_is_downgraded(self) -> None:
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:test",
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": "product:1",
                    "name": "Gateway",
                    "version": "1.0",
                }
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2026-12345",
                    "affects": [{"ref": "product:1"}],
                    "analysis": {"state": "not_affected"},
                }
            ],
        }
        parsed = parse_vex_bytes(json.dumps(payload).encode())
        self.assertEqual(parsed["format"], "cyclonedx-1.7")
        self.assertEqual(parsed["entries"][0]["status"], "under_investigation")
        self.assertTrue(parsed["warnings"])

    def test_cyclonedx_1_5_accepted_after_spec_widening(self) -> None:
        # spec 放宽到 1.5/1.6/1.7（与 SBOM Workbench vex_consume 一致）：
        # 外部 PSIRT 签发的 1.5/1.6 VEX 不再被拒，format 动态记录实际版本。
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:test15",
            "metadata": {"component": {"bom-ref": "p:1", "name": "X", "version": "1.0"}},
            "vulnerabilities": [
                {"id": "CVE-2026-1", "affects": [{"ref": "p:1"}],
                 "analysis": {"state": "not_affected", "justification": "code_not_present"}},
            ],
        }
        parsed = parse_vex_bytes(json.dumps(payload).encode())
        self.assertEqual(parsed["format"], "cyclonedx-1.5")
        self.assertEqual(parsed["entries"][0]["status"], "known_not_affected")

    def test_csaf_conflicting_statuses_are_rejected(self) -> None:
        payload = {
            "document": {
                "category": "vex",
                "csaf_version": "2.0",
                "tracking": {"id": "test-vex"},
            },
            "product_tree": {
                "full_product_names": [{"product_id": "p1", "name": "Gateway"}]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-12345",
                    "product_status": {
                        "known_affected": ["p1"],
                        "known_not_affected": ["p1"],
                    },
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "冲突"):
            parse_vex_bytes(json.dumps(payload).encode())

    def test_zero_day_export_never_invents_cve_unknown(self) -> None:
        case = {
            "id": "case-zero-day",
            "project_name": "Gateway",
            "project_version": "1.0",
            "cve_id": "",
            "euvd_id": "",
            "applicability_status": "under_investigation",
            "applicability_justification": "No public identifier assigned.",
            "art14_decision": "not_assessed",
            "workflow_status": "draft",
            "srp_fields": {},
        }
        cyclonedx = json.dumps(build_cyclonedx_vex(case))
        csaf = json.dumps(build_csaf_vex(case))
        self.assertNotIn("CVE-UNKNOWN", cyclonedx)
        self.assertNotIn("CVE-UNKNOWN", csaf)
        self.assertNotIn('"cve"', csaf)


if __name__ == "__main__":
    unittest.main()
