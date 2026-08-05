"""Tests for backlog 4: VEX draft suggestion + case prefill."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.vex_draft import suggest_applicability
from app.workflow_store import WorkflowStore


class SuggestApplicabilityTests(unittest.TestCase):
    def test_version_hit_suggests_known_affected(self) -> None:
        status, rationale = suggest_applicability(
            {
                "component_applicability": "受影响版本条件命中",
                "affected_versions": "0 <=2.5",
                "match_reason": "EUVD 版本上限包含 2.5",
            }
        )
        self.assertEqual(status, "known_affected")
        self.assertIn("0 <=2.5", rationale)
        self.assertIn("EUVD 版本上限包含 2.5", rationale)

    def test_review_flag_suggests_under_investigation(self) -> None:
        status, _ = suggest_applicability({"component_applicability": "待人工核验"})
        self.assertEqual(status, "under_investigation")

    def test_empty_finding_falls_back_to_review(self) -> None:
        status, rationale = suggest_applicability({})
        self.assertEqual(status, "under_investigation")
        self.assertIn("待人工核验", rationale)

    def test_never_auto_known_not_affected(self) -> None:
        # CSAF requires positive evidence for not_affected; the suggester must
        # never auto-claim it even when the version looks safe.
        status, _ = suggest_applicability(
            {"component_applicability": "待人工核验", "match_reason": "版本不在受影响范围"}
        )
        self.assertNotEqual(status, "known_not_affected")


class CreateCasePrefillTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = WorkflowStore(Path(self._tmp.name) / "wb.sqlite3")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_case_created_with_drafted_applicability(self) -> None:
        job = {
            "id": "11111111-1111-1111-1111-111111111111",
            "project_name": "P",
            "project_version": "1.0",
            "software_build": "b",
            "customer": "C",
            "file_name": "f.xlsx",
            "source_sha256": "abc",
            "result": {
                "matches": [
                    {
                        "component_name": "lib",
                        "component_version": "1.0",
                        "euvd_id": "EUVD-2024-1",
                        "exploitation_status": "",
                        "component_applicability": "受影响版本条件命中",
                        "affected_versions": "0 <=2.5",
                        "match_reason": "上限 2.5",
                    }
                ]
            },
        }
        case = self.store.create_case_from_finding(job, 0, "analyst")
        self.assertEqual(case["applicability_status"], "known_affected")
        self.assertIn("0 <=2.5", case["applicability_justification"])


if __name__ == "__main__":
    unittest.main()
