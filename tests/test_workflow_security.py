"""Tests for step 7 workflow security gates.

Three audit findings:
  * HIGH: awareness could be re-confirmed on approved/submitted/closed cases
    (confirm_awareness must refuse once a case reaches a terminal state).
  * HIGH: stale reopen matched cases by project_name only, so the same product
    name at two different customers would cross-reopen each other. Must scope by
    customer.
  * MEDIUM: audit_events had no hash chain, so a deleted/reordered/tampered row
    was undetectable. Each event now digests the previous event's digest.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.workflow_store import WorkflowStore

NOW = datetime.now(timezone.utc).replace(microsecond=0)


class WorkflowSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = WorkflowStore(Path(self.temporary.name) / "workbench.sqlite3")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manual_case(self) -> dict:
        return self.store.create_manual_case(
            {
                "project_name": "Gateway",
                "project_version": "1.0",
                "software_build": "b1",
                "component_name": "lib",
                "component_version": "1.0",
                "cve_id": "CVE-2026-1",
                "euvd_id": "EUVD-2026-1",
            },
            "analyst",
        )

    def _qualify(self) -> dict:
        case = self._manual_case()
        case = self.store.update_case(
            case["id"],
            {
                "applicability_status": "known_affected",
                "applicability_justification": "包含且可达",
                "exploitation_evidence_status": "reliable_evidence",
                "exploitation_evidence_summary": "确认利用",
                "initial_assessment_completed_at": (NOW - timedelta(hours=1)).isoformat(),
            },
            "analyst",
        )
        case = self.store.add_evidence(
            case["id"],
            {
                "source_type": "incident",
                "source_ref": "IR-1",
                "retrieved_at": NOW.isoformat(),
                "sha256": "a" * 64,
                "description": "实际利用",
                "product_relevance": "同构建",
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
            "Mfg",
            True,
            "依据",
            [evidence_id],
        )

    def test_awareness_locked_in_terminal_state(self) -> None:
        case = self._qualify()  # draft + awareness confirmed
        with self.store.connect() as connection:
            connection.execute(
                "UPDATE cases SET workflow_status='submitted' WHERE id=?",
                (case["id"],),
            )
        evidence_id = case["evidence"][0]["id"]
        with self.assertRaisesRegex(ValueError, "已"):
            self.store.confirm_awareness(
                case["id"],
                (NOW - timedelta(minutes=40)).isoformat(),
                "Mfg2",
                True,
                "修正",
                [evidence_id],
            )

    def test_awareness_still_allowed_in_draft(self) -> None:
        # In draft the analyst may still correct the awareness time; the lock
        # only applies to terminal states (approved/submitted/closed).
        case = self._qualify()
        evidence_id = case["evidence"][0]["id"]
        updated = self.store.confirm_awareness(
            case["id"],
            (NOW - timedelta(minutes=30)).isoformat(),
            "Mfg2",
            True,
            "修正",
            [evidence_id],
        )
        self.assertEqual(updated["awareness_confirmed_by"], "Mfg2")

    def _snapshot(self, job_id: str, project: str, version: str, customer: str, sha: str) -> str:
        return self.store.register_sbom_snapshot(
            {
                "id": job_id,
                "project_name": project,
                "project_version": version,
                "software_build": "b1",
                "customer": customer,
                "file_name": "f.xlsx",
                "source_sha256": sha,
            },
            sha,
            "table",
            "1",
        )

    def _link_case(self, project: str, customer: str, snapshot_id: str, sha: str) -> str:
        case_id = str(uuid.uuid4())
        now = NOW.isoformat()
        with self.store.connect() as connection:
            connection.execute(
                "INSERT INTO cases(id, source_key, project_name, customer, "
                "sbom_snapshot_id, sbom_sha256, workflow_status, stale_reason, "
                "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, 'draft', '', ?, ?)",
                (case_id, f"key-{case_id}", project, customer, snapshot_id, sha, now, now),
            )
        return case_id

    def test_stale_reopen_scoped_by_customer(self) -> None:
        snap_a = self._snapshot("job-a", "Gateway", "1.0", "CustomerA", "sha-a")
        snap_b = self._snapshot("job-b", "Gateway", "1.0", "CustomerB", "sha-b")
        case_a = self._link_case("Gateway", "CustomerA", snap_a, "sha-a")
        case_b = self._link_case("Gateway", "CustomerB", snap_b, "sha-b")
        # new snapshot for CustomerA only (version change) -> reopen CustomerA
        # case only; CustomerB's case must be untouched.
        self._snapshot("job-a2", "Gateway", "2.0", "CustomerA", "sha-a2")
        a = self.store.get_case(case_a)
        b = self.store.get_case(case_b)
        self.assertNotEqual(a["stale_reason"], "")
        self.assertEqual(b["stale_reason"], "")

    def test_audit_events_form_hash_chain(self) -> None:
        with self.store.connect() as connection:
            self.store._audit(connection, None, "evt", "alice", {"n": 1})
            self.store._audit(connection, None, "evt", "alice", {"n": 2})
            self.store._audit(connection, None, "evt", "bob", {"n": 3})
            rows = connection.execute(
                "SELECT payload_json, payload_sha256, prev_hash "
                "FROM audit_events ORDER BY id"
            ).fetchall()
        self.assertEqual(rows[0]["prev_hash"], "")
        self.assertEqual(rows[1]["prev_hash"], rows[0]["payload_sha256"])
        self.assertEqual(rows[2]["prev_hash"], rows[1]["payload_sha256"])
        # tamper detection: recompute the chain end-to-end
        previous = ""
        for row in rows:
            expected = hashlib.sha256(
                f"{previous}:{row['payload_json']}".encode("utf-8")
            ).hexdigest()
            self.assertEqual(row["payload_sha256"], expected)
            previous = row["payload_sha256"]


if __name__ == "__main__":
    unittest.main()
