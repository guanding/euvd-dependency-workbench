"""Tests for D2: idempotent jobs + cancel/retry + cross-store atomicity.

Covers the BackgroundTasks-enhanced job lifecycle:
  * _idempotent_job_id: same upload+mapping -> same job id (no duplicate spawns).
  * create_job reuses an active job instead of creating a new one.
  * cancel_job marks a queued/running job canceling; _run_job observes it (both
    the not-yet-started guard and the in-progress progress callback).
  * retry_job resets a failed/cancelled job back to queued.
  * _run_job persists the completed job JSON before registering the SQLite
    snapshot, so a crash between them leaves a repairable state (completed +
    no snapshot) rather than a contradictory one (snapshot + running).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
from fastapi import BackgroundTasks, HTTPException

from app import main
from app.main import _idempotent_job_id

UUID_A = "00000000-0000-0000-0000-000000000001"


def _upload_record(upload_id: str = UUID_A) -> dict:
    return {
        "id": upload_id,
        "original_name": "test.xlsx",
        "source_sha256": "abc123",
        "parsed": {
            "kind": "table",
            "headers": ["组件名称", "版本"],
            "sheet": "S",
            "header_row": 1,
            "rows": [{"组件名称": "openssl", "版本": "1.0"}],
            "mapping": {},
        },
    }


def _fake_result() -> dict:
    return {
        "summary": {"component_count": 1},
        "matches": [],
        "components": [{"row_number": 1, "name": "openssl", "version": "1.0", "result": "x"}],
        "errors": [],
    }


async def _fake_match(components, progress=None):
    for index, component in enumerate(components, start=1):
        if progress:
            await progress(index, len(components), getattr(component, "name", ""))
    return _fake_result()


class JobLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.job_dir = root / "jobs"
        self.upload_dir = root / "uploads"
        self.output_dir = root / "outputs"
        for directory in (self.job_dir, self.upload_dir, self.output_dir):
            directory.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _patches(self):
        return [
            patch.object(main, "JOB_DIR", self.job_dir),
            patch.object(main, "UPLOAD_DIR", self.upload_dir),
            patch.object(main, "OUTPUT_DIR", self.output_dir),
        ]

    def _write_upload(self, upload_id: str = UUID_A) -> dict:
        record = _upload_record(upload_id)
        (self.upload_dir / f"{upload_id}.upload-record.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        return record

    def _write_job(self, job_id: str, **overrides) -> dict:
        job = {
            "id": job_id,
            "upload_id": UUID_A,
            "mapping": {"name": "组件名称"},
            "file_name": "test.xlsx",
            "status": "queued",
            "stage": "排队中",
            "progress": 0,
            "created_at": "2026-08-04T00:00:00+00:00",
        }
        job.update(overrides)
        (self.job_dir / f"{job_id}.json").write_text(json.dumps(job), encoding="utf-8")
        return job

    def test_idempotent_job_id_is_deterministic(self) -> None:
        mapping = {"name": "组件名称", "version": "版本"}
        self.assertEqual(
            _idempotent_job_id(UUID_A, mapping),
            _idempotent_job_id(UUID_A, mapping),
        )
        self.assertNotEqual(
            _idempotent_job_id(UUID_A, mapping),
            _idempotent_job_id(UUID_A, {"name": "组件名称"}),
        )
        self.assertNotEqual(
            _idempotent_job_id(UUID_A, mapping),
            _idempotent_job_id("00000000-0000-0000-0000-000000000002", mapping),
        )

    def test_identifier_paths_are_uuid_validated_and_confined(self) -> None:
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            self.assertEqual(
                main._job_path(UUID_A),
                (self.job_dir / f"{UUID_A}.json").resolve(),
            )
            self.assertEqual(
                main._upload_record_path(UUID_A),
                (self.upload_dir / f"{UUID_A}.upload-record.json").resolve(),
            )
            for helper in (
                main._job_path,
                main._upload_record_path,
                main._legacy_upload_record_path,
            ):
                with self.subTest(helper=helper.__name__):
                    with self.assertRaises(HTTPException) as caught:
                        helper("../../outside")
                    self.assertEqual(caught.exception.status_code, 400)

    def test_export_path_rejects_untrusted_path_segments(self) -> None:
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            generated = main._safe_export_path(UUID_A, "vex-cyclonedx", "json")
            self.assertEqual(generated.parent, self.output_dir.resolve())
            self.assertRegex(generated.name, r"^export-[0-9a-f]{32}\.json$")
            for case_id, label, extension in (
                ("../../outside", "vex-cyclonedx", "json"),
                (UUID_A, "../outside", "json"),
                (UUID_A, "vex-cyclonedx", "../json"),
            ):
                with self.subTest(case_id=case_id, label=label, extension=extension):
                    with self.assertRaises(HTTPException) as caught:
                        main._safe_export_path(case_id, label, extension)
                    self.assertEqual(caught.exception.status_code, 400)

    def test_euvd_status_does_not_expose_transport_exception_details(self) -> None:
        transport_detail = "sensitive proxy detail credential=opaque-test-marker"

        class FailingClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

            async def get(self, *args, **kwargs):
                raise httpx.HTTPError(transport_detail)

        with (
            patch.object(main.EuvdClient, "local_snapshot_status", return_value=None),
            patch.object(main, "NETWORK_FALLBACK", True),
            patch.object(main.httpx, "AsyncClient", return_value=FailingClient()),
        ):
            response = asyncio.run(main.euvd_status())

        self.assertEqual(response["status"], "unavailable")
        self.assertNotIn(transport_detail, json.dumps(response))

    def test_create_job_reuses_active_job(self) -> None:
        self._write_upload()
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            stack.enter_context(patch.object(main, "WORKFLOW_STORE"))
            request = main.MatchRequest(
                upload_id=UUID_A, mapping={"name": "组件名称"}, project_name="P"
            )
            first = asyncio.run(main.create_job(request, BackgroundTasks()))
            second = asyncio.run(main.create_job(request, BackgroundTasks()))
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(list(self.job_dir.glob("*.json"))), 1)

    def test_cancel_running_job_marks_canceling(self) -> None:
        job_id = "11111111-1111-1111-1111-111111111111"
        self._write_job(job_id, status="running")
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            out = asyncio.run(main.cancel_job(job_id))
        self.assertEqual(out["status"], "canceling")
        saved = json.loads((self.job_dir / f"{job_id}.json").read_text())
        self.assertEqual(saved["status"], "canceling")

    def test_cancel_rejects_terminal_state(self) -> None:
        job_id = "22222222-2222-2222-2222-222222222222"
        self._write_job(job_id, status="completed")
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.cancel_job(job_id))
        self.assertEqual(caught.exception.status_code, 409)

    def test_retry_resets_failed_job(self) -> None:
        job_id = "33333333-3333-3333-3333-333333333333"
        self._write_upload()
        self._write_job(job_id, status="failed", error="boom")
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            out = asyncio.run(main.retry_job(job_id, BackgroundTasks()))
        self.assertEqual(out["status"], "queued")
        saved = json.loads((self.job_dir / f"{job_id}.json").read_text())
        self.assertEqual(saved["error"], "")

    def test_run_job_cancelled_before_start(self) -> None:
        job_id = "44444444-4444-4444-4444-444444444444"
        self._write_upload()
        self._write_job(job_id, status="canceling")
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            stack.enter_context(patch.object(main, "match_components", _fake_match))
            stack.enter_context(patch.object(main, "WORKFLOW_STORE"))
            asyncio.run(main._run_job(job_id, _upload_record(), {"name": "组件名称"}))
        saved = json.loads((self.job_dir / f"{job_id}.json").read_text())
        self.assertEqual(saved["status"], "cancelled")

    def test_run_job_persists_completed_before_snapshot(self) -> None:
        job_id = "55555555-5555-5555-5555-555555555555"
        self._write_upload()
        self._write_job(job_id, status="queued")
        store = MagicMock()
        seen: dict = {}

        def spy(job, *args):
            seen["file_status_at_register"] = json.loads(
                (self.job_dir / f"{job_id}.json").read_text()
            )["status"]

        store.register_sbom_snapshot.side_effect = spy
        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            stack.enter_context(patch.object(main, "match_components", _fake_match))
            stack.enter_context(patch.object(main, "WORKFLOW_STORE", store))
            stack.enter_context(patch.object(main, "write_report"))
            asyncio.run(main._run_job(job_id, _upload_record(), {"name": "组件名称"}))
        # snapshot registration saw an already-completed job file (not running)
        self.assertEqual(seen.get("file_status_at_register"), "completed")
        self.assertEqual(
            json.loads((self.job_dir / f"{job_id}.json").read_text())["status"],
            "completed",
        )

    def test_run_job_observes_canceling_during_run(self) -> None:
        job_id = "66666666-6666-6666-6666-666666666666"
        self._write_upload()
        self._write_job(job_id, status="running")

        async def fake(components, progress=None):
            # cancel arrives mid-run, before the first progress callback
            self._write_job(job_id, status="canceling")
            if progress:
                await progress(1, len(components), "openssl")
            return _fake_result()

        with ExitStack() as stack:
            for patcher in self._patches():
                stack.enter_context(patcher)
            stack.enter_context(patch.object(main, "match_components", fake))
            stack.enter_context(patch.object(main, "WORKFLOW_STORE"))
            asyncio.run(main._run_job(job_id, _upload_record(), {"name": "组件名称"}))
        saved = json.loads((self.job_dir / f"{job_id}.json").read_text())
        self.assertEqual(saved["status"], "cancelled")


class OrchestratorAvailabilityTests(unittest.TestCase):
    def test_running_state_is_available(self) -> None:
        from app.main import _orchestrator_alive

        self.assertTrue(_orchestrator_alive({"state": "running"}))

    def test_stale_finished_is_unavailable(self) -> None:
        from datetime import datetime, timedelta, timezone

        from app.main import _orchestrator_alive

        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.assertFalse(
            _orchestrator_alive({"state": "completed", "finished_at": old})
        )

    def test_fresh_finished_is_available(self) -> None:
        from datetime import datetime, timezone

        from app.main import _orchestrator_alive

        fresh = datetime.now(timezone.utc).isoformat()
        self.assertTrue(
            _orchestrator_alive({"state": "completed", "finished_at": fresh})
        )

    def test_no_finished_at_is_unavailable(self) -> None:
        from app.main import _orchestrator_alive

        self.assertFalse(_orchestrator_alive({"state": "idle"}))


if __name__ == "__main__":
    unittest.main()
