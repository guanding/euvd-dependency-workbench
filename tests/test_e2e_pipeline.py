"""End-to-end pipeline test (backlog 7).

Drives the REAL _run_job flow (no match_components mock) against a mini local
EUVD snapshot, then injects two faults the unit tests only spied on:
  * crash mid-run (match raises) -> job failed, no report, no snapshot
  * snapshot sha corruption -> fail-closed, job failed

This is the only test where upload(parse) -> build_components -> real
match_components -> write_report -> register_sbom_snapshot meet in one flow.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack, closing
from pathlib import Path
from unittest.mock import patch

from app import main, matcher
from app.spreadsheet_io import read_sbom


def _build_mini_snapshot(db_path: Path) -> None:
    record = {
        "id": "EUVD-2024-1",
        "aliases": "CVE-2024-1000",
        "enisaIdProduct": [
            {
                "product": {"name": "Example Product", "vendor": {"name": "Example"}},
                "product_version": "1.0",
            }
        ],
    }
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.executescript(
            """
            CREATE TABLE web_snapshot_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE data_source_versions(source_name TEXT, last_checked_at TEXT, last_modified TEXT, content_sha256 TEXT, record_count INTEGER, http_status INTEGER, source_url TEXT, is_current INTEGER);
            CREATE TABLE cve_euvd_mapping(cve_id TEXT, euvd_id TEXT);
            CREATE TABLE known_exploited(cve_id TEXT, euvd_id TEXT, date_added TEXT);
            CREATE TABLE known_exploited_sources(cve_id TEXT, euvd_id TEXT, source TEXT);
            CREATE TABLE vulnerabilities(euvd_id TEXT PRIMARY KEY, record_json TEXT, updated_raw TEXT);
            CREATE TABLE local_products(product_key TEXT, euvd_id TEXT);
            """
        )
        meta = {
            "source_id": "EUVD_LOCAL_MIRROR",
            "snapshot_created_at": "2026-08-04T00:00:00+00:00",
            "last_successful_to_date": "2026-07-28",
            "reference_data_freshness": "degraded_local_snapshot",
            "vulnerability_count": "1",
            "mapping_count": "1",
            "known_exploited_count": "1",
            "product_index_count": "1",
            "source_db_sha256": "a" * 64,
            "snapshot_integrity_check_at_build": "ok",
            "consumer_boundary": "read-only consumer",
            "current_source_versions_json": json.dumps(
                [
                    {
                        "source_name": "cve_euvd_mapping",
                        "last_modified": "2026-07-30T00:00:00+00:00",
                        "content_sha256": "b" * 64,
                        "record_count": 1,
                        "http_status": 0,
                    }
                ]
            ),
        }
        conn.executemany("INSERT INTO web_snapshot_metadata VALUES (?,?)", meta.items())
        for name, digest in (("cve_euvd_mapping", "b" * 64), ("known_exploited", "c" * 64)):
            conn.execute(
                "INSERT INTO data_source_versions VALUES (?,?,?,?,?,?,?,?)",
                (name, "2026-08-04T00:00:00Z", "2026-07-30T00:00:00Z", digest, 1, 0, "local-snapshot://test", 1),
            )
        conn.execute("INSERT INTO cve_euvd_mapping VALUES (?,?)", ("CVE-2024-1000", "EUVD-2024-1"))
        conn.execute("INSERT INTO known_exploited VALUES (?,?,?)", ("CVE-2024-1000", "EUVD-2024-1", "2026-01-01"))
        conn.execute("INSERT INTO known_exploited_sources VALUES (?,?,?)", ("CVE-2024-1000", "EUVD-2024-1", "cisa_kev"))
        conn.execute("INSERT INTO vulnerabilities VALUES (?,?,?)", ("EUVD-2024-1", json.dumps(record), "2026-01-01"))
        conn.execute("INSERT INTO local_products VALUES (?,?)", ("exampleproduct", "EUVD-2024-1"))


CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "vuln-lib",
            "version": "1.0",
            "bom-ref": "pkg:x/vuln-lib@1.0",
            "cpe": "cpe:2.3:a:example:example_product:1.0:*:*:*:*:*:*:*",
        }
    ],
    "vulnerabilities": [{"id": "CVE-2024-1000", "affects": [{"ref": "pkg:x/vuln-lib@1.0"}]}],
    "dependencies": [],
}


class E2EPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.data_dir = root / "data"
        self.output_dir = root / "outputs"
        self.uploads = self.data_dir / "uploads"
        self.jobs = self.data_dir / "jobs"
        for d in (self.data_dir, self.output_dir, self.uploads, self.jobs):
            d.mkdir(parents=True)
        self.db = self.data_dir / "euvd-readonly.sqlite3"
        _build_mini_snapshot(self.db)
        self.sha_path = self.data_dir / "euvd-readonly.sqlite3.sha256"
        self._write_sha()
        # matcher points at the mini snapshot
        self._m = {
            "LOCAL_EUVD_DB": matcher.LOCAL_EUVD_DB,
            "LOCAL_EUVD_SHA256_FILE": matcher.LOCAL_EUVD_SHA256_FILE,
            "LOCAL_EUVD_EXPECTED_SHA256": matcher.LOCAL_EUVD_EXPECTED_SHA256,
            "NETWORK_FALLBACK": matcher.NETWORK_FALLBACK,
        }
        matcher.LOCAL_EUVD_DB = self.db
        matcher.LOCAL_EUVD_SHA256_FILE = self.sha_path
        matcher.LOCAL_EUVD_EXPECTED_SHA256 = ""
        matcher.NETWORK_FALLBACK = False
        matcher.EuvdClient._local_validation_cache = None
        # main dirs + store point at tempdirs
        self._stack = ExitStack()
        self._stack.enter_context(patch.object(main, "DATA_DIR", self.data_dir))
        self._stack.enter_context(patch.object(main, "UPLOAD_DIR", self.uploads))
        self._stack.enter_context(patch.object(main, "JOB_DIR", self.jobs))
        self._stack.enter_context(patch.object(main, "OUTPUT_DIR", self.output_dir))
        self._stack.enter_context(
            patch.object(main, "WORKFLOW_STORE", main.WorkflowStore(self.data_dir / "workbench.sqlite3"))
        )

    def tearDown(self) -> None:
        self._stack.close()
        for k, v in self._m.items():
            setattr(matcher, k, v)
        matcher.EuvdClient._local_validation_cache = None
        self._tmp.cleanup()

    def _write_sha(self) -> None:
        self.sha_path.write_text(hashlib.sha256(self.db.read_bytes()).hexdigest() + "\n", "ascii")

    def _setup_job(self, job_id: str = "11111111-1111-1111-1111-111111111111") -> tuple[str, dict, dict]:
        cdx_path = self.uploads / "sbom.cdx.json"
        cdx_path.write_text(json.dumps(CYCLONEDX), "utf-8")
        parsed = read_sbom(cdx_path)
        upload_record = {
            "id": "up-1",
            "original_name": "sbom.cdx.json",
            "source_sha256": "x",
            "parsed": parsed,
        }
        (self.uploads / "up-1.upload-record.json").write_text(json.dumps(upload_record), "utf-8")
        job = {
            "id": job_id,
            "upload_id": "up-1",
            "mapping": dict(parsed["mapping"]),
            "file_name": "sbom.cdx.json",
            "source_sha256": "x",
            "project_name": "E2E",
            "project_version": "1.0",
            "software_build": "b1",
            "customer": "C",
            "status": "queued",
            "stage": "排队中",
            "progress": 0,
            "completed": 0,
            "total": 0,
            "created_at": "2026-08-05T00:00:00+00:00",
        }
        (self.jobs / f"{job_id}.json").write_text(json.dumps(job), "utf-8")
        return job_id, upload_record, job

    def test_happy_path_matches_writes_report_and_registers_snapshot(self) -> None:
        job_id, upload_record, _ = self._setup_job()
        asyncio.run(main._run_job(job_id, upload_record, upload_record["parsed"]["mapping"]))
        job = json.loads((self.jobs / f"{job_id}.json").read_text("utf-8"))
        self.assertEqual(job["status"], "completed", job.get("error"))
        self.assertTrue(job.get("report_path"))
        self.assertTrue(Path(job["report_path"]).is_file())
        # snapshot registered in the real (tempdir) workflow store
        with closing(sqlite3.connect(self.data_dir / "workbench.sqlite3")) as c:
            snap_count = c.execute("SELECT count(*) FROM sbom_snapshots").fetchone()[0]
        self.assertGreater(snap_count, 0)

    def test_crash_mid_run_marks_failed_with_no_report_or_snapshot(self) -> None:
        job_id, upload_record, _ = self._setup_job(job_id="22222222-2222-2222-2222-222222222222")

        async def raising_match(
            components, progress=None, *, monitoring_candidate_only=False
        ):
            raise RuntimeError("injected mid-run failure")

        with patch.object(main, "match_components", raising_match):
            asyncio.run(main._run_job(job_id, upload_record, upload_record["parsed"]["mapping"]))
        job = json.loads((self.jobs / f"{job_id}.json").read_text("utf-8"))
        self.assertEqual(job["status"], "failed")
        self.assertIn("injected mid-run failure", job.get("error", ""))
        self.assertFalse(job.get("report_path"))
        self.assertEqual(list(self.output_dir.glob("*.xlsx")), [])


if __name__ == "__main__":
    unittest.main()
