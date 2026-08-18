from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from app import matcher


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_demo_snapshot.py"
DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"
SPEC = importlib.util.spec_from_file_location("bootstrap_demo_snapshot", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class DemoSnapshotTests(unittest.TestCase):
    def test_container_points_to_the_built_in_snapshot_and_sidecar(self) -> None:
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("EUVD_LOCAL_DB=/app/euvd/euvd-readonly.sqlite3", dockerfile)
        self.assertIn(
            "EUVD_LOCAL_DB_SHA256_FILE=/app/euvd/euvd-readonly.sqlite3.sha256",
            dockerfile,
        )

    def test_snapshot_is_hash_bound_synthetic_and_matcher_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "data"
            result = MODULE.build_demo_snapshot(output)
            database = Path(result["database"])
            sidecar = Path(result["sha256_file"])
            actual = hashlib.sha256(database.read_bytes()).hexdigest()
            self.assertEqual(actual, sidecar.read_text(encoding="ascii").split()[0])

            with closing(sqlite3.connect(database)) as connection:
                metadata = dict(
                    connection.execute("SELECT key, value FROM web_snapshot_metadata")
                )
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertEqual(metadata["source_id"], "SYNTHETIC_DEMO_NOT_EUVD")
            self.assertEqual(metadata["reference_data_freshness"], "synthetic_demo_not_current")
            self.assertIn("not evidence for CRA Article 14", metadata["consumer_boundary"])
            self.assertNotIn("sbom_lookup_runs", tables)
            self.assertNotIn("sbom_lookup_results", tables)

            previous = (
                matcher.LOCAL_EUVD_DB,
                matcher.LOCAL_EUVD_SHA256_FILE,
                matcher.LOCAL_EUVD_EXPECTED_SHA256,
                matcher.EuvdClient._local_validation_cache,
            )
            try:
                matcher.LOCAL_EUVD_DB = database
                matcher.LOCAL_EUVD_SHA256_FILE = sidecar
                matcher.LOCAL_EUVD_EXPECTED_SHA256 = ""
                matcher.EuvdClient._local_validation_cache = None
                status = matcher.EuvdClient.local_snapshot_status()
                self.assertIsNotNone(status)
                self.assertEqual(status["status"], "local_degraded")
                self.assertEqual(status["source_id"], "SYNTHETIC_DEMO_NOT_EUVD")
            finally:
                (
                    matcher.LOCAL_EUVD_DB,
                    matcher.LOCAL_EUVD_SHA256_FILE,
                    matcher.LOCAL_EUVD_EXPECTED_SHA256,
                    matcher.EuvdClient._local_validation_cache,
                ) = previous

    def test_existing_snapshot_is_not_overwritten_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            MODULE.build_demo_snapshot(output)
            with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
                MODULE.build_demo_snapshot(output)


if __name__ == "__main__":
    unittest.main()
