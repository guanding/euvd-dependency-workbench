"""Tests for EuvdClient.list_euvd_records (改进1 EUVD 目录列表/搜索 API).

Verifies pagination, EUVD-ID prefix search, CVE search, KEV marker, severity
labeling, page_size cap, and fail-closed (None when snapshot unavailable).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from app import matcher


def _record(cve: str, score, name: str) -> dict:
    return {
        "aliases": f"{cve}\n",
        "baseScore": score,
        "datePublished": "Apr 1, 2024, 12:00:00 PM",
        "dateUpdated": "Aug 1, 2024, 12:00:00 PM",
        "description": f"Description for {name}. " * 20,
        "enisaIdProduct": [
            {"product": {"name": name, "vendor": {"name": "vend"}}, "product_version": "1.0"}
        ],
    }


class EuvdRecordsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name) / "euvd-readonly.sqlite3"
        rows = [
            ("EUVD-2024-1", _record("CVE-2024-1000", 9.5, "prodA")),
            ("EUVD-2024-2", _record("CVE-2024-2000", 5.0, "prodB")),
            ("EUVD-2024-3", _record("CVE-2024-3000", 2.0, "prodC")),
        ]
        with closing(sqlite3.connect(self.database_path)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE web_snapshot_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE data_source_versions(
                    source_name TEXT, last_checked_at TEXT, last_modified TEXT,
                    content_sha256 TEXT, record_count INTEGER, http_status INTEGER,
                    source_url TEXT, is_current INTEGER);
                CREATE TABLE cve_euvd_mapping(cve_id TEXT, euvd_id TEXT);
                CREATE TABLE known_exploited(cve_id TEXT, euvd_id TEXT, date_added TEXT);
                CREATE TABLE vulnerabilities(euvd_id TEXT PRIMARY KEY, record_json TEXT, updated_raw TEXT);
                """
            )
            connection.executemany(
                "INSERT INTO vulnerabilities VALUES (?, ?, ?)",
                [(eid, json.dumps(rec), "2026-01-01") for eid, rec in rows],
            )
            connection.executemany(
                "INSERT INTO cve_euvd_mapping VALUES (?, ?)",
                [("CVE-2024-1000", "EUVD-2024-1"),
                 ("CVE-2024-2000", "EUVD-2024-2"),
                 ("CVE-2024-3000", "EUVD-2024-3")],
            )
            # EUVD-2024-1 is in KEV; others are not
            connection.execute(
                "INSERT INTO known_exploited VALUES (?, ?, ?)",
                ("CVE-2024-1000", "EUVD-2024-1", "2026-01-01"),
            )
            meta = {
                "source_id": "EUVD_LOCAL_MIRROR",
                "snapshot_created_at": "2026-08-04T00:00:00+00:00",
                "last_successful_to_date": "2026-07-28",
                "reference_data_freshness": "degraded_local_snapshot",
                "vulnerability_count": "3",
                "snapshot_integrity_check_at_build": "ok",
                "consumer_boundary": "read-only consumer",
            }
            connection.executemany(
                "INSERT INTO web_snapshot_metadata VALUES (?, ?)", meta.items()
            )
        self.prev_db = matcher.LOCAL_EUVD_DB
        self.prev_sha = matcher.LOCAL_EUVD_SHA256_FILE
        self.prev_exp = matcher.LOCAL_EUVD_EXPECTED_SHA256
        matcher.LOCAL_EUVD_DB = self.database_path
        matcher.LOCAL_EUVD_SHA256_FILE = Path(str(self.database_path) + ".sha256")
        matcher.LOCAL_EUVD_SHA256_FILE.write_text(
            hashlib.sha256(self.database_path.read_bytes()).hexdigest() + "\n",
            encoding="ascii",
        )
        matcher.LOCAL_EUVD_EXPECTED_SHA256 = ""
        matcher.EuvdClient._local_validation_cache = None

    def tearDown(self) -> None:
        matcher.LOCAL_EUVD_DB = self.prev_db
        matcher.LOCAL_EUVD_SHA256_FILE = self.prev_sha
        matcher.LOCAL_EUVD_EXPECTED_SHA256 = self.prev_exp
        matcher.EuvdClient._local_validation_cache = None
        self.temporary.cleanup()

    def test_default_sort_desc_and_total(self):
        r = matcher.EuvdClient.list_euvd_records()
        self.assertEqual([x["euvd_id"] for x in r["records"]],
                         ["EUVD-2024-3", "EUVD-2024-2", "EUVD-2024-1"])
        self.assertEqual(r["total"], 3)

    def test_pagination(self):
        page1 = matcher.EuvdClient.list_euvd_records(page=1, page_size=2)
        page2 = matcher.EuvdClient.list_euvd_records(page=2, page_size=2)
        self.assertEqual(len(page1["records"]), 2)
        self.assertEqual(len(page2["records"]), 1)
        self.assertEqual(page2["records"][0]["euvd_id"], "EUVD-2024-1")

    def test_search_euvd_id_prefix(self):
        r = matcher.EuvdClient.list_euvd_records(q="EUVD-2024-1")
        self.assertEqual([x["euvd_id"] for x in r["records"]], ["EUVD-2024-1"])
        self.assertEqual(r["total"], 1)

    def test_search_cve_exact(self):
        r = matcher.EuvdClient.list_euvd_records(q="CVE-2024-2000")
        self.assertEqual([x["euvd_id"] for x in r["records"]], ["EUVD-2024-2"])

    def test_search_cve_prefix(self):
        r = matcher.EuvdClient.list_euvd_records(q="CVE-2024-")
        self.assertEqual(r["total"], 3)

    def test_kev_marker(self):
        r = matcher.EuvdClient.list_euvd_records()
        by_id = {x["euvd_id"]: x for x in r["records"]}
        self.assertTrue(by_id["EUVD-2024-1"]["kev"])
        self.assertFalse(by_id["EUVD-2024-2"]["kev"])

    def test_severity_labels(self):
        r = matcher.EuvdClient.list_euvd_records()
        sev = {x["euvd_id"]: x["severity"] for x in r["records"]}
        self.assertEqual(sev["EUVD-2024-1"], "严重")  # 9.5
        self.assertEqual(sev["EUVD-2024-2"], "中")    # 5.0
        self.assertEqual(sev["EUVD-2024-3"], "低")    # 2.0

    def test_page_size_capped_at_100(self):
        r = matcher.EuvdClient.list_euvd_records(page_size=500)
        self.assertEqual(r["page_size"], 100)

    def test_returns_none_when_snapshot_unavailable(self):
        # Corrupt the sha256 sidecar so validation fails → must return None
        matcher.LOCAL_EUVD_SHA256_FILE.write_text("00" * 32 + "\n", encoding="ascii")
        matcher.EuvdClient._local_validation_cache = None
        self.assertIsNone(matcher.EuvdClient.list_euvd_records())

    def test_record_shape(self):
        r = matcher.EuvdClient.list_euvd_records(q="EUVD-2024-1")
        rec = r["records"][0]
        for key in ("euvd_id", "cve_id", "cve_ids", "base_score", "severity",
                    "date_published", "date_updated", "products", "kev",
                    "description_preview"):
            self.assertIn(key, rec)
        self.assertEqual(rec["cve_id"], "CVE-2024-1000")
        self.assertEqual(rec["products"][0]["name"], "prodA")
        self.assertLessEqual(len(rec["description_preview"]), 200)


if __name__ == "__main__":
    unittest.main()
