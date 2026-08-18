"""Tests for build_local_euvd_snapshot.py consumer table allowlist.

Verifies the consumer snapshot excludes the independent Mirror tool's
customer-audit tables (sbom_lookup_runs / sbom_lookup_results) both logically
(tables absent) and physically (secret bytes purged by VACUUM), and that the
exclusion is recorded in snapshot metadata. Also verifies defense-in-depth:
any future mirror table not on the allowlist is excluded by default.
"""

import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "scripts"
    / "build_local_euvd_snapshot.py"
)
_spec = importlib.util.spec_from_file_location("build_local_euvd_snapshot", _SCRIPT)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
build_snapshot = _mod.build_snapshot
ALLOWLIST = _mod.CONSUMER_TABLE_ALLOWLIST


def _make_source(path: Path) -> None:
    """Minimal mirror-shaped source DB, including two customer-audit tables
    that must NOT survive into the consumer snapshot."""
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute(
        "CREATE TABLE vulnerabilities ("
        " euvd_id TEXT PRIMARY KEY, record_json TEXT, updated_raw INTEGER)"
    )
    con.execute("INSERT INTO vulnerabilities VALUES ('EUVD-TEST-0001', '{}', 100)")
    con.execute("CREATE TABLE cve_euvd_mapping (cve_id TEXT, euvd_id TEXT)")
    con.execute("CREATE TABLE known_exploited (vuln_id TEXT)")
    con.execute("CREATE TABLE known_exploited_sources (source_name TEXT)")
    con.execute(
        "CREATE TABLE data_source_versions ("
        " source_name TEXT, source_url TEXT, last_checked_at TEXT,"
        " last_modified TEXT, content_sha256 TEXT, record_count INTEGER,"
        " http_status INTEGER, is_current INTEGER)"
    )
    con.execute("CREATE TABLE sync_state (key TEXT PRIMARY KEY, value TEXT)")
    con.execute(
        "INSERT INTO sync_state (key, value) VALUES "
        "('last_successful_to_date', '2026-07-28'),"
        "('reference_data_freshness', 'fresh')"
    )
    con.execute(
        "CREATE TABLE sync_runs (run_id TEXT, mode TEXT, status TEXT, started_at TEXT)"
    )
    # Customer-audit tables — must be excluded from the consumer snapshot.
    con.execute("CREATE TABLE sbom_lookup_runs (id TEXT, customer_input TEXT)")
    con.execute(
        "INSERT INTO sbom_lookup_runs VALUES ('r1', 'CUSTOMER-SECRET-SBOM-DATA')"
    )
    con.execute("CREATE TABLE sbom_lookup_results (id TEXT, finding TEXT)")
    con.execute(
        "INSERT INTO sbom_lookup_results VALUES ('r1', 'CUSTOMER-SECRET-FINDING')"
    )
    con.commit()
    con.close()


def _table_names(db_path: Path) -> set[str]:
    con = sqlite3.connect(db_path)
    try:
        return {
            str(r[0])
            for r in con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    finally:
        con.close()


class BuildSnapshotAllowlistTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.source = self.dir / "mirror.sqlite3"
        self.output = self.dir / "consumer.sqlite3"
        _make_source(self.source)
        self.result = build_snapshot(self.source, self.output)

    def tearDown(self):
        self._tmp.cleanup()

    def test_customer_audit_tables_excluded(self):
        tables = _table_names(self.output)
        self.assertNotIn("sbom_lookup_runs", tables)
        self.assertNotIn("sbom_lookup_results", tables)

    def test_consumer_tables_kept(self):
        tables = _table_names(self.output)
        for required in (
            "vulnerabilities",
            "cve_euvd_mapping",
            "known_exploited",
            "known_exploited_sources",
            "data_source_versions",
            "sync_state",
            "sync_runs",
            "local_products",
            "web_snapshot_metadata",
        ):
            self.assertIn(required, tables, f"consumer table {required!r} missing")

    def test_customer_secret_purged_from_file(self):
        # DROP alone leaves data in free pages; VACUUM must physically remove it.
        blob = self.output.read_bytes()
        self.assertNotIn(b"CUSTOMER-SECRET-SBOM-DATA", blob)
        self.assertNotIn(b"CUSTOMER-SECRET-FINDING", blob)

    def test_exclusion_recorded_in_result_and_metadata(self):
        self.assertIn("sbom_lookup_runs", self.result["consumer_excluded_tables"])
        self.assertIn("sbom_lookup_results", self.result["consumer_excluded_tables"])
        con = sqlite3.connect(self.output)
        try:
            meta = dict(con.execute("SELECT key, value FROM web_snapshot_metadata"))
        finally:
            con.close()
        self.assertEqual(
            set(meta["consumer_table_allowlist"].split(",")), set(ALLOWLIST)
        )
        self.assertIn("sbom_lookup_runs", meta["consumer_excluded_tables"])

    def test_wal_mode_source_builds_without_false_drift_trip(self):
        # The real mirror uses WAL journal mode. Opening a WAL DB read-only
        # touches -wal/-shm mtimes; drift detection must key on WAL size, not
        # mtime, or every build of the live mirror false-trips with "source
        # EUVD database or WAL changed while snapshot was built".
        source_wal = self.dir / "mirror_wal.sqlite3"
        _make_source(source_wal)  # all mirror-shaped tables, DELETE mode
        con = sqlite3.connect(source_wal)
        con.execute("PRAGMA journal_mode=WAL")  # switch to the real mirror's mode
        con.commit()
        con.close()
        output_wal = self.dir / "consumer_wal.sqlite3"
        result = build_snapshot(source_wal, output_wal)
        self.assertEqual(result["status"], "completed")

    def test_unknown_future_table_also_excluded(self):
        # Defense in depth: a mirror table not on the allowlist (e.g. a future
        # customer-sensitive table) must also be excluded by default.
        source2 = self.dir / "mirror2.sqlite3"
        _make_source(source2)
        con = sqlite3.connect(source2)
        con.execute("CREATE TABLE future_customer_evidence (id TEXT, secret TEXT)")
        con.execute("INSERT INTO future_customer_evidence VALUES ('x', 'FUTURE-SECRET')")
        con.commit()
        con.close()
        output2 = self.dir / "consumer2.sqlite3"
        build_snapshot(source2, output2)
        self.assertNotIn("future_customer_evidence", _table_names(output2))
        self.assertNotIn(b"FUTURE-SECRET", output2.read_bytes())


def _make_source_with_products(path: Path) -> None:
    """Mirror-shaped source carrying one real product and one placeholder
    "n/a" product, plus alias CVEs absent from the reference mapping."""
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute(
        "CREATE TABLE vulnerabilities ("
        " euvd_id TEXT PRIMARY KEY, record_json TEXT, updated_raw INTEGER)"
    )
    con.execute("CREATE TABLE cve_euvd_mapping (cve_id TEXT, euvd_id TEXT)")
    con.execute("CREATE TABLE known_exploited (vuln_id TEXT)")
    con.execute("CREATE TABLE known_exploited_sources (source_name TEXT)")
    con.execute(
        "CREATE TABLE data_source_versions ("
        " source_name TEXT, source_url TEXT, last_checked_at TEXT,"
        " last_modified TEXT, content_sha256 TEXT, record_count INTEGER,"
        " http_status INTEGER, is_current INTEGER)"
    )
    con.execute("CREATE TABLE sync_state (key TEXT PRIMARY KEY, value TEXT)")
    con.execute(
        "INSERT INTO sync_state (key, value) VALUES "
        "('last_successful_to_date', '2026-07-28'),"
        "('reference_data_freshness', 'fresh')"
    )
    con.execute(
        "CREATE TABLE sync_runs (run_id TEXT, mode TEXT, status TEXT, started_at TEXT)"
    )
    # EUVD-1: real product + an alias CVE NOT present in the reference mapping.
    rec1 = {
        "id": "EUVD-2024-1",
        "aliases": "CVE-2024-9999",
        "enisaIdProduct": [
            {
                "product": {"name": "RealProduct", "vendor": {"name": "RealVendor"}},
                "product_version": "1.0",
            }
        ],
    }
    # EUVD-2: placeholder "n/a" product (must be filtered out of local_products)
    # but its alias CVE must still be backfilled — the CVE path is independent
    # of the product index, so filtering placeholders loses no signal.
    rec2 = {
        "id": "EUVD-2024-2",
        "aliases": "CVE-2024-8888",
        "enisaIdProduct": [
            {
                "product": {"name": "n/a", "vendor": {"name": "n/a"}},
                "product_version": "*",
            }
        ],
    }
    con.execute(
        "INSERT INTO vulnerabilities VALUES ('EUVD-2024-1', ?, 100)",
        (json.dumps(rec1),),
    )
    con.execute(
        "INSERT INTO vulnerabilities VALUES ('EUVD-2024-2', ?, 200)",
        (json.dumps(rec2),),
    )
    # One pair already supplied by the reference mapping — must be deduped,
    # not duplicated, by the alias backfill pass.
    con.execute(
        "INSERT INTO cve_euvd_mapping VALUES ('CVE-2024-1111', 'EUVD-2024-1')"
    )
    con.commit()
    con.close()


class ProductIndexNoiseAndBackfillTests(unittest.TestCase):
    """#1a filter placeholder product names + #2 backfill CVE mapping from
    record aliases. Both run inside build_snapshot's single vulnerabilities
    pass; filtering placeholder products never drops CVE-path signal."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.source = self.dir / "mirror.sqlite3"
        self.output = self.dir / "consumer.sqlite3"
        _make_source_with_products(self.source)
        build_snapshot(self.source, self.output)

    def tearDown(self):
        self._tmp.cleanup()

    def test_placeholder_product_names_filtered(self):
        con = sqlite3.connect(self.output)
        try:
            keys = {
                str(r[0])
                for r in con.execute("SELECT product_key FROM local_products")
            }
        finally:
            con.close()
        self.assertIn("realproduct", keys)
        # "n/a" normalize_key -> "na" (non-empty), so the filter must act on
        # the raw placeholder name, not rely on the empty-key guard.
        self.assertNotIn("na", keys)

    def test_cve_mapping_backfilled_from_aliases(self):
        con = sqlite3.connect(self.output)
        try:
            pairs = {
                (str(r[0]), str(r[1]))
                for r in con.execute("SELECT cve_id, euvd_id FROM cve_euvd_mapping")
            }
        finally:
            con.close()
        # Reference-supplied pair preserved (dedup, not duplicated).
        self.assertIn(("CVE-2024-1111", "EUVD-2024-1"), pairs)
        # Aliases backfilled — including the one on the n/a-only record,
        # proving product filtering and CVE backfill are independent.
        self.assertIn(("CVE-2024-9999", "EUVD-2024-1"), pairs)
        self.assertIn(("CVE-2024-8888", "EUVD-2024-2"), pairs)


if __name__ == "__main__":
    unittest.main()
