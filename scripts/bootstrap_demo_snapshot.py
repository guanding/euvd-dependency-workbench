#!/usr/bin/env python3
"""Create a tiny synthetic EUVD consumer snapshot for local smoke testing.

The generated database is deliberately marked degraded and synthetic.  It is
not downloaded from ENISA, is not evidence of current vulnerability status,
and must never replace a snapshot produced from an approved Mirror source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any


SNAPSHOT_NAME = "euvd-readonly.sqlite3"
DEMO_CVE_ID = "CVE-2099-999999"
DEMO_EUVD_ID = "EUVD-DEMO-0001"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _demo_record() -> dict[str, Any]:
    return {
        "id": DEMO_EUVD_ID,
        "aliases": DEMO_CVE_ID,
        "description": (
            "SYNTHETIC DEMO RECORD. It is not an ENISA EUVD record and must not "
            "be used for product, CRA Article 14, conformity, or release decisions."
        ),
        "baseScore": 0.0,
        "published": "2000-01-01T00:00:00Z",
        "updated": "2000-01-01T00:00:00Z",
        "enisaIdProduct": [
            {
                "product": {
                    "name": "Synthetic Demo Component",
                    "vendor": {"name": "Example Test Vendor"},
                },
                "product_version": "1.0-demo",
            }
        ],
    }


def _write_database(path: Path) -> None:
    record = _demo_record()
    record_json = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    record_sha = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
    source_versions = [
        {
            "source_name": "synthetic-demo",
            "last_checked_at": "2000-01-01T00:00:00Z",
            "last_modified": "2000-01-01T00:00:00Z",
            "content_sha256": record_sha,
            "record_count": 1,
            "http_status": 0,
            "source_url": "synthetic-demo://local-smoke-test",
        }
    ]
    metadata = {
        "source_id": "SYNTHETIC_DEMO_NOT_EUVD",
        "snapshot_created_at": "2000-01-01T00:00:00+00:00",
        "last_successful_to_date": "not-applicable-synthetic-demo",
        "reference_data_freshness": "synthetic_demo_not_current",
        "vulnerability_count": "1",
        "mapping_count": "1",
        "known_exploited_count": "0",
        "product_index_count": "1",
        "source_db_sha256": record_sha,
        "snapshot_integrity_check_at_build": "ok",
        "consumer_boundary": (
            "SYNTHETIC DEMO ONLY; not ENISA data, not current intelligence, and "
            "not evidence for CRA Article 14, conformity, customer delivery, or release."
        ),
        "current_source_versions_json": json.dumps(source_versions, sort_keys=True),
    }

    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(
            """
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE TABLE web_snapshot_metadata(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE data_source_versions(
                source_name TEXT,
                last_checked_at TEXT,
                last_modified TEXT,
                content_sha256 TEXT,
                record_count INTEGER,
                http_status INTEGER,
                source_url TEXT,
                is_current INTEGER
            );
            CREATE TABLE cve_euvd_mapping(cve_id TEXT, euvd_id TEXT);
            CREATE TABLE known_exploited(cve_id TEXT, euvd_id TEXT, date_added TEXT);
            CREATE TABLE known_exploited_sources(cve_id TEXT, euvd_id TEXT, source TEXT);
            CREATE TABLE vulnerabilities(
                euvd_id TEXT PRIMARY KEY,
                record_json TEXT NOT NULL,
                updated_raw TEXT
            );
            CREATE TABLE local_products(
                product_key TEXT,
                vendor_key TEXT,
                euvd_id TEXT,
                product_name TEXT,
                vendor_name TEXT,
                affected_versions TEXT
            );
            CREATE INDEX idx_demo_cve ON cve_euvd_mapping(cve_id, euvd_id);
            CREATE INDEX idx_demo_product ON local_products(product_key, vendor_key);
            """
        )
        connection.executemany(
            "INSERT INTO web_snapshot_metadata(key, value) VALUES (?, ?)",
            metadata.items(),
        )
        source = source_versions[0]
        connection.execute(
            "INSERT INTO data_source_versions VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (
                source["source_name"],
                source["last_checked_at"],
                source["last_modified"],
                source["content_sha256"],
                source["record_count"],
                source["http_status"],
                source["source_url"],
            ),
        )
        connection.execute(
            "INSERT INTO cve_euvd_mapping VALUES (?, ?)",
            (DEMO_CVE_ID, DEMO_EUVD_ID),
        )
        connection.execute(
            "INSERT INTO vulnerabilities VALUES (?, ?, ?)",
            (DEMO_EUVD_ID, record_json, "2000-01-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO local_products VALUES (?, ?, ?, ?, ?, ?)",
            (
                "syntheticdemocomponent",
                "exampletestvendor",
                DEMO_EUVD_ID,
                "Synthetic Demo Component",
                "Example Test Vendor",
                "1.0-demo",
            ),
        )
        result = connection.execute("PRAGMA integrity_check").fetchone()
        if result is None or result[0] != "ok":
            raise RuntimeError(f"synthetic demo snapshot integrity check failed: {result}")
        connection.commit()
        connection.execute("VACUUM")


def build_demo_snapshot(output_dir: Path, *, force: bool = False) -> dict[str, object]:
    output_dir = output_dir.resolve()
    database_path = output_dir / SNAPSHOT_NAME
    sidecar_path = output_dir / f"{SNAPSHOT_NAME}.sha256"
    if not force and (database_path.exists() or sidecar_path.exists()):
        raise SystemExit(
            "refusing to overwrite an existing snapshot; choose an empty directory "
            "or pass --force only when replacement is intended"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    temporary_database = output_dir / f".{SNAPSHOT_NAME}.{os.getpid()}.tmp"
    temporary_sidecar = output_dir / f".{SNAPSHOT_NAME}.sha256.{os.getpid()}.tmp"
    try:
        _write_database(temporary_database)
        digest = _sha256_file(temporary_database)
        temporary_sidecar.write_text(f"{digest}  {SNAPSHOT_NAME}\n", encoding="ascii")
        os.replace(temporary_database, database_path)
        os.replace(temporary_sidecar, sidecar_path)
    finally:
        temporary_database.unlink(missing_ok=True)
        temporary_sidecar.unlink(missing_ok=True)
    return {
        "status": "created",
        "database": str(database_path),
        "sha256_file": str(sidecar_path),
        "sha256": digest,
        "source_id": "SYNTHETIC_DEMO_NOT_EUVD",
        "customer_data": False,
        "release_authority": False,
        "conformity_decision": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("data"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    result = build_demo_snapshot(args.output_dir, force=args.force)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
