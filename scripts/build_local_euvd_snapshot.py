#!/usr/bin/env python3
"""Build an atomic, read-only Web snapshot from the formal EUVD mirror.

The formal mirror remains the synchronization authority.  This script creates
an independently replaceable consumer copy and adds a normalized product index
used by the Web application.  It never modifies the source database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import time
import unicodedata
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# Consumer snapshot table allowlist. Only these tables from the formal mirror
# are retained in the read-only Web snapshot. Any other table — notably the
# independent Mirror tool's ``sbom_lookup_runs`` / ``sbom_lookup_results`` which
# may hold customer SBOM audit data — is dropped and the database VACUUMed so
# customer data cannot leak into the consumer snapshot (DEVELOPER_HANDOFF §4.3).
# New mirror tables are excluded by default; keep this list minimal and deliberate.
CONSUMER_TABLE_ALLOWLIST = frozenset(
    {
        "vulnerabilities",
        "cve_euvd_mapping",
        "known_exploited",
        "known_exploited_sources",
        "data_source_versions",
        "sync_state",
        "sync_runs",
        "local_products",          # rebuilt below
        "web_snapshot_metadata",   # rebuilt below
    }
)

# Placeholder product names that carry no identity signal — filtered out of
# the local_products index. Their CVEs still reach the matcher via the CVE-exact
# path (cve_euvd_mapping), so this loses no vulnerability signal; it only keeps
# the product-candidate path from surfacing "n/a" garbage (VALIDATION_REPORT §1:
# 40.6% of EUVD product records are placeholders).
_PLACEHOLDER_PRODUCT_NAMES = frozenset(
    {
        "",
        "n/a",
        "na",
        "n.a",
        "n.a.",
        "none",
        "null",
        "-",
        "--",
        "unknown",
        "not applicable",
        "not specified",
    }
)

# CVE identifiers extracted from record aliases for mapping backfill.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_state(path: Path) -> dict[str, Any]:
    """Return a drift-sensitive state without requiring the file to exist."""

    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"exists": False, "size": 0, "mtime_ns": 0, "ctime_ns": 0}
    return {
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
    }


def stage_sha256_sidecar(path: Path, digest: str) -> tuple[Path, Path]:
    """Prepare the external expected digest before publishing either file."""

    sidecar = Path(str(path) + ".sha256")
    temporary = sidecar.with_name(
        f".{sidecar.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    try:
        temporary.write_text(f"{digest}  {path.name}\n", encoding="ascii")
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return sidecar, temporary


def normalize_key(value: Any) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value))
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", text.casefold())


def product_rows(
    euvd_id: str,
    record_json: str,
) -> Iterator[tuple[str, str, str, str, str, str]]:
    try:
        payload = json.loads(record_json)
    except json.JSONDecodeError:
        return
    entries = payload.get("enisaIdProduct")
    if not isinstance(entries, list):
        return
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        product = entry.get("product")
        if not isinstance(product, dict):
            continue
        product_name = str(product.get("name") or "").strip()
        if product_name.casefold() in _PLACEHOLDER_PRODUCT_NAMES:
            continue
        vendor = product.get("vendor")
        vendor_name = (
            str(vendor.get("name") or "").strip()
            if isinstance(vendor, dict)
            else ""
        )
        affected_versions = str(entry.get("product_version") or "").strip()
        product_key = normalize_key(product_name)
        vendor_key = normalize_key(vendor_name)
        identity = (product_key, vendor_key, affected_versions)
        if not product_key or identity in seen:
            continue
        seen.add(identity)
        yield (
            product_key,
            vendor_key,
            euvd_id,
            product_name,
            vendor_name,
            affected_versions,
        )


def scalar(connection: sqlite3.Connection, sql: str) -> Any:
    row = connection.execute(sql).fetchone()
    return row[0] if row else None


def _build_snapshot(source: Path, output: Path, temporary: Path) -> dict[str, Any]:
    source = source.resolve()
    output = output.resolve()
    if not source.is_file():
        raise ValueError(f"source EUVD database does not exist: {source}")
    if source == output:
        raise ValueError("source and output database must be different files")

    output.parent.mkdir(parents=True, exist_ok=True)
    source_wal = Path(str(source) + "-wal")
    source_state_before = file_state(source)
    source_wal_state_before = file_state(source_wal)
    source_main_file_sha256 = sha256_file(source)
    source_wal_file_sha256 = (
        sha256_file(source_wal) if source_wal_state_before["exists"] else ""
    )

    source_uri = f"file:{source.as_posix()}?mode=ro"
    with closing(
        sqlite3.connect(source_uri, uri=True, timeout=60)
    ) as source_db, source_db:
        source_db.execute("PRAGMA query_only=ON")
        source_integrity = scalar(source_db, "PRAGMA integrity_check")
        if source_integrity != "ok":
            raise ValueError(f"source database integrity_check={source_integrity}")
        with closing(sqlite3.connect(temporary, timeout=60)) as target_db, target_db:
            source_db.backup(target_db, pages=4096, sleep=0.05)

    source_state_after = file_state(source)
    source_wal_state_after = file_state(source_wal)
    # Drift detection guards a real concurrent write during backup. The main DB
    # file is compared fully (size+mtime+ctime). The WAL sidecar is compared by
    # size only: opening a WAL-mode database read-only touches the -wal/-shm
    # files (their mtime/ctime change) but never grows them, so a read would
    # false-trip a full-state comparison on every build. A concurrent write, by
    # contrast, grows the WAL — which size comparison still catches.
    if (
        source_state_before != source_state_after
        or source_wal_state_before["size"] != source_wal_state_after["size"]
    ):
        temporary.unlink(missing_ok=True)
        raise RuntimeError(
            "source EUVD database or WAL changed while snapshot was built"
        )

    # This hash binds the transactionally consistent SQLite backup, including
    # any committed content that was present in the source WAL.  The source
    # main-file hash alone is diagnostic only and is not the logical snapshot.
    source_logical_snapshot_sha256 = sha256_file(temporary)
    inserted_products = 0
    invalid_records = 0
    with closing(sqlite3.connect(temporary, timeout=60)) as database, database:
        database.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        journal_mode = str(scalar(database, "PRAGMA journal_mode=DELETE") or "")
        if journal_mode.casefold() != "delete":
            raise ValueError(f"consumer snapshot journal_mode={journal_mode}, expected delete")
        database.execute("PRAGMA foreign_keys=ON")
        # Drop every table not on the consumer allowlist before rebuilding the
        # Web-specific tables. The SQLite backup copies the whole mirror, so
        # without this the independent Mirror tool's customer-audit tables
        # (sbom_lookup_runs / sbom_lookup_results) would ship in the consumer
        # snapshot. See DEVELOPER_HANDOFF §4.3.
        existing_tables = {
            str(row[0])
            for row in database.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        consumer_excluded_tables = sorted(
            existing_tables - CONSUMER_TABLE_ALLOWLIST
        )
        for table in consumer_excluded_tables:
            database.execute(f'DROP TABLE IF EXISTS "{table}"')
        database.execute("DROP TABLE IF EXISTS local_products")
        database.execute("DROP TABLE IF EXISTS web_snapshot_metadata")
        # Capture the reference CVE→EUVD mapping supplied by the mirror, then
        # rebuild the consumer table as a lean (cve_id, euvd_id) pair index.
        # The mirror's 5-column schema tracks sync provenance the consumer never
        # queries; the lean table shrinks the snapshot and gives CVE backfill a
        # clean PRIMARY KEY dedup target.
        existing_mapping_pairs = {
            (str(row[0]).upper(), str(row[1]).upper())
            for row in database.execute(
                "SELECT cve_id, euvd_id FROM cve_euvd_mapping"
            )
        }
        database.execute("DROP TABLE cve_euvd_mapping")
        database.execute(
            """
            CREATE TABLE cve_euvd_mapping (
                cve_id TEXT NOT NULL,
                euvd_id TEXT NOT NULL,
                PRIMARY KEY(cve_id, euvd_id)
            )
            """
        )
        mapping_pairs: set[tuple[str, str]] = set(existing_mapping_pairs)
        database.execute(
            """
            CREATE TABLE local_products (
                product_key TEXT NOT NULL,
                vendor_key TEXT NOT NULL,
                euvd_id TEXT NOT NULL,
                product_name TEXT NOT NULL,
                vendor_name TEXT NOT NULL,
                affected_versions TEXT NOT NULL,
                FOREIGN KEY(euvd_id) REFERENCES vulnerabilities(euvd_id)
            )
            """
        )

        batch: list[tuple[str, str, str, str, str, str]] = []
        for euvd_id, record_json in database.execute(
            "SELECT euvd_id, record_json FROM vulnerabilities ORDER BY euvd_id"
        ):
            euvd_id_text = str(euvd_id)
            record_text = str(record_json)
            rows = list(product_rows(euvd_id_text, record_text))
            if not rows and not record_text.lstrip().startswith("{"):
                invalid_records += 1
            batch.extend(rows)
            # CVE backfill: pull alias CVEs from the same record in the same
            # pass — independent of product filtering, so placeholder-only
            # records still feed the CVE-exact path.
            try:
                payload = json.loads(record_text)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                aliases = payload.get("aliases")
                if isinstance(aliases, list):
                    alias_text = ",".join(str(a) for a in aliases)
                else:
                    alias_text = str(aliases or "")
                for cve in CVE_PATTERN.findall(alias_text):
                    mapping_pairs.add((str(cve).upper(), euvd_id_text))
            if len(batch) >= 5000:
                database.executemany(
                    "INSERT INTO local_products VALUES (?, ?, ?, ?, ?, ?)",
                    batch,
                )
                inserted_products += len(batch)
                batch.clear()
        if batch:
            database.executemany(
                "INSERT INTO local_products VALUES (?, ?, ?, ?, ?, ?)",
                batch,
            )
            inserted_products += len(batch)
        # Re-insert reference pairs plus alias-backfilled pairs into the rebuilt
        # lean table; PRIMARY KEY dedups against the reference set. Covers the
        # ~4.68% of records whose alias CVEs never reached the reference mapping.
        database.executemany(
            "INSERT OR IGNORE INTO cve_euvd_mapping(cve_id, euvd_id) VALUES (?, ?)",
            sorted(mapping_pairs),
        )
        cve_mapping_backfill_count = len(mapping_pairs) - len(existing_mapping_pairs)

        database.execute(
            "CREATE INDEX idx_local_products_product ON local_products(product_key)"
        )
        database.execute(
            "CREATE INDEX idx_local_products_product_vendor "
            "ON local_products(product_key, vendor_key)"
        )
        database.execute(
            "CREATE INDEX idx_local_products_euvd ON local_products(euvd_id)"
        )
        database.execute(
            """
            CREATE TABLE web_snapshot_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        state = {
            key: value
            for key, value in database.execute("SELECT key, value FROM sync_state")
        }
        current_sources = [
            dict(zip(
                (
                    "source_name",
                    "source_url",
                    "last_checked_at",
                    "last_modified",
                    "content_sha256",
                    "record_count",
                    "http_status",
                ),
                row,
            ))
            for row in database.execute(
                """
                SELECT source_name, source_url, last_checked_at, last_modified,
                       content_sha256, record_count, http_status
                FROM data_source_versions
                WHERE is_current = 1
                ORDER BY source_name
                """
            )
        ]
        metadata = {
            "schema_version": "1",
            "source_id": "EUVD_LOCAL_MIRROR",
            "snapshot_created_at": utc_now(),
            "source_db_sha256": source_logical_snapshot_sha256,
            "source_logical_snapshot_sha256": source_logical_snapshot_sha256,
            "source_main_file_sha256": source_main_file_sha256,
            "source_wal_file_sha256": source_wal_file_sha256,
            "source_wal_size_bytes": str(source_wal_state_before["size"]),
            "mirror_backup_sha256_before_web_index": source_logical_snapshot_sha256,
            "source_integrity_check": source_integrity,
            "vulnerability_count": str(
                scalar(database, "SELECT COUNT(*) FROM vulnerabilities") or 0
            ),
            "mapping_count": str(
                scalar(database, "SELECT COUNT(*) FROM cve_euvd_mapping") or 0
            ),
            "known_exploited_count": str(
                scalar(database, "SELECT COUNT(*) FROM known_exploited") or 0
            ),
            "product_index_count": str(inserted_products),
            "cve_mapping_backfill_count": str(cve_mapping_backfill_count),
            "invalid_record_count": str(invalid_records),
            "last_successful_to_date": state.get("last_successful_to_date", ""),
            "reference_data_freshness": state.get(
                "reference_data_freshness", "unknown"
            ),
            "current_source_versions_json": json.dumps(
                current_sources,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            "consumer_boundary": (
                "Read-only Web consumer snapshot; not the synchronization authority"
            ),
            "consumer_table_allowlist": ",".join(sorted(CONSUMER_TABLE_ALLOWLIST)),
            "consumer_excluded_tables": ",".join(consumer_excluded_tables),
        }
        database.executemany(
            "INSERT INTO web_snapshot_metadata(key, value) VALUES (?, ?)",
            metadata.items(),
        )
        database.execute("ANALYZE")
        database.commit()
        snapshot_integrity = scalar(database, "PRAGMA integrity_check")
        if snapshot_integrity != "ok":
            raise ValueError(f"snapshot database integrity_check={snapshot_integrity}")
        database.execute(
            "INSERT INTO web_snapshot_metadata(key, value) VALUES (?, ?)",
            ("snapshot_integrity_check_at_build", snapshot_integrity),
        )
        database.commit()
        if scalar(database, "PRAGMA quick_check") != "ok":
            raise ValueError("snapshot database quick_check failed after metadata seal")
        # Physically purge pages of the dropped non-allowlist tables so customer
        # audit data cannot linger in free pages of the snapshot file. DROP alone
        # does not shrink the file; VACUUM rewrites it without the freed pages.
        database.commit()
        database.execute("VACUUM")
        if scalar(database, "PRAGMA integrity_check") != "ok":
            raise ValueError("snapshot integrity_check failed after VACUUM")

    unexpected_sidecars = [
        str(Path(str(temporary) + suffix))
        for suffix in ("-wal", "-shm")
        if Path(str(temporary) + suffix).exists()
    ]
    if unexpected_sidecars:
        raise ValueError(
            "standalone consumer snapshot still has SQLite sidecars: "
            + ", ".join(unexpected_sidecars)
        )
    snapshot_sha256 = sha256_file(temporary)
    expected_sha256_file, staged_sidecar = stage_sha256_sidecar(
        output, snapshot_sha256
    )
    rollback_output = output.with_name(
        f".{output.name}.{os.getpid()}.{time.time_ns()}.rollback"
    )
    rollback_sidecar = expected_sha256_file.with_name(
        f".{expected_sha256_file.name}.{os.getpid()}.{time.time_ns()}.rollback"
    )
    had_output = output.is_file()
    had_sidecar = expected_sha256_file.is_file()
    try:
        if had_output:
            os.link(output, rollback_output)
        if had_sidecar:
            os.link(expected_sha256_file, rollback_sidecar)
        os.replace(temporary, output)
        os.replace(staged_sidecar, expected_sha256_file)
    except BaseException:
        if had_output and rollback_output.exists():
            os.replace(rollback_output, output)
        elif not had_output:
            output.unlink(missing_ok=True)
        if had_sidecar and rollback_sidecar.exists():
            os.replace(rollback_sidecar, expected_sha256_file)
        elif not had_sidecar:
            expected_sha256_file.unlink(missing_ok=True)
        raise
    finally:
        staged_sidecar.unlink(missing_ok=True)
        rollback_output.unlink(missing_ok=True)
        rollback_sidecar.unlink(missing_ok=True)
    return {
        "status": "completed",
        "source_id": "EUVD_LOCAL_MIRROR",
        "output": str(output),
        "snapshot_created_at": metadata["snapshot_created_at"],
        "source_db_sha256": source_logical_snapshot_sha256,
        "source_logical_snapshot_sha256": source_logical_snapshot_sha256,
        "source_main_file_sha256": source_main_file_sha256,
        "source_wal_file_sha256": source_wal_file_sha256,
        "source_wal_size_bytes": source_wal_state_before["size"],
        "snapshot_sha256": snapshot_sha256,
        "expected_sha256_file": str(expected_sha256_file),
        "source_integrity_check": source_integrity,
        "snapshot_integrity_check": snapshot_integrity,
        "vulnerability_count": int(metadata["vulnerability_count"]),
        "mapping_count": int(metadata["mapping_count"]),
        "known_exploited_count": int(metadata["known_exploited_count"]),
        "product_index_count": inserted_products,
        "last_successful_to_date": metadata["last_successful_to_date"],
        "reference_data_freshness": metadata["reference_data_freshness"],
        "important_boundary": metadata["consumer_boundary"],
        "consumer_excluded_tables": metadata["consumer_excluded_tables"],
    }


def build_snapshot(source: Path, output: Path) -> dict[str, Any]:
    """Build a consumer snapshot and remove all temporary files on failure."""

    resolved_output = output.resolve()
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved_output.with_name(
        f".{resolved_output.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    try:
        return _build_snapshot(source, resolved_output, temporary)
    finally:
        for candidate in (
            temporary,
            Path(str(temporary) + "-wal"),
            Path(str(temporary) + "-shm"),
        ):
            candidate.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--output-json", type=Path)
    args = parser.parse_args()
    result = build_snapshot(args.source, args.output)
    serialized = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
