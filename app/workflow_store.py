from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from .vex_draft import suggest_applicability
from pathlib import Path
from typing import Any, Iterator


CASE_STATUSES = {
    "draft",
    "technical_review",
    "compliance_review",
    "approved",
    "submitted",
    "closed",
}
APPLICABILITY_STATUSES = {
    "under_investigation",
    "known_affected",
    "known_not_affected",
    "fixed",
}
EXPLOITATION_EVIDENCE_STATUSES = {
    "not_assessed",
    "reliable_evidence",
    "insufficient",
    "no_evidence_found",
}
ART14_DECISIONS = {
    "not_assessed",
    "reportable",
    "not_reportable",
    "needs_more_information",
}
EVIDENCE_EXPLOITATION_VALUES = {"unknown", "yes", "no"}
VEX_SOURCES = {"cyclonedx-1.7", "csaf-2.0"}
CASE_TYPES = {"actively_exploited_vulnerability", "severe_incident"}
SEVERE_INCIDENT_CRITERIA_KEYS = {
    "availability_authenticity_integrity_confidentiality_impact",
    "malicious_code_introduction",
    "rationale",
}
SRP_FIELD_KEYS = {
    "reporter",
    "manufacturer_name",
    "manufacturer_contact",
    "title",
    "product_type",
    "product_category",
    "member_states_where_available",
    "csirt_coordinator",
    "user_notification",
    "sensitivity",
    "general_information",
    "vulnerability_nature",
    "exploit_nature",
    "corrective_measures_taken",
    "user_measures",
    "full_vulnerability_description",
    "vulnerability_severity",
    "vulnerability_impact",
    "malicious_actor",
    "security_update_details",
    "remediation_monitoring",
    "incident_suspected_unlawful_or_malicious",
    "incident_general_nature",
    "incident_detected_at",
    "incident_occurred_at",
    "incident_initial_assessment",
    "incident_corrective_measures_taken",
    "incident_user_measures",
    "incident_detailed_description",
    "incident_severity",
    "incident_impact",
    "incident_likely_threat_or_root_cause",
    "incident_applied_and_ongoing_mitigation_measures",
}
VULNERABILITY_SRP_FIELD_KEYS = {
    "general_information",
    "vulnerability_nature",
    "exploit_nature",
    "corrective_measures_taken",
    "user_measures",
    "full_vulnerability_description",
    "vulnerability_severity",
    "vulnerability_impact",
    "malicious_actor",
    "security_update_details",
    "remediation_monitoring",
}
INCIDENT_SRP_FIELD_KEYS = {
    key for key in SRP_FIELD_KEYS if key.startswith("incident_")
}
INCIDENT_SRP_DATE_TIME_FIELDS = {"incident_detected_at", "incident_occurred_at"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _normalize_identity(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def _match_cve(finding: dict[str, Any]) -> str:
    values = [
        finding.get("source_identifier"),
        finding.get("alternative_ids"),
        finding.get("description"),
    ]
    for value in values:
        match = re.search(r"\bCVE-\d{4}-\d{4,}\b", str(value or ""), re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return ""


class WorkflowStore:
    """Durable Art.14/VEX case store.

    Scanner jobs remain readable in their v2.1 JSON form. v2.2 copies their stable
    product/SBOM identities into SQLite when a case or snapshot is created, so
    existing installations migrate without rewriting customer source artifacts.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sbom_snapshots (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL UNIQUE,
                    product_name TEXT NOT NULL,
                    product_version TEXT NOT NULL DEFAULT '',
                    software_build TEXT NOT NULL DEFAULT '',
                    customer TEXT NOT NULL DEFAULT '',
                    source_file TEXT NOT NULL DEFAULT '',
                    source_sha256 TEXT NOT NULL DEFAULT '',
                    sbom_format TEXT NOT NULL DEFAULT '',
                    sbom_version TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    job_id TEXT,
                    finding_index INTEGER,
                    source_key TEXT NOT NULL UNIQUE,
                    case_type TEXT NOT NULL DEFAULT 'actively_exploited_vulnerability',
                    project_name TEXT NOT NULL,
                    project_version TEXT NOT NULL DEFAULT '',
                    software_build TEXT NOT NULL DEFAULT '',
                    customer TEXT NOT NULL DEFAULT '',
                    sbom_snapshot_id TEXT,
                    sbom_sha256 TEXT NOT NULL DEFAULT '',
                    component_name TEXT NOT NULL DEFAULT '',
                    component_version TEXT NOT NULL DEFAULT '',
                    cve_id TEXT NOT NULL DEFAULT '',
                    euvd_id TEXT NOT NULL DEFAULT '',
                    public_exploitation_status TEXT NOT NULL DEFAULT '',
                    public_evidence_checked_at TEXT NOT NULL DEFAULT '',
                    public_evidence_sha256 TEXT NOT NULL DEFAULT '',
                    applicability_status TEXT NOT NULL DEFAULT 'under_investigation',
                    applicability_justification TEXT NOT NULL DEFAULT '',
                    exploitation_evidence_status TEXT NOT NULL DEFAULT 'not_assessed',
                    exploitation_evidence_summary TEXT NOT NULL DEFAULT '',
                    product_risk_summary TEXT NOT NULL DEFAULT '',
                    mitigation_summary TEXT NOT NULL DEFAULT '',
                    art14_decision TEXT NOT NULL DEFAULT 'not_assessed',
                    decision_rationale TEXT NOT NULL DEFAULT '',
                    workflow_status TEXT NOT NULL DEFAULT 'draft',
                    reporting_stage TEXT NOT NULL DEFAULT 'not_started',
                    external_signal_at TEXT,
                    initial_assessment_completed_at TEXT,
                    awareness_at TEXT,
                    awareness_confirmed_by TEXT NOT NULL DEFAULT '',
                    awareness_confirmed_at TEXT,
                    awareness_basis TEXT NOT NULL DEFAULT '',
                    awareness_evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    corrective_measure_available_at TEXT,
                    next_review_at TEXT,
                    technical_reviewer TEXT NOT NULL DEFAULT '',
                    technical_reviewed_at TEXT,
                    technical_decision TEXT NOT NULL DEFAULT '',
                    technical_rationale TEXT NOT NULL DEFAULT '',
                    compliance_reviewer TEXT NOT NULL DEFAULT '',
                    compliance_reviewed_at TEXT,
                    compliance_decision TEXT NOT NULL DEFAULT '',
                    compliance_rationale TEXT NOT NULL DEFAULT '',
                    approved_at TEXT,
                    submitted_at TEXT,
                    submission_receipt TEXT NOT NULL DEFAULT '',
                    srp_fields_json TEXT NOT NULL DEFAULT '{}',
                    severe_incident_criteria_json TEXT NOT NULL DEFAULT '{}',
                    vex_source TEXT NOT NULL DEFAULT '',
                    vex_document_id TEXT NOT NULL DEFAULT '',
                    stale_reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(sbom_snapshot_id) REFERENCES sbom_snapshots(id)
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_ref TEXT NOT NULL DEFAULT '',
                    source_url TEXT NOT NULL DEFAULT '',
                    published_at TEXT,
                    retrieved_at TEXT NOT NULL,
                    sha256 TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL,
                    product_relevance TEXT NOT NULL DEFAULT '',
                    reliable_malicious_exploitation TEXT NOT NULL DEFAULT 'unknown',
                    malicious_actor_confirmed INTEGER NOT NULL DEFAULT 0,
                    without_permission_confirmed INTEGER NOT NULL DEFAULT 0,
                    actual_exploitation_confirmed INTEGER NOT NULL DEFAULT 0,
                    recorded_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS reviewers (
                    id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    pin_salt TEXT NOT NULL,
                    pin_hash TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS submission_receipts (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    receipt TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(case_id, stage),
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    prev_hash TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vex_imports (
                    id TEXT PRIMARY KEY,
                    format TEXT NOT NULL,
                    document_id TEXT NOT NULL DEFAULT '',
                    source_name TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    imported_by TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    warnings_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS feed_snapshots (
                    feed_name TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    retrieved_at TEXT,
                    sha256 TEXT NOT NULL DEFAULT '',
                    record_count INTEGER,
                    detail TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(workflow_status);
                CREATE INDEX IF NOT EXISTS idx_cases_cve ON cases(cve_id);
                CREATE INDEX IF NOT EXISTS idx_cases_euvd ON cases(euvd_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id);
                """
            )
            # Migration: existing databases predate the audit hash-chain column.
            self._ensure_column(
                connection, "audit_events", "prev_hash", "TEXT NOT NULL DEFAULT ''"
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)",
                (utc_now(),),
            )
            case_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(cases)").fetchall()
            }
            if "initial_assessment_completed_at" not in case_columns:
                connection.execute(
                    "ALTER TABLE cases ADD COLUMN initial_assessment_completed_at TEXT"
                )
            for column, declaration in {
                "reporting_stage": "TEXT NOT NULL DEFAULT 'not_started'",
                "awareness_basis": "TEXT NOT NULL DEFAULT ''",
                "awareness_evidence_refs_json": "TEXT NOT NULL DEFAULT '[]'",
                "case_type": (
                    "TEXT NOT NULL DEFAULT 'actively_exploited_vulnerability'"
                ),
                "severe_incident_criteria_json": "TEXT NOT NULL DEFAULT '{}'",
            }.items():
                if column not in case_columns:
                    connection.execute(
                        f"ALTER TABLE cases ADD COLUMN {column} {declaration}"
                    )
            evidence_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(evidence)").fetchall()
            }
            for column in (
                "malicious_actor_confirmed",
                "without_permission_confirmed",
                "actual_exploitation_confirmed",
            ):
                if column not in evidence_columns:
                    connection.execute(
                        f"ALTER TABLE evidence ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"
                    )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(3, ?)",
                (utc_now(),),
            )

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        """Add a column if missing (idempotent migration for existing DBs)."""
        existing = {
            str(row[1])
            for row in connection.execute(f"PRAGMA table_info({table})")
        }
        if column not in existing:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
            )

    def _audit(
        self,
        connection: sqlite3.Connection,
        case_id: str | None,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> None:
        serialized = _json(payload)
        # Hash chain: each event's digest binds the previous event's digest (by
        # insertion order, across all cases), so a deleted/reordered/tampered
        # audit row breaks end-to-end verification.
        previous = connection.execute(
            "SELECT payload_sha256 FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = str(previous["payload_sha256"]) if previous else ""
        digest = hashlib.sha256(
            f"{prev_hash}:{serialized}".encode("utf-8")
        ).hexdigest()
        connection.execute(
            """
            INSERT INTO audit_events(
                case_id, event_type, actor, payload_json, payload_sha256,
                prev_hash, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                event_type,
                actor.strip() or "system",
                serialized,
                digest,
                prev_hash,
                utc_now(),
            ),
        )


    def verify_audit_chain(self) -> dict[str, Any]:
        """Recompute the GLOBAL audit_events hash chain end-to-end (the same
        algorithm _audit uses) and report the first break.

        Returns {verified, broken_at, event_count, verified_at}. A deleted,
        reordered, or tampered row breaks the chain at broken_at (its id).
        Production counterpart of the chain check that lived only in tests.
        """
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, payload_json, payload_sha256 "
                "FROM audit_events ORDER BY id ASC"
            ).fetchall()
        previous = ""
        for row in rows:
            expected = hashlib.sha256(
                f"{previous}:{row['payload_json']}".encode("utf-8")
            ).hexdigest()
            if row["payload_sha256"] != expected:
                return {
                    "verified": False,
                    "broken_at": int(row["id"]),
                    "event_count": len(rows),
                    "verified_at": utc_now(),
                }
            previous = row["payload_sha256"]
        return {
            "verified": True,
            "broken_at": None,
            "event_count": len(rows),
            "verified_at": utc_now(),
        }

    def export_audit_trail(self, job_id: str | None = None) -> list[dict[str, Any]]:
        """Return audit_events in id ASC (chain order) with all 8 columns.

        When job_id is given, filter to that job's cases (in-scope); otherwise
        the full table. NOTE: prev_hash is GLOBAL — an in-scope first row may
        reference an out-of-scope event; verify_audit_chain checks the whole
        chain and the evidence bundle documents this scoping.
        """
        sql = (
            "SELECT id, case_id, event_type, actor, payload_json, "
            "payload_sha256, prev_hash, created_at FROM audit_events"
        )
        params: tuple[Any, ...] = ()
        if job_id is not None:
            sql += " WHERE case_id IN (SELECT id FROM cases WHERE job_id = ?)"
            params = (job_id,)
        sql += " ORDER BY id ASC"
        with self.connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _pin_hash(pin: str, salt: bytes) -> str:
        return hashlib.scrypt(
            pin.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        ).hex()

    def create_reviewer(self, display_name: str, role: str, pin: str) -> dict[str, Any]:
        display_name = display_name.strip()
        role = role.strip()
        if len(display_name) < 2:
            raise ValueError("审批人姓名至少需要 2 个字符")
        if role not in {"technical", "compliance", "manufacturer_authorized"}:
            raise ValueError("审批人角色无效")
        if len(pin) < 8:
            raise ValueError("本地审批 PIN 至少需要 8 个字符")
        reviewer_id = str(uuid.uuid4())
        salt = os.urandom(16)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO reviewers(
                    id, display_name, role, pin_salt, pin_hash, active, created_at
                ) VALUES(?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    reviewer_id,
                    display_name,
                    role,
                    salt.hex(),
                    self._pin_hash(pin, salt),
                    utc_now(),
                ),
            )
            self._audit(
                connection,
                None,
                "reviewer_profile_created",
                display_name,
                {"reviewer_id": reviewer_id, "role": role},
            )
        return {"id": reviewer_id, "display_name": display_name, "role": role}

    def list_reviewers(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, display_name, role, active, created_at
                FROM reviewers WHERE active = 1 ORDER BY display_name
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_reviewer(
        self,
        reviewer_id: str,
        pin: str,
        allowed_roles: set[str] | None = None,
    ) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM reviewers WHERE id = ? AND active = 1",
                (reviewer_id,),
            ).fetchone()
        if row is None:
            raise ValueError("审批人不存在或已停用")
        if allowed_roles and row["role"] not in allowed_roles:
            raise ValueError("审批人角色不允许执行该操作")
        expected = self._pin_hash(pin, bytes.fromhex(row["pin_salt"]))
        if not hmac.compare_digest(expected, row["pin_hash"]):
            raise ValueError("审批 PIN 错误")
        return {
            "id": row["id"],
            "display_name": row["display_name"],
            "role": row["role"],
        }

    @staticmethod
    def _case_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["srp_fields"] = json.loads(item.pop("srp_fields_json") or "{}")
        item["severe_incident_criteria"] = json.loads(
            item.pop("severe_incident_criteria_json") or "{}"
        )
        item["awareness_evidence_refs"] = json.loads(
            item.pop("awareness_evidence_refs_json") or "[]"
        )
        return item

    def register_sbom_snapshot(
        self,
        job: dict[str, Any],
        source_sha256: str = "",
        sbom_format: str = "",
        sbom_version: str = "",
    ) -> str:
        job_id = str(job["id"])
        snapshot_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"euvd-sbom:{job_id}"))
        source_sha256 = source_sha256 or str(job.get("source_sha256") or "")
        product_name = str(job.get("project_name") or job.get("file_name") or "SBOM")
        product_version = str(job.get("project_version") or "")
        software_build = str(job.get("software_build") or "")
        customer = str(job.get("customer") or "")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO sbom_snapshots(
                    id, job_id, product_name, product_version, software_build,
                    customer, source_file, source_sha256, sbom_format, sbom_version,
                    created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    product_name=excluded.product_name,
                    product_version=excluded.product_version,
                    software_build=excluded.software_build,
                    customer=excluded.customer,
                    source_file=excluded.source_file,
                    source_sha256=excluded.source_sha256,
                    sbom_format=excluded.sbom_format,
                    sbom_version=excluded.sbom_version
                """,
                (
                    snapshot_id,
                    job_id,
                    product_name,
                    product_version,
                    software_build,
                    customer,
                    str(job.get("file_name") or ""),
                    source_sha256,
                    sbom_format,
                    sbom_version,
                    utc_now(),
                ),
            )
            # Version, build, or SBOM population/hash changes invalidate open decisions.
            connection.execute(
                """
                UPDATE cases
                SET stale_reason = ?, workflow_status = 'draft',
                    reporting_stage = 'reopened', art14_decision = 'not_assessed',
                    technical_reviewer = '', technical_reviewed_at = NULL,
                    technical_decision = '', technical_rationale = '',
                    compliance_reviewer = '', compliance_reviewed_at = NULL,
                    compliance_decision = '', compliance_rationale = '',
                    approved_at = NULL, updated_at = ?
                WHERE project_name = ? AND customer = ? AND sbom_snapshot_id <> ?
                  AND workflow_status NOT IN ('submitted', 'closed')
                  AND stale_reason = ''
                  AND EXISTS (
                    SELECT 1 FROM sbom_snapshots previous
                    WHERE previous.id = cases.sbom_snapshot_id
                      AND (
                        previous.product_version <> ?
                        OR previous.software_build <> ?
                        OR previous.source_sha256 <> ?
                      )
                  )
                """,
                (
                    "产品版本、build 或 SBOM hash/总体发生变化；适用性、VEX 和未提交审批已重开",
                    utc_now(),
                    product_name,
                    customer,
                    snapshot_id,
                    product_version,
                    software_build,
                    source_sha256,
                ),
            )
        return snapshot_id

    def create_case_from_finding(
        self,
        job: dict[str, Any],
        finding_index: int,
        actor: str,
    ) -> dict[str, Any]:
        matches = list((job.get("result") or {}).get("matches") or [])
        if finding_index < 0 or finding_index >= len(matches):
            raise ValueError("漏洞记录索引无效")
        finding = matches[finding_index]
        source_key = f"job:{job['id']}:finding:{finding_index}"
        case_id = str(uuid.uuid5(uuid.NAMESPACE_URL, source_key))
        snapshot_id = self.register_sbom_snapshot(job)
        now = utc_now()
        suggested_status, suggested_justification = suggest_applicability(finding)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO cases(
                    id, job_id, finding_index, source_key, project_name,
                    project_version, software_build, customer, sbom_snapshot_id,
                    sbom_sha256, component_name, component_version, cve_id, euvd_id,
                    public_exploitation_status, public_evidence_checked_at,
                    public_evidence_sha256, external_signal_at,
                    applicability_status, applicability_justification,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    job["id"],
                    finding_index,
                    source_key,
                    str(job.get("project_name") or job.get("file_name") or "SBOM"),
                    str(job.get("project_version") or ""),
                    str(job.get("software_build") or ""),
                    str(job.get("customer") or ""),
                    snapshot_id,
                    str(job.get("source_sha256") or ""),
                    str(finding.get("component_name") or ""),
                    str(finding.get("component_version") or ""),
                    _match_cve(finding),
                    str(finding.get("euvd_id") or ""),
                    str(finding.get("exploitation_status") or ""),
                    str(finding.get("evidence_checked_at") or ""),
                    str(finding.get("kev_snapshot_sha256") or ""),
                    str(finding.get("kev_date_added") or "") or None,
                    suggested_status,
                    suggested_justification,
                    now,
                    now,
                ),
            )
            self._audit(
                connection,
                case_id,
                "case_created_from_finding",
                actor,
                {
                    "job_id": job["id"],
                    "finding_index": finding_index,
                    "public_signal_is_not_art14_decision": True,
                },
            )
        return self.get_case(case_id)

    def create_case_from_vex(
        self,
        entry: dict[str, Any],
        vex_import_id: str,
        actor: str,
    ) -> dict[str, Any]:
        source_key = (
            f"vex:{vex_import_id}:{entry.get('vulnerability_id')}:{entry.get('product_id')}"
        )
        case_id = str(uuid.uuid5(uuid.NAMESPACE_URL, source_key))
        status = str(entry.get("status") or "under_investigation")
        if status not in APPLICABILITY_STATUSES:
            status = "under_investigation"
        justification = str(entry.get("justification") or entry.get("detail") or "").strip()
        if status == "known_not_affected" and not justification:
            status = "under_investigation"
            justification = (
                "导入 VEX 的 known_not_affected 缺少产品级理由，已降级为 under_investigation"
            )
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO cases(
                    id, source_key, project_name, project_version, component_name,
                    component_version, cve_id, euvd_id, applicability_status,
                    applicability_justification, vex_source, vex_document_id,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    source_key,
                    str(entry.get("product_name") or entry.get("product_id") or "VEX产品"),
                    str(entry.get("product_version") or ""),
                    str(entry.get("component_name") or ""),
                    str(entry.get("component_version") or ""),
                    str(entry.get("cve_id") or ""),
                    str(entry.get("euvd_id") or ""),
                    status,
                    justification,
                    str(entry.get("format") or ""),
                    vex_import_id,
                    now,
                    now,
                ),
            )
            self._audit(
                connection,
                case_id,
                "vex_entry_imported",
                actor,
                {"vex_import_id": vex_import_id, "status": status},
            )
        return self.get_case(case_id)

    def create_manual_case(
        self,
        payload: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        project_name = str(payload.get("project_name") or "").strip()
        if not project_name:
            raise ValueError("产品名称不能为空")
        case_type = str(
            payload.get("case_type") or "actively_exploited_vulnerability"
        )
        if case_type not in CASE_TYPES:
            raise ValueError("Art.14 案件类型无效")
        case_id = str(uuid.uuid4())
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO cases(
                    id, source_key, case_type, project_name, project_version, software_build,
                    customer, component_name, component_version, cve_id, euvd_id,
                    public_exploitation_status, exploitation_evidence_summary,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    f"manual:{case_id}",
                    case_type,
                    project_name,
                    str(payload.get("project_version") or ""),
                    str(payload.get("software_build") or ""),
                    str(payload.get("customer") or ""),
                    str(payload.get("component_name") or ""),
                    str(payload.get("component_version") or ""),
                    str(payload.get("cve_id") or "").upper(),
                    str(payload.get("euvd_id") or "").upper(),
                    str(payload.get("public_exploitation_status") or "manual_signal"),
                    str(payload.get("vulnerability_summary") or ""),
                    now,
                    now,
                ),
            )
            self._audit(
                connection,
                case_id,
                "manual_case_created",
                actor,
                {
                    "case_type": case_type,
                    "zero_day_without_public_id_supported": not bool(
                        payload.get("cve_id") or payload.get("euvd_id")
                    ),
                    "automatic_art14_decision": False,
                },
            )
        return self.get_case(case_id)

    def list_cases(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM cases ORDER BY updated_at DESC, created_at DESC"
            ).fetchall()
        return [self._case_dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise KeyError(case_id)
            evidence = [
                dict(item)
                for item in connection.execute(
                    "SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at DESC",
                    (case_id,),
                ).fetchall()
            ]
            approvals = [
                dict(item)
                for item in connection.execute(
                    "SELECT * FROM approvals WHERE case_id = ? ORDER BY created_at",
                    (case_id,),
                ).fetchall()
            ]
            submissions = [
                dict(item)
                for item in connection.execute(
                    """
                    SELECT * FROM submission_receipts
                    WHERE case_id = ? ORDER BY submitted_at
                    """,
                    (case_id,),
                ).fetchall()
            ]
            audits = [
                dict(item)
                for item in connection.execute(
                    """
                    SELECT event_type, actor, payload_sha256, created_at
                    FROM audit_events WHERE case_id = ? ORDER BY id DESC LIMIT 100
                    """,
                    (case_id,),
                ).fetchall()
            ]
        case = self._case_dict(row)
        case["evidence"] = evidence
        case["approvals"] = approvals
        case["submission_receipts"] = submissions
        case["audit_events"] = audits
        return case

    def update_case(
        self,
        case_id: str,
        updates: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        allowed = {
            "project_name",
            "project_version",
            "software_build",
            "customer",
            "component_name",
            "component_version",
            "cve_id",
            "euvd_id",
            "applicability_status",
            "applicability_justification",
            "exploitation_evidence_status",
            "exploitation_evidence_summary",
            "product_risk_summary",
            "mitigation_summary",
            "initial_assessment_completed_at",
            "corrective_measure_available_at",
            "next_review_at",
            "srp_fields",
            "severe_incident_criteria",
        }
        clean = {key: value for key, value in updates.items() if key in allowed}
        if not clean:
            raise ValueError("没有可更新字段")
        if (
            "applicability_status" in clean
            and clean["applicability_status"] not in APPLICABILITY_STATUSES
        ):
            raise ValueError("产品适用性状态无效")
        if (
            "exploitation_evidence_status" in clean
            and clean["exploitation_evidence_status"]
            not in EXPLOITATION_EVIDENCE_STATUSES
        ):
            raise ValueError("积极利用证据状态无效")
        if clean.get("applicability_status") == "known_not_affected" and not str(
            clean.get("applicability_justification") or ""
        ).strip():
            existing = self.get_case(case_id)
            if not existing.get("applicability_justification"):
                raise ValueError("known_not_affected 必须填写技术理由")
        if "severe_incident_criteria" in clean:
            criteria = clean["severe_incident_criteria"]
            if not isinstance(criteria, dict):
                raise ValueError("严重事件准则必须是对象")
            unknown = set(criteria) - SEVERE_INCIDENT_CRITERIA_KEYS
            if unknown:
                raise ValueError(
                    "严重事件准则包含未知字段: " + ", ".join(sorted(unknown))
                )
            for key in (
                "availability_authenticity_integrity_confidentiality_impact",
                "malicious_code_introduction",
            ):
                if key in criteria and not isinstance(criteria[key], bool):
                    raise ValueError(f"严重事件准则 {key} 必须是布尔值")
            criteria_rationale = str(criteria.get("rationale") or "").strip()
            if len(criteria_rationale) > 8_000:
                raise ValueError("严重事件准则理由超过 8000 字符")
            clean["severe_incident_criteria"] = {
                "availability_authenticity_integrity_confidentiality_impact": bool(
                    criteria.get(
                        "availability_authenticity_integrity_confidentiality_impact"
                    )
                ),
                "malicious_code_introduction": bool(
                    criteria.get("malicious_code_introduction")
                ),
                "rationale": criteria_rationale,
            }
        if "srp_fields" in clean:
            fields = clean["srp_fields"]
            if not isinstance(fields, dict):
                raise ValueError("SRP 字段必须是对象")
            unknown = set(fields) - SRP_FIELD_KEYS
            if unknown:
                raise ValueError("SRP 字段包含未知字段: " + ", ".join(sorted(unknown)))
            current_case = self.get_case(case_id)
            inappropriate = set(fields) & (
                VULNERABILITY_SRP_FIELD_KEYS
                if current_case.get("case_type") == "severe_incident"
                else INCIDENT_SRP_FIELD_KEYS
            )
            if inappropriate:
                raise ValueError(
                    "SRP 字段不适用于当前案件类型: "
                    + ", ".join(sorted(inappropriate))
                )
            normalized_fields: dict[str, str] = {}
            for key, value in fields.items():
                if value is None:
                    normalized_fields[key] = ""
                    continue
                if not isinstance(value, str):
                    raise ValueError(f"SRP 字段 {key} 必须是文本")
                if len(value) > 16_000:
                    raise ValueError(f"SRP 字段 {key} 超过 16000 字符")
                normalized = value.strip()
                if key == "incident_suspected_unlawful_or_malicious" and normalized:
                    normalized = normalized.casefold()
                    if normalized not in {"yes", "no", "unknown"}:
                        raise ValueError(
                            "SRP 事件非法/恶意原因必须是 yes、no 或 unknown"
                        )
                if key == "product_type" and normalized:
                    product_types = {
                        "default": "Default",
                        "important": "Important",
                        "critical": "Critical",
                    }
                    if normalized.casefold() not in product_types:
                        raise ValueError(
                            "SRP 产品类型必须是 Default、Important 或 Critical"
                        )
                    normalized = product_types[normalized.casefold()]
                if key in INCIDENT_SRP_DATE_TIME_FIELDS and normalized:
                    try:
                        parsed = datetime.fromisoformat(
                            normalized.replace("Z", "+00:00")
                        )
                    except ValueError as exc:
                        raise ValueError(f"SRP 字段 {key} 必须是 ISO 8601 日期时间") from exc
                    if parsed.tzinfo is None:
                        raise ValueError(f"SRP 字段 {key} 必须包含时区")
                    parsed_utc = parsed.astimezone(timezone.utc)
                    if parsed_utc > datetime.now(timezone.utc):
                        raise ValueError(f"SRP 字段 {key} 不能在未来")
                    normalized = parsed_utc.isoformat(timespec="seconds")
                normalized_fields[key] = normalized
            if all(
                normalized_fields.get(key) for key in INCIDENT_SRP_DATE_TIME_FIELDS
            ):
                occurred_at = datetime.fromisoformat(
                    normalized_fields["incident_occurred_at"]
                )
                detected_at = datetime.fromisoformat(
                    normalized_fields["incident_detected_at"]
                )
                if occurred_at > detected_at:
                    raise ValueError("SRP 事件发生时间不能晚于检测时间")
            clean["srp_fields"] = normalized_fields
        for field in (
            "initial_assessment_completed_at",
            "corrective_measure_available_at",
            "next_review_at",
        ):
            if clean.get(field):
                parsed = datetime.fromisoformat(str(clean[field]).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError(f"{field} 必须包含时区")
                if field != "next_review_at" and parsed.astimezone(
                    timezone.utc
                ) > datetime.now(timezone.utc):
                    raise ValueError(f"{field} 不能在未来")
                clean[field] = parsed.astimezone(timezone.utc).isoformat(
                    timespec="seconds"
                )

        columns: list[str] = []
        values: list[Any] = []
        for key, value in clean.items():
            column = {
                "srp_fields": "srp_fields_json",
                "severe_incident_criteria": "severe_incident_criteria_json",
            }.get(key, key)
            columns.append(f"{column} = ?")
            values.append(
                _json(value)
                if key in {"srp_fields", "severe_incident_criteria"}
                else value
            )
        columns.append("updated_at = ?")
        values.append(utc_now())
        values.append(case_id)

        critical = {
            "project_version",
            "software_build",
            "component_version",
            "applicability_status",
            "applicability_justification",
            "exploitation_evidence_status",
            "exploitation_evidence_summary",
            "product_risk_summary",
            "mitigation_summary",
            "initial_assessment_completed_at",
            "corrective_measure_available_at",
            "severe_incident_criteria",
            "srp_fields",
        }
        with self.connect() as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone() is None:
                raise KeyError(case_id)
            connection.execute(
                f"UPDATE cases SET {', '.join(columns)} WHERE id = ?", values
            )
            if critical.intersection(clean):
                connection.execute(
                    """
                    UPDATE cases SET workflow_status='draft',
                        art14_decision='not_assessed',
                        technical_reviewer='', technical_reviewed_at=NULL,
                        technical_decision='', technical_rationale='',
                        compliance_reviewer='', compliance_reviewed_at=NULL,
                        compliance_decision='', compliance_rationale='',
                        approved_at=NULL, submitted_at=NULL, submission_receipt=''
                    WHERE id = ?
                    """,
                    (case_id,),
                )
            self._audit(connection, case_id, "case_updated", actor, clean)
        return self.get_case(case_id)

    def confirm_awareness(
        self,
        case_id: str,
        awareness_at: str,
        actor: str,
        confirmation: bool,
        basis: str,
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        if not confirmation:
            raise ValueError("必须明确确认该时间是制造商 awareness 时间")
        parsed = datetime.fromisoformat(awareness_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("awareness 时间必须包含时区")
        parsed_utc = parsed.astimezone(timezone.utc)
        if parsed_utc > datetime.now(timezone.utc):
            raise ValueError("awareness 时间不能在未来")
        normalized = parsed_utc.isoformat(timespec="seconds")
        basis = basis.strip()
        if not basis:
            raise ValueError("必须记录达到合理确定程度的 awareness 依据")
        if not evidence_refs:
            raise ValueError("awareness 必须绑定至少一条案件证据")
        case = self.get_case(case_id)
        if case.get("workflow_status") in {"approved", "submitted", "closed"}:
            raise ValueError(
                f"案件已{case['workflow_status']}，awareness 不可重新确认；如需修正请先重开案件"
            )
        if not case.get("initial_assessment_completed_at"):
            raise ValueError("必须先记录初步评估完成时间")
        with self.connect() as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone() is None:
                raise KeyError(case_id)
            valid_refs = {
                row["id"]
                for row in connection.execute(
                    "SELECT id FROM evidence WHERE case_id = ?", (case_id,)
                ).fetchall()
            }
            if any(reference not in valid_refs for reference in evidence_refs):
                raise ValueError("awareness 证据引用不属于当前案件")
            connection.execute(
                """
                UPDATE cases SET awareness_at=?, awareness_confirmed_by=?,
                    awareness_confirmed_at=?, awareness_basis=?,
                    awareness_evidence_refs_json=?, updated_at=? WHERE id=?
                """,
                (
                    normalized,
                    actor.strip(),
                    utc_now(),
                    basis,
                    _json(evidence_refs),
                    utc_now(),
                    case_id,
                ),
            )
            self._audit(
                connection,
                case_id,
                "awareness_manually_confirmed",
                actor,
                {
                    "awareness_at": normalized,
                    "previous_awareness_at": case.get("awareness_at"),
                    "basis": basis,
                    "evidence_refs": evidence_refs,
                    "automatic_inference": False,
                },
            )
        return self.get_case(case_id)

    def add_evidence(
        self,
        case_id: str,
        evidence: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        status = str(evidence.get("reliable_malicious_exploitation") or "unknown")
        if status not in EVIDENCE_EXPLOITATION_VALUES:
            raise ValueError("证据利用状态无效")
        description = str(evidence.get("description") or "").strip()
        if not description:
            raise ValueError("证据描述不能为空")
        evidence_id = str(uuid.uuid4())
        retrieved_at = str(evidence.get("retrieved_at") or utc_now())
        sha256 = str(evidence.get("sha256") or "").strip().casefold()
        if sha256 and not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("证据 SHA-256 必须是 64 位十六进制")
        malicious_actor = bool(evidence.get("malicious_actor_confirmed"))
        without_permission = bool(evidence.get("without_permission_confirmed"))
        actual_exploitation = bool(evidence.get("actual_exploitation_confirmed"))
        with self.connect() as connection:
            if connection.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone() is None:
                raise KeyError(case_id)
            connection.execute(
                """
                INSERT INTO evidence(
                    id, case_id, source_type, source_ref, source_url, published_at,
                    retrieved_at, sha256, description, product_relevance,
                    reliable_malicious_exploitation, malicious_actor_confirmed,
                    without_permission_confirmed, actual_exploitation_confirmed,
                    recorded_by, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    case_id,
                    str(evidence.get("source_type") or "other"),
                    str(evidence.get("source_ref") or ""),
                    str(evidence.get("source_url") or ""),
                    evidence.get("published_at"),
                    retrieved_at,
                    sha256,
                    description,
                    str(evidence.get("product_relevance") or ""),
                    status,
                    int(malicious_actor),
                    int(without_permission),
                    int(actual_exploitation),
                    actor.strip(),
                    utc_now(),
                ),
            )
            self._audit(
                connection,
                case_id,
                "evidence_added",
                actor,
                {
                    "evidence_id": evidence_id,
                    "reliable_malicious_exploitation": status,
                    "malicious_actor_confirmed": malicious_actor,
                    "without_permission_confirmed": without_permission,
                    "actual_exploitation_confirmed": actual_exploitation,
                },
            )
        return self.get_case(case_id)

    def review_case(
        self,
        case_id: str,
        stage: str,
        reviewer: str,
        reviewer_id: str,
        decision: str,
        rationale: str,
    ) -> dict[str, Any]:
        reviewer = reviewer.strip()
        rationale = rationale.strip()
        if stage not in {"technical", "compliance"}:
            raise ValueError("审批阶段无效")
        if decision not in ART14_DECISIONS - {"not_assessed"}:
            raise ValueError("Art.14 决策无效")
        if not reviewer or not rationale:
            raise ValueError("审批人和理由不能为空")
        case = self.get_case(case_id)

        if decision == "reportable":
            if case["applicability_status"] != "known_affected":
                raise ValueError("reportable 前必须确认具体产品为 known_affected")
            if not case.get("awareness_at") or not case.get("awareness_confirmed_by"):
                raise ValueError("reportable 前必须人工确认制造商 awareness 时间")
            if case.get("case_type") == "severe_incident":
                criteria = case.get("severe_incident_criteria") or {}
                criteria_met = bool(
                    criteria.get(
                        "availability_authenticity_integrity_confidentiality_impact"
                    )
                    or criteria.get("malicious_code_introduction")
                )
                if not criteria_met or not str(criteria.get("rationale") or "").strip():
                    raise ValueError(
                        "reportable 严重事件必须确认至少一项 CRA Art.14(5) 准则并记录理由"
                    )
                qualifying_evidence = [
                    item
                    for item in case.get("evidence") or []
                    if item.get("description")
                    and item.get("product_relevance")
                    and item.get("sha256")
                    and (item.get("source_ref") or item.get("source_url"))
                ]
                if not qualifying_evidence:
                    raise ValueError(
                        "reportable 严重事件必须绑定含来源、SHA-256、产品相关性和影响说明的结构化证据"
                    )
            else:
                if case["exploitation_evidence_status"] != "reliable_evidence":
                    raise ValueError("reportable 前必须确认存在可靠的实际恶意利用证据")
                qualifying_evidence = [
                    item
                    for item in case.get("evidence") or []
                    if item.get("reliable_malicious_exploitation") == "yes"
                    and item.get("malicious_actor_confirmed")
                    and item.get("without_permission_confirmed")
                    and item.get("actual_exploitation_confirmed")
                    and item.get("product_relevance")
                    and item.get("sha256")
                    and (item.get("source_ref") or item.get("source_url"))
                ]
                if not qualifying_evidence:
                    raise ValueError(
                        "reportable 必须绑定一条含来源、SHA-256、产品相关性、恶意行为者、未经许可和实际利用确认的结构化证据"
                    )
        if decision == "not_reportable":
            if not case.get("next_review_at"):
                raise ValueError("not_reportable 必须设置下一次复核时间")
            if case["applicability_status"] == "under_investigation":
                raise ValueError("产品仍在调查时不能关闭为 not_reportable")

        now = utc_now()
        with self.connect() as connection:
            if stage == "technical":
                connection.execute(
                    """
                    UPDATE cases SET technical_reviewer=?, technical_reviewed_at=?,
                        technical_decision=?, technical_rationale=?,
                        compliance_reviewer='', compliance_reviewed_at=NULL,
                        compliance_decision='', compliance_rationale='',
                        art14_decision='not_assessed', workflow_status='technical_review',
                        approved_at=NULL, updated_at=?
                    WHERE id=?
                    """,
                    (
                        f"{reviewer} [{reviewer_id}]",
                        now,
                        decision,
                        rationale,
                        now,
                        case_id,
                    ),
                )
            else:
                if not case.get("technical_reviewer"):
                    raise ValueError("必须先完成技术审批")
                if _normalize_identity(case["technical_reviewer"]) == _normalize_identity(
                    f"{reviewer} [{reviewer_id}]"
                ):
                    raise ValueError("合规审批人必须与技术审批人不同")
                if f"[{reviewer_id}]" in case["technical_reviewer"]:
                    raise ValueError("合规审批必须使用不同的本地审批账户")
                if case.get("technical_decision") != decision:
                    connection.execute(
                        """
                        UPDATE cases SET compliance_reviewer=?, compliance_reviewed_at=?,
                            compliance_decision=?, compliance_rationale=?,
                            art14_decision='not_assessed',
                            workflow_status='compliance_review',
                            approved_at=NULL, updated_at=? WHERE id=?
                        """,
                        (
                            f"{reviewer} [{reviewer_id}]",
                            now,
                            decision,
                            rationale,
                            now,
                            case_id,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE cases SET compliance_reviewer=?, compliance_reviewed_at=?,
                            compliance_decision=?, compliance_rationale=?,
                            art14_decision=?, decision_rationale=?,
                            workflow_status='approved',
                            approved_at=?, updated_at=? WHERE id=?
                        """,
                        (
                            f"{reviewer} [{reviewer_id}]",
                            now,
                            decision,
                            rationale,
                            decision,
                            rationale,
                            now,
                            now,
                            case_id,
                        ),
                    )
            connection.execute(
                """
                INSERT INTO approvals(id, case_id, stage, reviewer, decision, rationale, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    case_id,
                    stage,
                    f"{reviewer} [{reviewer_id}]",
                    decision,
                    rationale,
                    now,
                ),
            )
            self._audit(
                connection,
                case_id,
                f"{stage}_review_recorded",
                reviewer,
                {
                    "decision": decision,
                    "rationale": rationale,
                    "case_type": case.get("case_type"),
                },
            )
        return self.get_case(case_id)

    def mark_submitted(
        self,
        case_id: str,
        actor: str,
        stage: str,
        submitted_at: str,
        receipt: str,
    ) -> dict[str, Any]:
        case = self.get_case(case_id)
        if case["workflow_status"] not in {"approved", "submitted"} or case[
            "art14_decision"
        ] != "reportable":
            raise ValueError("只有已四眼批准且决定为 reportable 的案件可登记提交")
        if not receipt.strip():
            raise ValueError("必须填写 SRP 回执或提交编号")
        if stage not in {"early-warning", "notification", "final-report"}:
            raise ValueError("SRP 提交阶段无效")
        parsed = datetime.fromisoformat(submitted_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("提交时间必须包含时区")
        parsed_utc = parsed.astimezone(timezone.utc)
        awareness = datetime.fromisoformat(
            str(case["awareness_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        if parsed_utc < awareness:
            raise ValueError("SRP 提交时间不能早于制造商 awareness 时间")
        if parsed_utc > datetime.now(timezone.utc):
            raise ValueError("SRP 提交时间不能在未来")
        normalized = parsed_utc.isoformat(timespec="seconds")
        ordered_stages = ["early-warning", "notification", "final-report"]
        existing_receipts = {
            str(item.get("stage")): item
            for item in case.get("submission_receipts") or []
        }
        stage_index = ordered_stages.index(stage)
        missing_prerequisites = [
            required
            for required in ordered_stages[:stage_index]
            if required not in existing_receipts
        ]
        if missing_prerequisites:
            raise ValueError(
                "必须先登记前序 SRP 阶段回执: "
                + ", ".join(missing_prerequisites)
            )
        if stage_index:
            previous = existing_receipts[ordered_stages[stage_index - 1]]
            previous_time = datetime.fromisoformat(
                str(previous["submitted_at"]).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
            if parsed_utc < previous_time:
                raise ValueError("SRP 提交时间不能早于前序阶段")
        reporting_stage = {
            "early-warning": "early_warning_submitted",
            "notification": "notification_submitted",
            "final-report": "final_submitted",
        }[stage]
        with self.connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO submission_receipts(
                        id, case_id, stage, submitted_at, receipt, recorded_by, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        case_id,
                        stage,
                        normalized,
                        receipt.strip(),
                        actor.strip(),
                        utc_now(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("该 SRP 阶段已登记回执") from exc
            connection.execute(
                """
                UPDATE cases SET workflow_status=?, reporting_stage=?,
                    submitted_at=?, submission_receipt=?, updated_at=? WHERE id=?
                """,
                (
                    "submitted" if stage == "final-report" else "approved",
                    reporting_stage,
                    normalized,
                    receipt.strip(),
                    utc_now(),
                    case_id,
                ),
            )
            self._audit(
                connection,
                case_id,
                "srp_submission_manually_recorded",
                actor,
                {
                    "stage": stage,
                    "submitted_at": normalized,
                    "receipt": receipt.strip(),
                    "api_submission": False,
                    "submission_mode": "manual_only",
                    "case_type": case.get("case_type"),
                },
            )
        return self.get_case(case_id)

    def record_vex_import(
        self,
        vex_format: str,
        document_id: str,
        source_name: str,
        source_sha256: str,
        actor: str,
        entry_count: int,
        warnings: list[str],
        receipt_vex_document_sha256: str = "",
        receipt_statements_canonical_sha256: str = "",
        receipt_issuer_id: str = "",
    ) -> str:
        if vex_format not in VEX_SOURCES:
            raise ValueError("不支持的 VEX 格式")
        import_id = str(uuid.uuid4())
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO vex_imports(
                    id, format, document_id, source_name, source_sha256,
                    imported_by, entry_count, warnings_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    import_id,
                    vex_format,
                    document_id,
                    source_name,
                    source_sha256,
                    actor.strip(),
                    entry_count,
                    _json(warnings),
                    utc_now(),
                ),
            )
            audit_payload: dict[str, Any] = {
                "import_id": import_id,
                "format": vex_format,
                "source_sha256": source_sha256,
                "entry_count": entry_count,
            }
            if receipt_vex_document_sha256:
                audit_payload["receipt_vex_document_sha256"] = receipt_vex_document_sha256
            if receipt_statements_canonical_sha256:
                audit_payload["receipt_statements_canonical_sha256"] = (
                    receipt_statements_canonical_sha256
                )
            if receipt_issuer_id:
                audit_payload["receipt_issuer_id"] = receipt_issuer_id
            self._audit(
                connection,
                None,
                "vex_document_imported",
                actor,
                audit_payload,
            )
        return import_id

    def record_feed_snapshot(
        self,
        feed_name: str,
        status: str,
        retrieved_at: str | None,
        sha256: str = "",
        record_count: int | None = None,
        detail: str = "",
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO feed_snapshots(
                    feed_name, status, retrieved_at, sha256, record_count, detail, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feed_name) DO UPDATE SET
                    status=excluded.status, retrieved_at=excluded.retrieved_at,
                    sha256=excluded.sha256, record_count=excluded.record_count,
                    detail=excluded.detail, updated_at=excluded.updated_at
                """,
                (
                    feed_name,
                    status,
                    retrieved_at,
                    sha256,
                    record_count,
                    detail,
                    utc_now(),
                ),
            )

    def list_feed_snapshots(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM feed_snapshots ORDER BY feed_name"
            ).fetchall()
        return [dict(row) for row in rows]
