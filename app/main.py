from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .art14 import (
    SRP_FIELD_PROFILE,
    SRP_STAGES,
    build_srp_payload,
    deadline_status,
    srp_readiness,
    write_srp_html,
    write_srp_json,
    write_srp_submission_package_zip,
    write_srp_xlsx,
)
from .matcher import (
    EUVD_BASE_URL,
    NETWORK_FALLBACK,
    EuvdClient,
    match_components,
    refresh_public_snapshots,
    repair_text,
)
from .spreadsheet_io import (
    HANDOFF_MONITORING_PURPOSE,
    HANDOFF_VERSION_APPLICABILITY_BOUNDARY,
    build_components,
    read_sbom,
    write_report,
)
from .template_builder import PUBLIC_TEMPLATE_FILENAME, template_bytes
from .vex import parse_vex_bytes, write_vex
from .vex_intake import VexIntakeError, verify_vex_intake_receipt
from .version import APP_VERSION, USER_AGENT
from .evidence_package import (
    build_evidence_package_payload,
    write_evidence_package_zip,
    write_evidence_xlsx,
)
from .workflow_store import WorkflowStore


APP_DIR = Path(__file__).resolve().parent
SBOM_TEMPLATE_PATH = (
    APP_DIR / "assets" / "客户SBOM导入模板_PRO-03B_v1.4兼容版.xlsx"
)
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOB_DIR = DATA_DIR / "jobs"
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/app/outputs"))
# Phase 2 mirror ops signal files (shared with the mirror_ops.py orchestrator).
# Web only writes the request and reads the status; it never runs the sync
# (constraint #3: the Web workbench is not the synchronization authority).
SYNC_REQUEST_PATH = DATA_DIR / "sync-request.json"
SYNC_STATUS_PATH = DATA_DIR / "sync-status.json"
# Phase A: guardian heartbeat TTL — the Web treats the mirror_ops daemon as
# alive while now - guardian_heartbeat_at < this (seconds). Tuned to exceed the
# longest single sync subprocess; a hung daemon past this is a real alert.
GUARDIAN_HEARTBEAT_TTL_SECONDS = int(os.getenv("GUARDIAN_HEARTBEAT_TTL_SECONDS", "900"))
MAX_COMPONENTS = int(os.getenv("MAX_COMPONENTS", "2000"))
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_CYCLONEDX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_SUFFIXES = {".xlsx", ".xlsm", ".csv", ".tsv", ".json"}
CANONICAL_UUID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
    if host.strip()
]

for directory in (UPLOAD_DIR, JOB_DIR, OUTPUT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

WORKFLOW_STORE = WorkflowStore(DATA_DIR / "workbench.sqlite3")
_feed_refresh_task: asyncio.Task[Any] | None = None

app = FastAPI(
    title="EUVD Dependency Workbench",
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url=None,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    if request.url.path.startswith("/api/") or request.url.path in {
        "/",
        "/index.html",
        "/app.js",
        "/srp-guide.html",
        "/styles.css",
    }:
        response.headers["Cache-Control"] = "no-store"
    return response


class MatchRequest(BaseModel):
    upload_id: str = Field(pattern=CANONICAL_UUID_PATTERN)
    mapping: dict[str, str]
    project_name: str = Field(default="", max_length=120)
    project_version: str = Field(default="", max_length=80)
    software_build: str = Field(default="", max_length=160)
    customer: str = Field(default="", max_length=120)


class ReviewerCreateRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=120)
    role: str
    pin: str = Field(min_length=8, max_length=128)


class ManualCaseRequest(BaseModel):
    case_type: str = Field(
        default="actively_exploited_vulnerability",
        pattern=r"^(actively_exploited_vulnerability|severe_incident)$",
    )
    project_name: str = Field(min_length=1, max_length=160)
    project_version: str = Field(default="", max_length=100)
    software_build: str = Field(default="", max_length=160)
    customer: str = Field(default="", max_length=160)
    component_name: str = Field(default="", max_length=200)
    component_version: str = Field(default="", max_length=100)
    cve_id: str = Field(default="", max_length=40)
    euvd_id: str = Field(default="", max_length=40)
    public_exploitation_status: str = Field(default="manual_signal", max_length=160)
    vulnerability_summary: str = Field(default="", max_length=4000)
    actor: str = Field(default="local analyst", max_length=120)


class CaseFromFindingRequest(BaseModel):
    job_id: str = Field(pattern=CANONICAL_UUID_PATTERN)
    finding_index: int = Field(ge=0)
    actor: str = Field(default="local analyst", max_length=120)


class CaseUpdateRequest(BaseModel):
    updates: dict[str, Any]
    actor: str = Field(default="local analyst", max_length=120)


class EvidenceRequest(BaseModel):
    source_type: str = Field(default="other", max_length=80)
    source_ref: str = Field(default="", max_length=500)
    source_url: str = Field(default="", max_length=2000)
    published_at: str | None = None
    retrieved_at: str | None = None
    sha256: str = Field(default="", max_length=64)
    description: str = Field(min_length=1, max_length=8000)
    product_relevance: str = Field(default="", max_length=4000)
    reliable_malicious_exploitation: str = "unknown"
    malicious_actor_confirmed: bool = False
    without_permission_confirmed: bool = False
    actual_exploitation_confirmed: bool = False
    actor: str = Field(default="local analyst", max_length=120)


class AwarenessRequest(BaseModel):
    reviewer_id: str
    pin: str
    awareness_at: str
    basis: str = Field(min_length=1, max_length=8000)
    evidence_refs: list[str]
    confirmation: bool


class ReviewRequest(BaseModel):
    reviewer_id: str
    pin: str
    stage: str
    decision: str
    rationale: str = Field(min_length=1, max_length=8000)


class SubmissionRequest(BaseModel):
    reviewer_id: str
    pin: str
    stage: str
    submitted_at: str
    receipt: str = Field(min_length=1, max_length=500)


def _canonical_uuid_text(identifier: str, label: str) -> str:
    try:
        canonical = str(uuid.UUID(identifier))
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{label} 无效") from exc
    if canonical != identifier:
        raise HTTPException(status_code=400, detail=f"{label} 必须是规范的小写 UUID")
    return canonical


def _confined_uuid_path(root: Path, identifier: str, suffix: str, label: str) -> Path:
    canonical = _canonical_uuid_text(identifier, label)
    resolved_root = root.resolve()
    candidate = (resolved_root / f"{canonical}{suffix}").resolve()
    if candidate.parent != resolved_root:
        raise HTTPException(status_code=400, detail=f"{label} 路径无效")
    return candidate


def _job_path(job_id: str) -> Path:
    return _confined_uuid_path(JOB_DIR, job_id, ".json", "job_id")


def _upload_record_path(upload_id: str) -> Path:
    return _confined_uuid_path(
        UPLOAD_DIR, upload_id, ".upload-record.json", "upload_id"
    )


def _legacy_upload_record_path(upload_id: str) -> Path:
    return _confined_uuid_path(UPLOAD_DIR, upload_id, ".json", "upload_id")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    temporary.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _list_jobs() -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    for path in JOB_DIR.glob("*.json"):
        try:
            jobs.append(_read_json(path))
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(jobs, key=lambda job: job.get("created_at", ""), reverse=True)


def _safe_name(value: str, fallback: str = "SBOM") -> str:
    stem = Path(value).stem
    cleaned = re.sub(r"[^\w\u4e00-\u9fff.-]+", "_", stem, flags=re.UNICODE).strip("._")
    return cleaned[:80] or fallback


def _compact_pre7_evidence(
    summary: dict[str, Any],
    artifact: dict[str, Any],
) -> dict[str, Any]:
    """Keep workflow records small while preserving a hash-bound full artifact."""

    requirements = summary.get("requirements") or {}
    rq06 = deepcopy(requirements.get("PRE-7-RQ-06") or {})
    rq07 = requirements.get("PRE-7-RQ-07") or {}
    items = rq07.get("items") if isinstance(rq07.get("items"), list) else []
    return {
        "summary_type": summary.get("summary_type", "artifact_field_presence"),
        "automatic_conformity_decision": False,
        "requirements": {
            "PRE-7-RQ-06": rq06,
            "PRE-7-RQ-07": {
                "coverage_counts": deepcopy(rq07.get("coverage_counts") or {}),
                "evidence_gaps": deepcopy(rq07.get("evidence_gaps") or []),
                "item_count": len(items),
                "full_evidence_artifact": deepcopy(artifact),
            },
        },
        "limitations": deepcopy(summary.get("limitations") or []),
    }


def _enhance_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = dict(result.get("summary") or {})
    components = list(result.get("components") or [])
    component_count = int(summary.get("component_count") or len(components))
    identity_ready = sum(
        1
        for row in components
        if row.get("identity_ready")
        or (
            row.get("name")
            and row.get("version")
            and (row.get("vendor") or row.get("purl") or row.get("cpe"))
        )
        or row.get("cve_ids")
        or row.get("euvd_ids")
    )
    error_count = int(summary.get("error_count") or len(result.get("errors") or []))
    query_success = max(0, component_count - error_count)
    query_metadata_rows = [row for row in components if "query_truncated" in row]
    complete_fetch = sum(
        1
        for row in query_metadata_rows
        if row.get("query_status") == "成功" and not row.get("query_truncated")
    )

    summary.setdefault("identity_ready_components", identity_ready)
    summary.setdefault(
        "identity_coverage_percent",
        round(identity_ready * 100 / component_count) if component_count else 100,
    )
    summary.setdefault("query_success_components", query_success)
    summary.setdefault(
        "query_coverage_percent",
        round(query_success * 100 / component_count) if component_count else 100,
    )
    summary.setdefault("complete_fetch_components", complete_fetch)
    summary.setdefault(
        "retrieval_coverage_percent",
        round(complete_fetch * 100 / query_success)
        if query_success and query_metadata_rows
        else None,
    )
    summary.setdefault(
        "review_components",
        sum(1 for row in components if int(row.get("review_count") or 0) > 0),
    )
    summary.setdefault(
        "truncated_queries",
        sum(1 for row in query_metadata_rows if row.get("query_truncated")),
    )
    summary["retrieval_coverage_known"] = bool(query_metadata_rows)
    return summary


def _project_row(job: dict[str, Any]) -> dict[str, Any]:
    result = job.get("result") or {}
    matches = result.get("matches") or []
    summary = _enhance_summary(result) if result else {}
    severity_counts = {
        severity: sum(
            1
            for row in matches
            if row.get("match_status") == "已匹配" and row.get("severity") == severity
        )
        for severity in ("严重", "高", "中", "低", "未评级")
    }
    scores = [
        float(row["cvss_score"])
        for row in matches
        if row.get("match_status") == "已匹配" and row.get("cvss_score") is not None
    ]
    return {
        "id": job.get("id"),
        "name": job.get("project_name") or _safe_name(job.get("file_name", "SBOM")),
        "version": job.get("project_version") or "",
        "customer": job.get("customer") or "",
        "file_name": job.get("file_name") or "",
        "status": job.get("status") or "unknown",
        "stage": job.get("stage") or "",
        "created_at": job.get("created_at") or "",
        "finished_at": job.get("finished_at") or "",
        "report_url": f"/api/jobs/{job.get('id')}/report"
        if job.get("report_name")
        else "",
        "summary": summary,
        "severity_counts": severity_counts,
        "highest_cvss": max(scores) if scores else None,
    }


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    response = {
        key: value
        for key, value in job.items()
        if key not in {"result", "report_path", "mapping"}
    }
    result = job.get("result")
    if result:
        response["result"] = {
            "summary": _enhance_summary(result),
            "matches": [
                {**row, "finding_index": index}
                for index, row in enumerate(result["matches"][:1000])
            ],
            "components": result["components"][:2000],
            "errors": result["errors"][:200],
            "truncated": len(result["matches"]) > 1000,
        }
    if job.get("report_name"):
        response["report_url"] = f"/api/jobs/{job['id']}/report"
    return response


async def _run_job(job_id: str, upload_record: dict[str, Any], mapping: dict[str, str]) -> None:
    path = _job_path(job_id)
    job = _read_json(path)
    if job.get("status") == "canceling":
        # Cancelled before the worker picked it up.
        job.update(
            {
                "status": "cancelled",
                "stage": "已取消",
                "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
        )
        _write_json(path, job)
        return
    try:
        parsed = upload_record["parsed"]
        components = build_components(parsed, mapping, MAX_COMPONENTS)
        handoff_evidence = (parsed.get("metadata_binding") or {}).get("evidence") or {}
        monitoring_candidate_only = bool(
            handoff_evidence.get("monitoring_purpose")
            == HANDOFF_MONITORING_PURPOSE
            and handoff_evidence.get("automatic_vulnerability_confirmation") is False
            and handoff_evidence.get("automatic_art14_decision") is False
            and handoff_evidence.get("version_applicability_boundary")
            == HANDOFF_VERSION_APPLICABILITY_BOUNDARY
        )
        job.update(
            {
                "status": "running",
                "stage": "正在查询 EUVD",
                "total": len(components),
                "completed": 0,
                "progress": 0,
            }
        )
        _write_json(path, job)

        async def progress(completed: int, total: int, component_name: str) -> None:
            # Cooperative cancellation: the operator may POST /cancel between
            # components; the next progress callback observes it and aborts.
            if _read_json(path).get("status") == "canceling":
                raise JobCancelled()
            job["completed"] = completed
            job["total"] = total
            job["progress"] = round(completed * 100 / total) if total else 100
            job["current_component"] = component_name
            if completed == total or completed % 2 == 0:
                _write_json(path, job)

        result = await match_components(
            components,
            progress=progress,
            monitoring_candidate_only=monitoring_candidate_only,
        )
        result["input_sbom_snapshot"] = {
            "sheet": parsed.get("sheet") or "",
            "header_row": parsed.get("header_row") or 1,
            "headers": list(parsed.get("headers") or []),
            "rows": list(parsed.get("rows") or []),
        }
        job["stage"] = "正在生成报告"
        _write_json(path, job)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_name = f"EUVD匹配报告_{_safe_name(upload_record['original_name'])}_{timestamp}.xlsx"
        report_path = OUTPUT_DIR / report_name
        await asyncio.to_thread(
            write_report,
            report_path,
            upload_record["original_name"],
            result,
        )

        job.update(
            {
                "status": "completed",
                "stage": "完成",
                "progress": 100,
                "completed": len(components),
                "result": result,
                "report_name": report_name,
                "report_path": str(report_path),
                "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
        )
        # Atomicity order: persist the completed job JSON *before* registering
        # the product snapshot in SQLite. A crash between the two then leaves a
        # completed job with no snapshot, which the startup reconcile repairs
        # (completed -> register). The old order (register then write) could
        # leave a snapshot behind a still-running job that startup would then
        # mark failed — a contradictory cross-store state.
        _write_json(path, job)
        await asyncio.to_thread(
            WORKFLOW_STORE.register_sbom_snapshot,
            job,
            str(upload_record.get("source_sha256") or ""),
            str((upload_record.get("parsed") or {}).get("kind") or ""),
            str((upload_record.get("parsed") or {}).get("bom_version") or ""),
        )
    except JobCancelled:
        job.update(
            {
                "status": "cancelled",
                "stage": "已取消",
                "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
        )
        _write_json(path, job)
    except Exception as exc:
        job.update(
            {
                "status": "failed",
                "stage": "失败",
                "error": repair_text(exc),
                "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
        )
        _write_json(path, job)


JOB_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "euvd-sbom-matcher/job")


def _idempotent_job_id(upload_id: str, mapping: dict[str, str]) -> str:
    """Deterministic job id from upload + column mapping.

    Same upload + same mapping returns the same job id, so a duplicate submit
    (double-click, retry) reuses the existing job instead of spawning a new one.
    Product identity fields (name/version/build/customer) are deliberately
    excluded: they are operator-editable metadata, not part of the match work.
    """
    canonical = json.dumps(
        {
            field: mapping.get(field, "")
            for field in (
                "name",
                "version",
                "vendor",
                "purl",
                "cpe",
                "scope",
                "license",
                "cve",
                "euvd",
            )
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return str(uuid.uuid5(JOB_ID_NAMESPACE, f"{upload_id}\n{canonical}"))


class JobCancelled(Exception):
    """Raised inside _run_job when the operator requested cancellation."""


@app.get("/api/health")
async def health() -> dict[str, Any]:
    local_status = await asyncio.to_thread(EuvdClient.local_snapshot_status)
    if not NETWORK_FALLBACK and (
        local_status is None
        or local_status.get("status") not in {"local_ready", "local_degraded"}
    ):
        detail = (
            str(local_status.get("detail") or local_status.get("status"))
            if local_status
            else "本地 EUVD 快照缺失"
        )
        raise HTTPException(
            status_code=503,
            detail=f"EUVD 本地就绪检查失败: {detail}",
        )
    return {
        "status": "ok",
        "service": "EUVD Dependency Workbench",
        "version": APP_VERSION,
        "source": "externally hash-verified local EUVD snapshot; local VEX/Art.14 workflow",
        "euvd_network_fallback_enabled": NETWORK_FALLBACK,
        "euvd_local_status": local_status,
        "automatic_srp_submission": False,
        "srp_submission_mode": "manual_only",
        "srp_assistance_mode": "generate_review_confirm_open_official_portal",
        "srp_information_url": SRP_FIELD_PROFILE["srp_information_url"],
        "srp_portal_url": SRP_FIELD_PROFILE.get("portal_url"),
        "srp_portal_url_status": SRP_FIELD_PROFILE["portal_url_status"],
        "srp_field_profile": SRP_FIELD_PROFILE,
        "art14_case_types": [
            "actively_exploited_vulnerability",
            "severe_incident",
        ],
    }


@app.get("/api/dashboard")
async def dashboard() -> dict[str, Any]:
    jobs = _list_jobs()
    projects = [_project_row(job) for job in jobs]
    completed_jobs = [job for job in jobs if job.get("status") == "completed" and job.get("result")]
    completed_projects = [_project_row(job) for job in completed_jobs]

    summaries = [project["summary"] for project in completed_projects]
    component_count = sum(int(summary.get("component_count") or 0) for summary in summaries)
    identity_ready = sum(
        int(summary.get("identity_ready_components") or 0) for summary in summaries
    )
    query_success = sum(
        int(summary.get("query_success_components") or 0) for summary in summaries
    )
    known_retrieval_projects = [
        project
        for project in completed_projects
        if project["summary"].get("retrieval_coverage_known")
    ]
    known_query_success = sum(
        int(project["summary"].get("query_success_components") or 0)
        for project in known_retrieval_projects
    )
    complete_fetch = sum(
        int(project["summary"].get("complete_fetch_components") or 0)
        for project in known_retrieval_projects
    )
    severity_counts = {
        severity: sum(project["severity_counts"][severity] for project in completed_projects)
        for severity in ("严重", "高", "中", "低", "未评级")
    }
    unique_projects = {
        (project["name"].casefold(), project["customer"].casefold())
        for project in completed_projects
    }
    art14_cases = await asyncio.to_thread(WORKFLOW_STORE.list_cases)
    return {
        "metrics": {
            "project_count": len(unique_projects),
            "version_count": len(completed_projects),
            "component_count": component_count,
            "confirmed_findings": sum(
                int(summary.get("confirmed_findings") or 0) for summary in summaries
            ),
            "review_findings": sum(
                int(summary.get("review_findings") or 0) for summary in summaries
            ),
            "known_exploited_findings": sum(
                int(summary.get("known_exploited_findings") or 0) for summary in summaries
            ),
            "art14_review_findings": sum(
                int(summary.get("art14_review_findings") or 0) for summary in summaries
            ),
            "art14_case_count": len(art14_cases),
            "art14_approved_reportable": sum(
                1
                for item in art14_cases
                if item.get("workflow_status") in {"approved", "submitted"}
                and item.get("art14_decision") == "reportable"
            ),
            "query_errors": sum(int(summary.get("error_count") or 0) for summary in summaries),
            "identity_coverage_percent": round(identity_ready * 100 / component_count)
            if component_count
            else 100,
            "query_coverage_percent": round(query_success * 100 / component_count)
            if component_count
            else 100,
            "retrieval_coverage_percent": round(complete_fetch * 100 / known_query_success)
            if known_query_success
            else None,
        },
        "severity_counts": severity_counts,
        "recent_projects": completed_projects[:8],
        "active_projects": [project for project in projects if project["status"] != "completed"][:8],
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


@app.get("/api/projects")
async def list_projects() -> dict[str, Any]:
    return {"projects": [_project_row(job) for job in _list_jobs()]}


@app.get("/api/catalog/components")
async def component_catalog() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for job in _list_jobs():
        result = job.get("result") or {}
        for component in result.get("components") or []:
            rows.append(
                {
                    **component,
                    "job_id": job.get("id"),
                    "project_name": job.get("project_name")
                    or _safe_name(job.get("file_name", "SBOM")),
                    "project_version": job.get("project_version") or "",
                    "customer": job.get("customer") or "",
                    "finished_at": job.get("finished_at") or "",
                }
            )
    return {"components": rows[:5000], "truncated": len(rows) > 5000}


@app.get("/api/catalog/vulnerabilities")
async def vulnerability_catalog() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for job in _list_jobs():
        result = job.get("result") or {}
        for finding_index, match in enumerate(result.get("matches") or []):
            rows.append(
                {
                    **match,
                    "finding_index": finding_index,
                    "job_id": job.get("id"),
                    "project_name": job.get("project_name")
                    or _safe_name(job.get("file_name", "SBOM")),
                    "project_version": job.get("project_version") or "",
                    "customer": job.get("customer") or "",
                    "finished_at": job.get("finished_at") or "",
                }
            )
    return {"vulnerabilities": rows[:5000], "truncated": len(rows) > 5000}


@app.get("/api/euvd/status")
async def euvd_status() -> dict[str, Any]:
    local_status = await asyncio.to_thread(EuvdClient.local_snapshot_status)
    if local_status is not None:
        return {
            **local_status,
            "base_url": EUVD_BASE_URL,
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
    if not NETWORK_FALLBACK:
        return {
            "status": "local_required_unavailable",
            "base_url": EUVD_BASE_URL,
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "network_fallback_enabled": False,
            "detail": "本地 EUVD 快照缺失；默认禁止将 SBOM 产品/供应商查询回退到网络",
        }
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.get(
                f"{EUVD_BASE_URL}/api/enisaid",
                params={"id": "EUVD-2025-201695"},
                headers={"User-Agent": USER_AGENT},
            )
            response.raise_for_status()
        return {
            "status": "online",
            "base_url": EUVD_BASE_URL,
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
    except httpx.HTTPError:
        return {
            "status": "unavailable",
            "base_url": EUVD_BASE_URL,
            "detail": "EUVD endpoint check failed",
        }


async def _refresh_and_record_feeds(force: bool) -> dict[str, Any]:
    local_snapshots = await asyncio.to_thread(EuvdClient.local_feed_snapshots)
    if local_snapshots is not None:
        for snapshot in local_snapshots:
            await asyncio.to_thread(
                WORKFLOW_STORE.record_feed_snapshot,
                str(snapshot.get("feed_name") or "local-euvd"),
                str(snapshot.get("status") or "unknown"),
                snapshot.get("retrieved_at"),
                str(snapshot.get("sha256") or ""),
                snapshot.get("record_count"),
                str(snapshot.get("detail") or ""),
            )
        return {
            "mode": "local-read-only-inspection",
            "network_refresh_performed": False,
            "important_boundary": (
                "Web 服务只检查本地消费者快照；正式同步必须在独立镜像项目执行。"
            ),
            "feeds": local_snapshots,
        }
    if not NETWORK_FALLBACK:
        detail = "本地 EUVD 快照不可用，且 Web 网络回退默认关闭"
        for name in ("cve-euvd-mapping", "euvd-kev"):
            await asyncio.to_thread(
                WORKFLOW_STORE.record_feed_snapshot,
                name,
                "unavailable",
                None,
                "",
                None,
                detail,
            )
        raise ValueError(detail)
    try:
        snapshots = await refresh_public_snapshots(force=force)
    except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
        detail = repair_text(exc)
        for name in ("cve-euvd-mapping", "euvd-kev"):
            await asyncio.to_thread(
                WORKFLOW_STORE.record_feed_snapshot,
                name,
                "unavailable",
                None,
                "",
                None,
                detail,
            )
        raise
    for name, snapshot in snapshots.items():
        await asyncio.to_thread(
            WORKFLOW_STORE.record_feed_snapshot,
            name,
            str(snapshot.get("status") or "unknown"),
            snapshot.get("downloaded_at"),
            str(snapshot.get("snapshot_sha256") or ""),
            snapshot.get("record_count"),
            str(snapshot.get("fallback_error") or ""),
        )
    return snapshots


@app.get("/api/euvd/snapshots")
async def list_euvd_snapshots() -> dict[str, Any]:
    local_snapshots = await asyncio.to_thread(EuvdClient.local_feed_snapshots)
    return {
        "snapshots": (
            local_snapshots
            if local_snapshots is not None
            else await asyncio.to_thread(WORKFLOW_STORE.list_feed_snapshots)
        ),
        "interpretation": {
            "fresh": "本地快照在配置的更新窗口内",
            "stale": "快照已过期，不能把未命中解释为当前无公开利用信号",
            "degraded": "本次更新失败，正在使用 last-known-good 快照",
            "unavailable": "没有可用快照；结果必须视为 Unknown",
        },
    }


@app.post("/api/euvd/snapshots/refresh")
async def refresh_euvd_snapshots() -> dict[str, Any]:
    try:
        return {"snapshots": await _refresh_and_record_feeds(force=True)}
    except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail=repair_text(exc)) from exc


@app.post("/api/euvd/sync-request")
async def request_mirror_sync() -> dict[str, Any]:
    """改进2b Phase2: drop a sync-request signal file for the mirror ops
    orchestrator (mirror_ops.py watch) to pick up. Constraint #3: the Web
    workbench only writes the signal, it never runs the sync itself.
    """
    if SYNC_STATUS_PATH.exists():
        try:
            current = json.loads(SYNC_STATUS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = {}
        if current.get("state") == "running":
            raise HTTPException(status_code=409, detail="同步正在进行中，请等待完成")
    request = {
        "requested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": "web",
        "request_id": str(uuid.uuid4()),
    }
    SYNC_REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    SYNC_REQUEST_PATH.write_text(
        json.dumps(request, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {"requested": True, "request_id": request["request_id"]}


def _parse_status_time(value: Any) -> datetime | None:
    """Parse an ISO-8601 status timestamp, normalizing naive → UTC. None if unparseable."""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _orchestrator_alive(status: dict[str, Any], max_age_seconds: int = 300) -> bool:
    """True if the orchestrator is actively running or finished/failed recently.

    A stale sync-status.json left by a dead/stuck ops container must NOT report
    the orchestrator as available (the old `setdefault(True)` did, whenever the
    file merely existed).

    Phase A: guardian_heartbeat_at (refreshed by mirror_ops every poll cycle) is
    the authoritative liveness signal — when present, freshness within
    GUARDIAN_HEARTBEAT_TTL_SECONDS decides alive/dead. When absent (older Mirror
    build), fall back to the finished_at heuristic.
    """
    if status.get("state") == "running":
        return True
    heartbeat = status.get("guardian_heartbeat_at")
    if heartbeat:
        moment = _parse_status_time(heartbeat)
        if moment is not None:
            return (
                datetime.now(timezone.utc) - moment
            ).total_seconds() < GUARDIAN_HEARTBEAT_TTL_SECONDS
    finished = status.get("finished_at")
    if not finished:
        return False
    moment = _parse_status_time(finished)
    if moment is None:
        return False
    return (datetime.now(timezone.utc) - moment).total_seconds() < max_age_seconds


@app.get("/api/euvd/sync-status")
async def mirror_sync_status() -> dict[str, Any]:
    if not SYNC_STATUS_PATH.exists():
        return {
            "state": "idle",
            "stage": "",
            "error": "",
            "orchestrator_available": False,
        }
    try:
        status = json.loads(SYNC_STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"state": "idle", "stage": "", "error": "status unreadable"}
    status["orchestrator_available"] = _orchestrator_alive(status)
    return status


@app.get("/api/euvd/records")
async def list_euvd_records(
    page: int = 1,
    page_size: int = 50,
    sort: str = "euvd_id_desc",
    q: str = "",
    actively_exploited_only: bool = False,
) -> dict[str, Any]:
    """改进1：EUVD 目录列表 + 搜索（只读快照查询，绝不联网，绝不写快照）。
    actively_exploited_only=true 时只返回积极利用漏洞（KEV∪exploitedSince）。"""
    try:
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="page/page_size 必须为整数") from exc
    result = await asyncio.to_thread(
        EuvdClient.list_euvd_records,
        page,
        page_size,
        sort,
        q,
        bool(actively_exploited_only),
    )
    if result is None:
        raise HTTPException(status_code=503, detail="本地 EUVD 快照不可用或哈希失配")
    status = await asyncio.to_thread(EuvdClient.local_snapshot_status)
    result["freshness"] = {
        "last_successful_to_date": (status or {}).get("last_successful_to_date", ""),
        "reference_data_freshness": (status or {}).get("reference_data_freshness", ""),
        "vulnerability_count": (status or {}).get("vulnerability_count", 0),
    }
    return result


def _get_case_or_404(case_id: str) -> dict[str, Any]:
    try:
        return WORKFLOW_STORE.get_case(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Art.14 案件不存在") from exc


def _case_response(case: dict[str, Any]) -> dict[str, Any]:
    return {
        **case,
        "deadlines": deadline_status(case),
        "srp_readiness": {
            stage: srp_readiness(case, stage) for stage in sorted(SRP_STAGES)
        },
    }


@app.get("/api/reviewers")
async def list_reviewers() -> dict[str, Any]:
    return {"reviewers": await asyncio.to_thread(WORKFLOW_STORE.list_reviewers)}


@app.post("/api/reviewers")
async def create_reviewer(request: ReviewerCreateRequest) -> dict[str, Any]:
    try:
        reviewer = await asyncio.to_thread(
            WORKFLOW_STORE.create_reviewer,
            request.display_name,
            request.role,
            request.pin,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return reviewer


@app.get("/api/art14/cases")
async def list_art14_cases() -> dict[str, Any]:
    cases = await asyncio.to_thread(WORKFLOW_STORE.list_cases)
    return {"cases": [_case_response(item) for item in cases]}


@app.post("/api/art14/cases")
async def create_manual_art14_case(request: ManualCaseRequest) -> dict[str, Any]:
    try:
        case = await asyncio.to_thread(
            WORKFLOW_STORE.create_manual_case,
            request.model_dump(exclude={"actor"}),
            request.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.post("/api/art14/cases/from-finding")
async def create_art14_case_from_finding(
    request: CaseFromFindingRequest,
) -> dict[str, Any]:
    path = _job_path(request.job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    job = _read_json(path)
    try:
        case = await asyncio.to_thread(
            WORKFLOW_STORE.create_case_from_finding,
            job,
            request.finding_index,
            request.actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.get("/api/art14/cases/{case_id}")
async def get_art14_case(case_id: str) -> dict[str, Any]:
    return _case_response(await asyncio.to_thread(_get_case_or_404, case_id))


@app.patch("/api/art14/cases/{case_id}")
async def update_art14_case(
    case_id: str,
    request: CaseUpdateRequest,
) -> dict[str, Any]:
    try:
        case = await asyncio.to_thread(
            WORKFLOW_STORE.update_case,
            case_id,
            request.updates,
            request.actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Art.14 案件不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.post("/api/art14/cases/{case_id}/evidence")
async def add_art14_evidence(
    case_id: str,
    request: EvidenceRequest,
) -> dict[str, Any]:
    try:
        case = await asyncio.to_thread(
            WORKFLOW_STORE.add_evidence,
            case_id,
            request.model_dump(exclude={"actor"}),
            request.actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Art.14 案件不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.post("/api/art14/cases/{case_id}/awareness")
async def confirm_art14_awareness(
    case_id: str,
    request: AwarenessRequest,
) -> dict[str, Any]:
    try:
        reviewer = await asyncio.to_thread(
            WORKFLOW_STORE.verify_reviewer,
            request.reviewer_id,
            request.pin,
            {"manufacturer_authorized", "compliance"},
        )
        actor = f"{reviewer['display_name']} [{reviewer['id']}]"
        case = await asyncio.to_thread(
            WORKFLOW_STORE.confirm_awareness,
            case_id,
            request.awareness_at,
            actor,
            request.confirmation,
            request.basis,
            request.evidence_refs,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Art.14 案件不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.post("/api/art14/cases/{case_id}/review")
async def review_art14_case(
    case_id: str,
    request: ReviewRequest,
) -> dict[str, Any]:
    roles = (
        {"technical", "manufacturer_authorized"}
        if request.stage == "technical"
        else {"compliance", "manufacturer_authorized"}
    )
    try:
        reviewer = await asyncio.to_thread(
            WORKFLOW_STORE.verify_reviewer,
            request.reviewer_id,
            request.pin,
            roles,
        )
        case = await asyncio.to_thread(
            WORKFLOW_STORE.review_case,
            case_id,
            request.stage,
            reviewer["display_name"],
            reviewer["id"],
            request.decision,
            request.rationale,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Art.14 案件不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.post("/api/art14/cases/{case_id}/submission")
async def record_art14_submission(
    case_id: str,
    request: SubmissionRequest,
) -> dict[str, Any]:
    try:
        reviewer = await asyncio.to_thread(
            WORKFLOW_STORE.verify_reviewer,
            request.reviewer_id,
            request.pin,
            {"manufacturer_authorized"},
        )
        actor = f"{reviewer['display_name']} [{reviewer['id']}]"
        case = await asyncio.to_thread(
            WORKFLOW_STORE.mark_submitted,
            case_id,
            actor,
            request.stage,
            request.submitted_at,
            request.receipt,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Art.14 案件不存在") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return _case_response(case)


@app.post("/api/vex/import")
async def import_vex(
    file: UploadFile = File(...),
    receipt: UploadFile = File(...),
    issuer_id: str = Form(...),
    actor: str = Form(default="local analyst"),
) -> dict[str, Any]:
    """Import a VEX document bound to a trusted Workbench M8-1 intake receipt.

    Trust anchor (simplified): EUVD re-derives vex_document_sha256 +
    statements_canonical_sha256 (byte-exact to Workbench) and checks the issuer
    is ADMITTED in the allowlist. Does NOT re-verify the cosign signature
    (trusts Workbench already did). Bare VEX without receipt is rejected (HTTP
    400) — eliminates the vendor-self-signed-VEX bypass anti-pattern.
    """
    original_name = Path(file.filename or "vex.json").name
    if Path(original_name).suffix.casefold() != ".json":
        raise HTTPException(status_code=400, detail="VEX 仅支持 JSON 文件")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="VEX 文件不能超过 20 MB")
    receipt_bytes = await receipt.read(MAX_UPLOAD_BYTES + 1)
    if len(receipt_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="receipt 文件不能超过 20 MB")
    try:
        receipt_doc = json.loads(receipt_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail=f"receipt.json 解析失败: {exc}"
        ) from exc
    try:
        validated_statements = await asyncio.to_thread(
            verify_vex_intake_receipt, content, receipt_doc, issuer_id
        )
    except VexIntakeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"VEX receipt 信任锚验证失败: {exc}",
        ) from exc
    try:
        parsed = await asyncio.to_thread(parse_vex_bytes, content)
        digest = hashlib.sha256(content).hexdigest()
        import_id = await asyncio.to_thread(
            WORKFLOW_STORE.record_vex_import,
            parsed["format"],
            parsed["document_id"],
            original_name,
            digest,
            actor,
            len(parsed["entries"]),
            parsed["warnings"],
            receipt_doc["vex_document_sha256"],
            receipt_doc["statements_canonical_sha256"],
            issuer_id,
        )
        cases = [
            await asyncio.to_thread(
                WORKFLOW_STORE.create_case_from_vex,
                entry,
                import_id,
                actor,
            )
            for entry in parsed["entries"]
        ]
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc
    return {
        "import_id": import_id,
        "format": parsed["format"],
        "document_id": parsed["document_id"],
        "source_sha256": digest,
        "warnings": parsed["warnings"],
        "cases": [_case_response(item) for item in cases],
        "receipt_vex_document_sha256": receipt_doc["vex_document_sha256"],
        "receipt_statements_canonical_sha256": receipt_doc["statements_canonical_sha256"],
        "issuer_id": issuer_id,
        "validated_statement_count": len(validated_statements),
    }


def _safe_export_path(case_id: str, label: str, extension: str) -> Path:
    _canonical_uuid_text(case_id, "case_id")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}", label):
        raise HTTPException(status_code=400, detail="导出标签无效")
    allowed_extensions = {"json", "xlsx", "html", "zip"}
    if extension not in allowed_extensions:
        raise HTTPException(status_code=400, detail="导出格式无效")
    output_root = OUTPUT_DIR.resolve()
    candidate = (output_root / f"export-{uuid.uuid4().hex}.{extension}").resolve()
    if candidate.parent != output_root:
        raise HTTPException(status_code=400, detail="导出路径无效")
    return candidate


@app.get("/api/art14/cases/{case_id}/vex/{vex_format}")
async def export_case_vex(case_id: str, vex_format: str) -> FileResponse:
    if vex_format not in {"cyclonedx", "csaf"}:
        raise HTTPException(status_code=400, detail="VEX 格式必须是 cyclonedx 或 csaf")
    case = await asyncio.to_thread(_get_case_or_404, case_id)
    if case.get("case_type") == "severe_incident":
        raise HTTPException(status_code=409, detail="严重安全事件案件不适用 VEX 导出")
    path = _safe_export_path(case_id, f"vex-{vex_format}", "json")
    try:
        await asyncio.to_thread(write_vex, path, case, vex_format)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=repair_text(exc)) from exc
    return FileResponse(
        path,
        media_type="application/json",
        filename=f"{case_id}_vex-{vex_format}.json",
    )


@app.get("/api/art14/cases/{case_id}/srp/{stage}")
async def get_srp_draft(case_id: str, stage: str) -> dict[str, Any]:
    if stage not in SRP_STAGES:
        raise HTTPException(status_code=400, detail="SRP 阶段无效")
    case = await asyncio.to_thread(_get_case_or_404, case_id)
    return build_srp_payload(case, stage)


@app.get("/api/art14/cases/{case_id}/srp/{stage}/export/{extension}")
async def export_srp_draft(
    case_id: str,
    stage: str,
    extension: str,
) -> FileResponse:
    if stage not in SRP_STAGES or extension not in {"json", "xlsx", "html"}:
        raise HTTPException(status_code=400, detail="SRP 导出阶段或格式无效")
    case = await asyncio.to_thread(_get_case_or_404, case_id)
    path = _safe_export_path(case_id, f"srp-{stage}", extension)
    writer = {
        "json": write_srp_json,
        "xlsx": write_srp_xlsx,
        "html": write_srp_html,
    }[extension]
    await asyncio.to_thread(writer, path, case, stage)
    media_type = {
        "json": "application/json",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "html": "text/html",
    }[extension]
    return FileResponse(
        path,
        media_type=media_type,
        filename=f"{case_id}_srp-{stage}.{extension}",
    )


@app.get("/api/art14/cases/{case_id}/srp/{stage}/package.zip")
async def export_srp_submission_package(case_id: str, stage: str) -> FileResponse:
    if stage not in SRP_STAGES:
        raise HTTPException(status_code=400, detail="SRP 阶段无效")
    case = await asyncio.to_thread(_get_case_or_404, case_id)
    path = _safe_export_path(case_id, f"srp-{stage}-assisted-package", "zip")
    try:
        await asyncio.to_thread(write_srp_submission_package_zip, path, case, stage)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=repair_text(exc)) from exc
    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"{case_id}_srp-{stage}-assisted-package.zip",
    )


@app.post("/api/uploads/preview")
async def upload_preview(
    file: UploadFile = File(...),
    receipt: UploadFile | None = None,
) -> dict[str, Any]:
    original_name = Path(file.filename or "sbom").name
    suffix = Path(original_name).suffix.casefold()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail="仅支持 .xlsx、.xlsm、.csv、.tsv 和 CycloneDX .json",
        )

    upload_id = str(uuid.uuid4())
    target = UPLOAD_DIR / f"{upload_id}{suffix}"
    size = 0
    digest = hashlib.sha256()
    upload_limit = (
        MAX_CYCLONEDX_UPLOAD_BYTES if suffix == ".json" else MAX_UPLOAD_BYTES
    )
    with target.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > upload_limit:
                output.close()
                target.unlink(missing_ok=True)
                limit_mb = upload_limit // (1024 * 1024)
                raise HTTPException(
                    status_code=413,
                    detail=f"该格式文件不能超过 {limit_mb} MB",
                )
            digest.update(chunk)
            output.write(chunk)

    # Optional SBOM Workbench handoff receipt (co-located as {id}.receipt.json
    # so _extract_handoff_binding can find it next to the CycloneDX file).
    # Source code never enters EUVD; the receipt only carries boundary
    # declarations (classification / direction / hashes).
    receipt_path: Path | None = None
    if receipt is not None and receipt.filename:
        receipt_path = UPLOAD_DIR / f"{upload_id}.receipt.json"
        receipt_size = 0
        try:
            with receipt_path.open("wb") as r_out:
                while r_chunk := await receipt.read(1024 * 1024):
                    receipt_size += len(r_chunk)
                    if receipt_size > MAX_UPLOAD_BYTES:
                        r_out.close()
                        raise HTTPException(
                            status_code=413,
                            detail=f"receipt 不能超过 {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
                        )
                    r_out.write(r_chunk)
        except HTTPException:
            target.unlink(missing_ok=True)
            receipt_path.unlink(missing_ok=True)
            raise
        except OSError as exc:
            target.unlink(missing_ok=True)
            receipt_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=500,
                detail=f"receipt 写入失败: {repair_text(exc)}",
            ) from exc

    try:
        parsed = await asyncio.to_thread(read_sbom, target)
    except (ValueError, OSError, json.JSONDecodeError, RecursionError) as exc:
        target.unlink(missing_ok=True)
        if receipt_path is not None:
            receipt_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=repair_text(exc)) from exc

    if len(parsed["rows"]) > MAX_COMPONENTS:
        target.unlink(missing_ok=True)
        raise HTTPException(
            status_code=413,
            detail=f"组件数超过限制 {MAX_COMPONENTS}，未保存上传记录",
        )

    serializable_rows = [
        {header: repair_text(row.get(header)) for header in parsed["headers"]}
        for row in parsed["rows"]
    ]
    source_sha256 = digest.hexdigest()
    full_summary = parsed.get("pre7_evidence_summary") or {}
    evidence_path = UPLOAD_DIR / f"{upload_id}.pre7-evidence.json"
    evidence_payload = {
        "artifact_type": "PRE-7 artifact-field inventory",
        "automatic_conformity_decision": False,
        "source_document_reference": {
            "file_name": target.name,
            "original_name": original_name,
            "sha256": source_sha256,
            "preserved": True,
        },
        "document_identity": parsed.get("document_identity") or {},
        "pre7_evidence_summary": full_summary,
        "warnings": parsed.get("warnings") or [],
    }
    try:
        await asyncio.to_thread(_write_json, evidence_path, evidence_payload)
        evidence_sha256 = await asyncio.to_thread(_sha256_file, evidence_path)
    except OSError as exc:
        target.unlink(missing_ok=True)
        evidence_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail=f"证据制品写入失败: {repair_text(exc)}",
        ) from exc
    rq07_items = (
        ((full_summary.get("requirements") or {}).get("PRE-7-RQ-07") or {}).get(
            "items"
        )
        or []
    )
    evidence_reference = {
        "file_name": evidence_path.name,
        "sha256": evidence_sha256,
        "contains_item_level_observations": bool(rq07_items),
    }
    compact_summary = _compact_pre7_evidence(full_summary, evidence_reference)
    parsed_for_record = dict(parsed)
    parsed_for_record["rows"] = serializable_rows
    parsed_for_record["warnings"] = list(parsed.get("warnings") or [])[:100]
    parsed_for_record["warning_count"] = len(parsed.get("warnings") or [])
    parsed_for_record["pre7_evidence_summary"] = compact_summary
    for duplicated_field in (
        "source_document",
        "source_components",
        "sbom_metadata",
        "dependencies",
    ):
        parsed_for_record.pop(duplicated_field, None)
    record = {
        "id": upload_id,
        "original_name": original_name,
        "stored_file": str(target),
        "uploaded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_sha256": source_sha256,
        "source_document_reference": {
            "file_name": target.name,
            "sha256": source_sha256,
            "preserved": True,
        },
        "pre7_evidence_artifact": evidence_reference,
        "parsed": parsed_for_record,
    }
    try:
        await asyncio.to_thread(_write_json, _upload_record_path(upload_id), record)
    except OSError as exc:
        target.unlink(missing_ok=True)
        evidence_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail=f"上传记录写入失败: {repair_text(exc)}",
        ) from exc
    warnings = list(parsed.get("warnings") or [])
    rq06 = (compact_summary.get("requirements") or {}).get("PRE-7-RQ-06") or {}
    return {
        "upload_id": upload_id,
        "file_name": original_name,
        "kind": parsed["kind"],
        "sheet": parsed["sheet"],
        "header_row": parsed["header_row"],
        "headers": parsed["headers"],
        "mapping": parsed["mapping"],
        "row_count": len(serializable_rows),
        "source_sha256": source_sha256,
        "preview_rows": serializable_rows[:8],
        "spec_version": parsed.get("spec_version") or "",
        "serial_number": parsed.get("serial_number") or "",
        "bom_version": parsed.get("bom_version"),
        "document_identity": parsed.get("document_identity") or {},
        "sbom_metadata_observations": rq06.get("evidence_observations") or {},
        "dependency_count": len(parsed.get("dependencies") or [])
        if isinstance(parsed.get("dependencies"), list)
        else 0,
        "warnings": warnings[:100],
        "warning_count": len(warnings),
        "source_document_reference": record["source_document_reference"],
        "pre7_evidence_artifact": evidence_reference,
        "pre7_evidence_summary": compact_summary,
        "automatic_conformity_decision": False,
        "metadata_binding": parsed.get("metadata_binding"),
    }


@app.post("/api/jobs")
async def create_job(request: MatchRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    record_path = _upload_record_path(request.upload_id)
    if not record_path.exists():
        record_path = _legacy_upload_record_path(request.upload_id)
    if not record_path.exists():
        raise HTTPException(status_code=404, detail="上传记录不存在，请重新上传")
    upload_record = _read_json(record_path)
    headers = set(upload_record["parsed"]["headers"])
    for field, header in request.mapping.items():
        if header and header not in headers:
            raise HTTPException(status_code=400, detail=f"列映射无效: {field}")
    if not any(request.mapping.get(field) for field in ("name", "cve", "euvd")):
        raise HTTPException(status_code=400, detail="必须选择组件名称、CVE 或 EUVD ID 列之一")

    job_id = _idempotent_job_id(request.upload_id, request.mapping)
    job_path = _job_path(job_id)
    if job_path.exists():
        existing = _read_json(job_path)
        # Idempotent reuse: a duplicate submit of the same upload + mapping
        # returns the active job instead of spawning a new one. A failed or
        # cancelled job falls through and is overwritten (re-created) below.
        if existing.get("status") in {"queued", "running", "completed"}:
            return _public_job(existing)
    job = {
        "id": job_id,
        "upload_id": request.upload_id,
        "mapping": dict(request.mapping),
        "file_name": upload_record["original_name"],
        "source_sha256": upload_record.get("source_sha256") or "",
        "sbom_format": (upload_record.get("parsed") or {}).get("kind") or "",
        "sbom_version": (upload_record.get("parsed") or {}).get("bom_version") or "",
        "sbom_spec_version": (upload_record.get("parsed") or {}).get("spec_version") or "",
        "sbom_serial_number": (upload_record.get("parsed") or {}).get("serial_number") or "",
        "sbom_document_identity": (upload_record.get("parsed") or {}).get("document_identity") or {},
        "pre7_evidence_summary": (upload_record.get("parsed") or {}).get("pre7_evidence_summary") or {},
        "sbom_source_declarations": (
            ((upload_record.get("parsed") or {}).get("metadata_binding") or {}).get("evidence")
            or {}
        ),
        "project_name": repair_text(request.project_name)
        or _safe_name(upload_record["original_name"]),
        "project_version": repair_text(request.project_version),
        "software_build": repair_text(request.software_build),
        "customer": repair_text(request.customer),
        "status": "queued",
        "stage": "排队中",
        "progress": 0,
        "completed": 0,
        "total": 0,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    _write_json(job_path, job)
    background_tasks.add_task(_run_job, job_id, upload_record, request.mapping)
    return _public_job(job)


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    path = _job_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="任务不存在")
    return _public_job(_read_json(path))



@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str) -> dict[str, Any]:
    path = _job_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="任务不存在")
    job = _read_json(path)
    if job.get("status") not in {"queued", "running"}:
        raise HTTPException(
            status_code=409, detail=f"任务状态 {job.get('status')} 不可取消"
        )
    # Mark canceling; _run_job's progress callback observes it between components
    # and aborts. A queued job that never started is cancelled immediately.
    job.update({"status": "canceling", "stage": "正在取消"})
    _write_json(path, job)
    return _public_job(job)


@app.post("/api/jobs/{job_id}/retry")
async def retry_job(job_id: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    path = _job_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="任务不存在")
    job = _read_json(path)
    if job.get("status") not in {"failed", "cancelled"}:
        raise HTTPException(
            status_code=409, detail=f"任务状态 {job.get('status')} 不可重试"
        )
    record_path = _upload_record_path(job.get("upload_id") or "")
    if not record_path.exists():
        record_path = _legacy_upload_record_path(job.get("upload_id") or "")
    if not record_path.exists():
        raise HTTPException(status_code=404, detail="上传记录已删除，请重新上传")
    upload_record = _read_json(record_path)
    job.update(
        {
            "status": "queued",
            "stage": "排队中",
            "progress": 0,
            "completed": 0,
            "total": 0,
            "error": "",
            "finished_at": None,
            "result": None,
            "report_name": None,
            "report_path": None,
        }
    )
    _write_json(path, job)
    background_tasks.add_task(
        _run_job, job_id, upload_record, job.get("mapping") or {}
    )
    return _public_job(job)


@app.get("/api/jobs/{job_id}/report")
async def download_report(job_id: str) -> FileResponse:
    path = _job_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="任务不存在")
    job = _read_json(path)
    if job.get("status") != "completed" or not job.get("report_path"):
        raise HTTPException(status_code=409, detail="报告尚未生成")
    report_path = Path(job["report_path"]).resolve()
    output_root = OUTPUT_DIR.resolve()
    if report_path.parent != output_root:
        raise HTTPException(status_code=400, detail="报告路径无效")
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="报告文件不存在")
    return FileResponse(
        report_path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=job["report_name"],
    )


@app.get("/api/jobs/{job_id}/evidence-package")
async def download_evidence_package(job_id: str, format: str = "zip") -> Response:
    """Phase B compliance evidence bundle (manifest + evidence.json + evidence.xlsx
    + audit_trail.json as ZIP; or ?format=json / xlsx). Fail-closed: if the SBOM
    re-hash does not match the recorded source_sha256, returns 422 rather than
    shipping a bundle whose integrity root is broken."""
    path = _job_path(job_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="任务不存在")
    job = _read_json(path)
    if job.get("status") != "completed":
        raise HTTPException(status_code=409, detail="证据包需任务完成后生成")
    payload = build_evidence_package_payload(job, WORKFLOW_STORE, UPLOAD_DIR)
    integrity = payload.get("sbom_integrity") or {}
    if integrity.get("rehash_sha256") is not None and integrity.get("match") is False:
        raise HTTPException(
            status_code=422,
            detail=(
                f"SBOM 完整性校验失败：rehash {integrity.get('rehash_sha256')} "
                f"≠ source {integrity.get('source_sha256')}"
            ),
        )
    safe_name = re.sub(r"[^0-9A-Za-z._-]", "_", job.get("project_name") or job_id)
    fmt = (format or "zip").lower()
    if fmt == "json":
        return JSONResponse(payload)
    if fmt == "xlsx":
        return Response(
            content=write_evidence_xlsx(payload),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f'attachment; filename="EUVDevidence_{safe_name}.xlsx"'
            },
        )
    return Response(
        content=write_evidence_package_zip(payload),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="EUVDevidence_{safe_name}.zip"'
        },
    )


@app.get("/api/template")
async def download_template() -> Response:
    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if SBOM_TEMPLATE_PATH.is_file():
        return FileResponse(
            SBOM_TEMPLATE_PATH,
            media_type=media_type,
            filename=SBOM_TEMPLATE_PATH.name,
        )
    payload = await asyncio.to_thread(template_bytes)
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": (
                "attachment; filename=sbom-import-template.xlsx; "
                f"filename*=UTF-8''{quote(PUBLIC_TEMPLATE_FILENAME)}"
            )
        },
    )


def _purge_old_uploads(
    upload_dir: Path, purge_days: int, dry_run: bool = False
) -> list[str]:
    """Delete uploads older than purge_days. Returns the names of files older
    than the cutoff (deleted unless dry_run). purge_days<=0 disables. Extracted
    from the startup hook so it is unit-testable (审查中危: 原 startup 删 7 天
    上传无 dry-run, 静默删)."""
    if purge_days <= 0:
        return []
    cutoff = datetime.now().timestamp() - purge_days * 24 * 3600
    purged: list[str] = []
    for path in upload_dir.iterdir():
        if path.is_file() and path.stat().st_mtime < cutoff:
            purged.append(path.name)
            if not dry_run:
                path.unlink(missing_ok=True)
    return purged


@app.on_event("startup")
async def cleanup_old_uploads() -> None:
    global _feed_refresh_task
    purge_days = int(os.getenv("STARTUP_PURGE_DAYS", "7"))
    dry_run = os.getenv("STARTUP_PURGE_DRY_RUN", "") == "1"
    purged = _purge_old_uploads(UPLOAD_DIR, purge_days, dry_run)
    if purged:
        print(
            f"[startup] purge {len(purged)} upload(s) older than {purge_days} "
            f"day(s) (dry_run={dry_run}): {', '.join(purged[:10])}"
            f"{' ...' if len(purged) > 10 else ''}",
            flush=True,
        )
    for job_path in JOB_DIR.glob("*.json"):
        try:
            job = _read_json(job_path)
        except (OSError, json.JSONDecodeError):
            continue
        if job.get("status") in {"queued", "running"}:
            job.update(
                {
                    "status": "failed",
                    "stage": "服务重启后中断，请重新扫描",
                    "error": "后台扫描未在服务重启后自动恢复",
                    "finished_at": datetime.now().astimezone().isoformat(
                        timespec="seconds"
                    ),
                }
            )
            _write_json(job_path, job)
        elif job.get("status") == "completed":
            # Idempotent v2.1 -> v2.2 migration: keep legacy job JSON readable
            # while registering its stable product/SBOM identity in SQLite.
            await asyncio.to_thread(
                WORKFLOW_STORE.register_sbom_snapshot,
                job,
                str(job.get("source_sha256") or ""),
                str(job.get("sbom_format") or ""),
                str(job.get("sbom_version") or ""),
            )

    async def scheduled_refresh() -> None:
        while True:
            try:
                await _refresh_and_record_feeds(force=False)
            except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError):
                pass
            await asyncio.sleep(24 * 3600)

    _feed_refresh_task = asyncio.create_task(scheduled_refresh())


@app.on_event("shutdown")
async def stop_background_refresh() -> None:
    if _feed_refresh_task:
        _feed_refresh_task.cancel()


app.mount("/", StaticFiles(directory=APP_DIR / "static", html=True), name="static")
