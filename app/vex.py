from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CYCLONEDX_STATE_TO_INTERNAL = {
    "exploitable": "known_affected",
    "in_triage": "under_investigation",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "false_positive": "known_not_affected",
    "not_affected": "known_not_affected",
}
INTERNAL_TO_CYCLONEDX_STATE = {
    "known_affected": "exploitable",
    "under_investigation": "in_triage",
    "known_not_affected": "not_affected",
    "fixed": "resolved",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _product_lookup(payload: dict[str, Any]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    tree = payload.get("product_tree") or {}
    for item in tree.get("full_product_names") or []:
        product_id = str(item.get("product_id") or "")
        name = str((item.get("name") or product_id))
        if product_id:
            lookup[product_id] = name
    return lookup


def _parse_cyclonedx(payload: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[str]]:
    spec = str(payload.get("specVersion") or "")
    if payload.get("bomFormat") != "CycloneDX" or spec not in {"1.5", "1.6", "1.7"}:
        raise ValueError("仅支持 CycloneDX 1.5/1.6/1.7 VEX JSON")
    metadata_component = (payload.get("metadata") or {}).get("component") or {}
    default_product = str(
        metadata_component.get("name")
        or metadata_component.get("bom-ref")
        or "CycloneDX产品"
    )
    default_version = str(metadata_component.get("version") or "")
    document_id = str(payload.get("serialNumber") or uuid.uuid4())
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    for vulnerability in payload.get("vulnerabilities") or []:
        vulnerability_id = str(vulnerability.get("id") or "").upper()
        analysis = vulnerability.get("analysis") or {}
        state = CYCLONEDX_STATE_TO_INTERNAL.get(
            str(analysis.get("state") or ""), "under_investigation"
        )
        affects = vulnerability.get("affects") or [{}]
        if not affects:
            affects = [{}]
        for affected in affects:
            product_id = str(affected.get("ref") or metadata_component.get("bom-ref") or "")
            entries.append(
                {
                    "format": f"cyclonedx-{spec}",
                    "vulnerability_id": vulnerability_id,
                    "cve_id": vulnerability_id if vulnerability_id.startswith("CVE-") else "",
                    "euvd_id": vulnerability_id if vulnerability_id.startswith("EUVD-") else "",
                    "product_id": product_id,
                    "product_name": default_product,
                    "product_version": default_version,
                    "status": state,
                    "justification": str(analysis.get("justification") or ""),
                    "detail": str(analysis.get("detail") or ""),
                }
            )
        if state == "known_not_affected" and not (
            analysis.get("justification") or analysis.get("detail")
        ):
            warnings.append(f"{vulnerability_id}: known_not_affected 缺少理由")
    return document_id, entries, warnings


def _parse_csaf(payload: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[str]]:
    document = payload.get("document") or {}
    if str(document.get("category") or "").casefold() != "vex":
        raise ValueError("仅支持 CSAF 2.0 VEX Profile JSON")
    document_id = str((document.get("tracking") or {}).get("id") or uuid.uuid4())
    product_names = _product_lookup(payload)
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    for vulnerability in payload.get("vulnerabilities") or []:
        cve_id = str(vulnerability.get("cve") or "").upper()
        statuses = vulnerability.get("product_status") or {}
        notes = " ".join(
            str(note.get("text") or "") for note in vulnerability.get("notes") or []
        ).strip()
        for status in (
            "known_affected",
            "known_not_affected",
            "fixed",
            "under_investigation",
        ):
            for product_id in statuses.get(status) or []:
                entries.append(
                    {
                        "format": "csaf-2.0",
                        "vulnerability_id": cve_id,
                        "cve_id": cve_id,
                        "euvd_id": "",
                        "product_id": str(product_id),
                        "product_name": product_names.get(str(product_id), str(product_id)),
                        "product_version": "",
                        "status": status,
                        "justification": notes,
                        "detail": notes,
                    }
                )
                if status == "known_not_affected" and not notes:
                    warnings.append(f"{cve_id}/{product_id}: known_not_affected 缺少理由")
    return document_id, entries, warnings


def parse_vex_bytes(content: bytes) -> dict[str, Any]:
    payload = json.loads(content)
    if not isinstance(payload, dict):
        raise ValueError("VEX 根节点必须为 JSON 对象")
    if payload.get("bomFormat") == "CycloneDX":
        document_id, entries, warnings = _parse_cyclonedx(payload)
        vex_format = f"cyclonedx-{payload.get('specVersion') or '1.7'}"
    else:
        document_id, entries, warnings = _parse_csaf(payload)
        vex_format = "csaf-2.0"
    seen: dict[tuple[str, str], str] = {}
    for entry in entries:
        key = (
            str(entry.get("vulnerability_id") or ""),
            str(entry.get("product_id") or ""),
        )
        previous = seen.get(key)
        if previous and previous != entry.get("status"):
            raise ValueError(
                f"同一漏洞/产品存在冲突 VEX 状态: {key[0]} / {key[1]}"
            )
        seen[key] = str(entry.get("status") or "")
        if entry.get("status") == "known_not_affected" and not str(
            entry.get("justification") or entry.get("detail") or ""
        ).strip():
            entry["status"] = "under_investigation"
            entry["justification"] = (
                "known_not_affected 缺少产品级理由，已降级为 under_investigation"
            )
    if not entries:
        warnings.append("VEX 中未发现可导入的漏洞产品状态")
    return {
        "format": vex_format,
        "document_id": document_id,
        "entries": entries,
        "warnings": warnings,
    }


def build_cyclonedx_vex(case: dict[str, Any]) -> dict[str, Any]:
    vulnerability_id = (
        case.get("cve_id") or case.get("euvd_id") or f"CRA-CASE-{case['id']}"
    )
    if (
        case.get("applicability_status") == "known_not_affected"
        and not case.get("applicability_justification")
    ):
        raise ValueError("known_not_affected 导出必须包含产品级理由")
    product_ref = f"product:{case['id']}"
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "component": {
                "type": "application",
                "bom-ref": product_ref,
                "name": case.get("project_name") or "Product",
                "version": case.get("project_version") or "unknown",
            },
            "properties": [
                {"name": "cra:case-id", "value": case["id"]},
                {"name": "cra:draft-only", "value": "true"},
            ],
        },
        "vulnerabilities": [
            {
                "id": vulnerability_id,
                "source": {"name": "ENISA EUVD / customer assessment"},
                "affects": [{"ref": product_ref}],
                "analysis": {
                    "state": INTERNAL_TO_CYCLONEDX_STATE.get(
                        case.get("applicability_status"), "in_triage"
                    ),
                    "detail": case.get("applicability_justification")
                    or "Product applicability remains under investigation.",
                    "lastUpdated": _now(),
                },
                "properties": [
                    {"name": "cra:art14-decision", "value": case.get("art14_decision") or "not_assessed"},
                    {"name": "cra:four-eye-status", "value": case.get("workflow_status") or "draft"},
                ],
            }
        ],
    }


def build_csaf_vex(case: dict[str, Any]) -> dict[str, Any]:
    cve_id = case.get("cve_id") or ""
    if (
        case.get("applicability_status") == "known_not_affected"
        and not case.get("applicability_justification")
    ):
        raise ValueError("known_not_affected 导出必须包含产品级理由")
    product_id = f"CSAFPID-{case['id']}"
    status = case.get("applicability_status") or "under_investigation"
    vulnerability: dict[str, Any] = {
        "notes": [
            {
                "category": "details",
                "title": "Product applicability",
                "text": case.get("applicability_justification")
                or "Under investigation",
            }
        ],
        "product_status": {status: [product_id]},
    }
    if cve_id:
        vulnerability["cve"] = cve_id
    return {
        "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
        "document": {
            "category": "vex",
            "csaf_version": "2.0",
            "lang": "en",
            "publisher": {
                "category": "vendor",
                "name": (case.get("srp_fields") or {}).get("manufacturer_name")
                or "Manufacturer review required",
                "namespace": "https://example.invalid/cra-vex",
            },
            "title": f"VEX draft for {case.get('project_name') or 'product'}",
            "tracking": {
                "current_release_date": _now(),
                "id": f"CRA-VEX-{case['id']}",
                "initial_release_date": _now(),
                "revision_history": [
                    {"date": _now(), "number": "1", "summary": "Initial draft"}
                ],
                "status": "draft",
                "version": "1",
            },
            "notes": [
                {
                    "category": "legal_disclaimer",
                    "title": "Scope",
                    "text": "Draft generated for human review; it is not an automatic CRA Article 14 decision or SRP submission.",
                }
            ],
        },
        "product_tree": {
            "full_product_names": [
                {
                    "name": " ".join(
                        value
                        for value in [
                            case.get("project_name"),
                            case.get("project_version"),
                        ]
                        if value
                    ),
                    "product_id": product_id,
                }
            ]
        },
        "vulnerabilities": [vulnerability],
    }


def write_vex(path: Path, case: dict[str, Any], vex_format: str) -> None:
    if vex_format == "cyclonedx":
        payload = build_cyclonedx_vex(case)
    elif vex_format == "csaf":
        payload = build_csaf_vex(case)
    else:
        raise ValueError("VEX 导出格式无效")
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
