from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from .spreadsheet_io import _safe_cell


SRP_STAGES = {"early-warning", "notification", "final-report"}


def _parse_aware(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return parsed.astimezone(timezone.utc)


def deadline_status(case: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    aware = _parse_aware(case.get("awareness_at"))
    corrective = _parse_aware(case.get("corrective_measure_available_at"))
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    def item(due: datetime | None) -> dict[str, Any]:
        if due is None:
            return {"due_at": None, "status": "not_started", "remaining_seconds": None}
        remaining = int((due - current).total_seconds())
        return {
            "due_at": due.isoformat(timespec="seconds"),
            "status": "overdue" if remaining < 0 else "open",
            "remaining_seconds": remaining,
        }

    return {
        "basis": {
            "awareness_is_manually_confirmed": bool(
                case.get("awareness_at") and case.get("awareness_confirmed_by")
            ),
            "automatic_awareness_inference": False,
            "reporting_rule": "without undue delay and no later than the calculated deadline",
            "final_report_basis": "14 days after a corrective or mitigating measure is available",
        },
        "early_warning_24h": item(aware + timedelta(hours=24) if aware else None),
        "notification_72h": item(aware + timedelta(hours=72) if aware else None),
        "final_report_14d": item(
            corrective + timedelta(days=14) if corrective else None
        ),
    }


def srp_readiness(case: dict[str, Any], stage: str) -> dict[str, Any]:
    if stage not in SRP_STAGES:
        raise ValueError("SRP 报告阶段无效")
    fields = case.get("srp_fields") or {}
    common = {
        "notification_type": "Vulnerability",
        "notification_level": stage,
        "reporter": fields.get("reporter"),
        "manufacturer_name": fields.get("manufacturer_name"),
        "product_name": case.get("project_name"),
        "product_type": fields.get("product_type"),
        "product_category": fields.get("product_category"),
        "member_states_where_available": fields.get("member_states_where_available"),
        "title": fields.get("title"),
        "cve_id": case.get("cve_id"),
        "euvd_id": case.get("euvd_id"),
    }
    stage_fields: dict[str, Any] = {}
    if stage in {"notification", "final-report"}:
        stage_fields = {
            "general_information": fields.get("general_information"),
            "vulnerability_nature": fields.get("vulnerability_nature"),
            "exploit_nature": fields.get("exploit_nature")
            or case.get("exploitation_evidence_summary"),
            "corrective_measures_taken": fields.get("corrective_measures_taken")
            or case.get("mitigation_summary"),
            "user_measures": fields.get("user_measures"),
            "sensitivity": fields.get("sensitivity"),
        }
    if stage == "final-report":
        stage_fields.update(
            {
                "corrective_measure_available_at": case.get(
                    "corrective_measure_available_at"
                ),
                "full_vulnerability_description": fields.get(
                    "full_vulnerability_description"
                ),
                "vulnerability_severity": fields.get("vulnerability_severity"),
                "vulnerability_impact": fields.get("vulnerability_impact"),
                "malicious_actor": fields.get("malicious_actor"),
                "security_update_details": fields.get("security_update_details"),
            }
        )
    payload = {**common, **stage_fields}
    required = {"manufacturer_name", "product_name", "title"}
    if stage in {"notification", "final-report"}:
        required.update(
            {
                "product_type",
                "member_states_where_available",
                "general_information",
                "vulnerability_nature",
                "exploit_nature",
                "corrective_measures_taken",
                "user_measures",
            }
        )
    if stage == "final-report":
        required.update(
            {
                "corrective_measure_available_at",
                "full_vulnerability_description",
                "vulnerability_severity",
                "vulnerability_impact",
                "security_update_details",
            }
        )
    if fields.get("product_type") and str(fields["product_type"]).casefold() != "default":
        required.add("product_category")
    missing = [key for key in sorted(required) if not payload.get(key)]
    gates = {
        "four_eye_approved": case.get("workflow_status")
        in {"approved", "submitted"},
        "decision_reportable": case.get("art14_decision") == "reportable",
        "awareness_confirmed": bool(
            case.get("awareness_at") and case.get("awareness_confirmed_by")
        ),
        "manual_submission_only": True,
        "srp_api_submission": False,
    }
    ready = not missing and all(
        gates[key]
        for key in ("four_eye_approved", "decision_reportable", "awareness_confirmed")
    )
    return {"stage": stage, "ready": ready, "missing_fields": missing, "gates": gates}


def build_srp_payload(case: dict[str, Any], stage: str) -> dict[str, Any]:
    readiness = srp_readiness(case, stage)
    fields = case.get("srp_fields") or {}
    payload = {
        "document_type": "CRA Article 14 SRP preparation draft",
        "stage": stage,
        "draft_only": True,
        "automatic_submission": False,
        "legal_basis": ["CRA Art.3(42)", "CRA Art.14", "CRA Art.16"],
        "case_id": case["id"],
        "common_fields": {
            "notification_type": "Vulnerability",
            "notification_level": stage,
            "reporter": fields.get("reporter"),
            "reporting_time": None,
            "title": fields.get("title"),
        },
        "manufacturer": {
            "name": fields.get("manufacturer_name"),
            "contact": fields.get("manufacturer_contact"),
        },
        "product": {
            "name": case.get("project_name"),
            "version": case.get("project_version"),
            "build": case.get("software_build"),
            "type": fields.get("product_type"),
            "category": fields.get("product_category"),
            "member_states_where_available": fields.get(
                "member_states_where_available"
            ),
            "component": case.get("component_name"),
            "component_version": case.get("component_version"),
        },
        "vulnerability": {
            "cve_id": case.get("cve_id"),
            "euvd_id": case.get("euvd_id"),
            "product_applicability": case.get("applicability_status"),
            "applicability_justification": case.get("applicability_justification"),
        },
        "exploitation": {
            "evidence_status": case.get("exploitation_evidence_status"),
            "nature": fields.get("exploit_nature")
            or case.get("exploitation_evidence_summary"),
            "external_signal_at": case.get("external_signal_at"),
            "manufacturer_awareness_at": case.get("awareness_at"),
            "awareness_confirmed_by": case.get("awareness_confirmed_by"),
        },
        "risk_and_response": {
            "product_risk_summary": case.get("product_risk_summary"),
            "general_information": fields.get("general_information"),
            "vulnerability_nature": fields.get("vulnerability_nature"),
            "corrective_measures_taken": fields.get("corrective_measures_taken")
            or case.get("mitigation_summary"),
            "user_measures": fields.get("user_measures"),
            "csirt_coordinator": fields.get("csirt_coordinator"),
            "user_notification": fields.get("user_notification"),
            "sensitivity": fields.get("sensitivity"),
        },
        "final_report": {
            "corrective_measure_available_at": case.get(
                "corrective_measure_available_at"
            ),
            "full_vulnerability_description": fields.get(
                "full_vulnerability_description"
            ),
            "vulnerability_severity": fields.get("vulnerability_severity"),
            "vulnerability_impact": fields.get("vulnerability_impact"),
            "malicious_actor": fields.get("malicious_actor"),
            "security_update_details": fields.get("security_update_details"),
            "remediation_monitoring": fields.get("remediation_monitoring"),
        }
        if stage == "final-report"
        else None,
        "approval": {
            "technical_reviewer": case.get("technical_reviewer"),
            "technical_reviewed_at": case.get("technical_reviewed_at"),
            "compliance_reviewer": case.get("compliance_reviewer"),
            "compliance_reviewed_at": case.get("compliance_reviewed_at"),
            "decision": case.get("art14_decision"),
        },
        "deadlines": deadline_status(case),
        "readiness": readiness,
    }
    return payload


def write_srp_json(path: Path, case: dict[str, Any], stage: str) -> None:
    path.write_text(
        json.dumps(build_srp_payload(case, stage), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_srp_xlsx(path: Path, case: dict[str, Any], stage: str) -> None:
    payload = build_srp_payload(case, stage)
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "SRP草稿"
    sheet.append(["字段", "内容"])
    header_fill = PatternFill("solid", fgColor="163B65")
    for cell in sheet[1]:
        cell.font = Font(color="FFFFFF", bold=True)
        cell.fill = header_fill
    rows = [
        ("声明", "仅供人工审核和在 ENISA SRP 手工填报；本文件不会自动提交。"),
        ("阶段", stage),
        ("通知类型", payload["common_fields"]["notification_type"]),
        ("通知级别", payload["common_fields"]["notification_level"]),
        ("Reporter", payload["common_fields"]["reporter"]),
        ("标题", payload["common_fields"]["title"]),
        ("案件ID", case["id"]),
        ("制造商", payload["manufacturer"]["name"]),
        ("制造商联系方式", payload["manufacturer"]["contact"]),
        ("产品", payload["product"]["name"]),
        ("产品版本", payload["product"]["version"]),
        ("构建", payload["product"]["build"]),
        ("组件", payload["product"]["component"]),
        ("CVE", payload["vulnerability"]["cve_id"]),
        ("EUVD", payload["vulnerability"]["euvd_id"]),
        ("产品适用性", payload["vulnerability"]["product_applicability"]),
        ("适用性理由", payload["vulnerability"]["applicability_justification"]),
        ("积极利用证据", payload["exploitation"]["evidence_status"]),
        ("利用性质", payload["exploitation"]["nature"]),
        ("awareness", payload["exploitation"]["manufacturer_awareness_at"]),
        ("风险分析", payload["risk_and_response"]["product_risk_summary"]),
        ("一般信息", payload["risk_and_response"]["general_information"]),
        ("漏洞一般性质", payload["risk_and_response"]["vulnerability_nature"]),
        ("已采取修正/缓解措施", payload["risk_and_response"]["corrective_measures_taken"]),
        ("用户可采取措施", payload["risk_and_response"]["user_measures"]),
        ("产品可用成员国", payload["product"]["member_states_where_available"]),
        ("CSIRT协调员", payload["risk_and_response"]["csirt_coordinator"]),
        ("用户通知", payload["risk_and_response"]["user_notification"]),
        ("敏感性", payload["risk_and_response"]["sensitivity"]),
        ("技术审核人", payload["approval"]["technical_reviewer"]),
        ("合规审核人", payload["approval"]["compliance_reviewer"]),
        ("Art.14决定", payload["approval"]["decision"]),
        ("草稿准备状态", "Ready" if payload["readiness"]["ready"] else "Not ready"),
        ("缺少字段", ", ".join(payload["readiness"]["missing_fields"])),
    ]
    if stage == "final-report":
        rows.extend(
            [
                ("修正措施可用时间", (payload["final_report"] or {}).get("corrective_measure_available_at")),
                ("完整漏洞说明", (payload["final_report"] or {}).get("full_vulnerability_description")),
                ("漏洞严重性", (payload["final_report"] or {}).get("vulnerability_severity")),
                ("漏洞影响", (payload["final_report"] or {}).get("vulnerability_impact")),
                ("恶意行为者", (payload["final_report"] or {}).get("malicious_actor")),
                ("安全更新详情", (payload["final_report"] or {}).get("security_update_details")),
                ("修复后监测", (payload["final_report"] or {}).get("remediation_monitoring")),
            ]
        )
    # All values can ultimately originate from an uploaded SBOM or an analyst
    # form.  Route both columns through the same formula/XML guard used by the
    # main report writer so Excel never interprets customer text as a formula.
    for key, value in rows:
        sheet.append([_safe_cell(key), _safe_cell(value)])
    sheet.column_dimensions["A"].width = 26
    sheet.column_dimensions["B"].width = 90
    for row in sheet.iter_rows():
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    workbook.save(path)


def write_srp_html(path: Path, case: dict[str, Any], stage: str) -> None:
    payload = build_srp_payload(case, stage)
    rows = []
    for section, value in payload.items():
        if isinstance(value, dict):
            for key, item in value.items():
                rows.append((f"{section}.{key}", json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else item))
        else:
            rows.append((section, value))
    body = "\n".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape('' if value is None else str(value))}</td></tr>"
        for key, value in rows
    )
    path.write_text(
        f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>SRP {escape(stage)} draft</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#17202a}}h1{{font-size:24px}}
.notice{{padding:12px;background:#fff4ce;border:1px solid #e0b000}}table{{border-collapse:collapse;width:100%;margin-top:18px}}
th,td{{border:1px solid #ccd4dc;padding:8px;text-align:left;vertical-align:top}}th{{width:28%;background:#eef4f8}}
@media print{{.notice{{break-inside:avoid}}}}</style></head><body>
<h1>CRA Article 14 SRP {escape(stage)} 草稿</h1>
<p class="notice">仅供人工审核和手工填报。未连接或自动提交至 ENISA SRP。</p>
<table>{body}</table></body></html>""",
        encoding="utf-8",
    )
