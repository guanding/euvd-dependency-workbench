"""EUVD 侧 VEX intake receipt 消费（信任锚，简化版）。

消费 SBOM Workbench M8-1 产的签名绑定 intake receipt，1:1 复刻 Workbench 的
canonical 算法重算 vex_document_sha256 + statements_canonical_sha256（字节级
一致），查 issuer allowlist，fail-closed。

简化版：不验 cosign 签名（信任 Workbench 已验签 + 操作员拷贝 receipt）。完整
cosign 验签（防 receipt 伪造）留下一迭代。

算法移植自 sbom_workbench/vex_consume.py + manifest.py，必须保持字节级一致
（allow_nan=False + separators(",",":") + ensure_ascii=False + normalize 11-key
缺省 None 不省略 + purl qualifier-aware 保留 arch/distro）。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Constants (mirror vex_consume.py:68-90, 47-67)                              #
# --------------------------------------------------------------------------- #

ALLOWED_STATUSES = frozenset({"not_affected", "affected", "fixed", "unknown"})
NARROWING_STATUS = "not_affected"
VEX_FORMAT_CYCLONEDX = "cyclonedx-bom"
VEX_FORMAT_OPENVEX = "openvex"
VEX_INTAKE_SCHEMA_VERSION = "sbom-workbench.vex-intake-receipt/v1"
_PURL_PREFIX = "pkg:"
_PURL_RE = re.compile(r"^pkg:[A-Za-z0-9.\-+]+/.+")
_SHA256_HEX_LEN = 64
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")

VEX_INTAKE_KEYS = frozenset(
    {
        "schema_version",
        "vex_format",
        "vex_document_sha256",
        "signature_sha256",
        "issuer_id",
        "cosign_tool_identity",
        "statements_canonical_sha256",
        "statement_count",
        "narrowing_eligible_count",
        "boundary",
    }
)

CYCLONEDX_JUSTIFICATIONS = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    }
)
OPENVEX_JUSTIFICATIONS = frozenset(
    {
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)

_QUALIFIER_AWARE_KEEP = frozenset({"arch", "distro"})

ALLOWLIST_PATH = Path(__file__).resolve().parent / "vex_issuer_allowlist.json"
ALLOWLIST_SCHEMA_VERSION = "vex-issuer-allowlist-euvd-1.0"
ISSUER_STATUSES = frozenset({"NOT_ADMITTED", "ADMITTED_FOR_VEX_INTAKE"})


class VexIntakeError(ValueError):
    """Raised when a VEX receipt fails fail-closed verification."""


# --------------------------------------------------------------------------- #
# Canonical JSON (mirror manifest.py:25-32)                                   #
# --------------------------------------------------------------------------- #


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic JSON encoding — must match Workbench manifest byte-for-byte."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Identity helpers (mirror vex_consume.py:136-163)                            #
# --------------------------------------------------------------------------- #


def _ref_to_purl(ref: Any) -> str | None:
    """Qualifier-aware canonicalization: drop volatile qualifiers (package-id etc.)
    but KEEP arch/distro (affect package identity / ABI)."""
    if not isinstance(ref, str) or not ref.startswith(_PURL_PREFIX):
        return None
    base, _, query = ref.partition("?")
    if not query:
        return base
    kept = []
    for pair in query.split("&"):
        key, sep, value = pair.partition("=")
        if key in _QUALIFIER_AWARE_KEEP and sep:
            kept.append(f"{key}={value}")
    return base + ("?" + "&".join(kept) if kept else "")


def _openvex_product_purl(product: Any) -> str | None:
    if not isinstance(product, dict):
        return None
    ident = product.get("@id")
    return ident if isinstance(ident, str) and ident.startswith(_PURL_PREFIX) else None


def _detect_format(document: dict[str, Any]) -> str:
    context = document.get("@context")
    if isinstance(context, str) and "openvex" in context:
        return VEX_FORMAT_OPENVEX
    if document.get("bomFormat") == "CycloneDX":
        return VEX_FORMAT_CYCLONEDX
    raise VexIntakeError("VEX document is neither CycloneDX BOM nor OpenVEX")


# --------------------------------------------------------------------------- #
# Parsing (mirror vex_consume.py:180-265)                                     #
# --------------------------------------------------------------------------- #


def _parse_cyclonedx(document: dict[str, Any]) -> list[dict[str, Any]]:
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise VexIntakeError("CycloneDX VEX must carry a vulnerabilities array")
    statements: list[dict[str, Any]] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            raise VexIntakeError("CycloneDX vulnerability entry must be an object")
        analysis = entry.get("analysis")
        if not isinstance(analysis, dict):
            raise VexIntakeError("CycloneDX vulnerability must carry an analysis object")
        affects = entry.get("affects")
        if not isinstance(affects, list):
            raise VexIntakeError("CycloneDX vulnerability must carry an affects array")
        purls = sorted(
            {
                purl
                for affect in affects
                if isinstance(affect, dict)
                for purl in (_ref_to_purl(affect.get("ref")),)
                if purl
            }
        )
        statements.append(
            {
                "vulnerability_id": entry.get("id"),
                "status": analysis.get("state"),
                "justification": analysis.get("justification"),
                "detail": analysis.get("detail"),
                "first_issued_utc": analysis.get("firstIssued"),
                "last_updated_utc": analysis.get("lastUpdated"),
                "product_purls": purls,
            }
        )
    return statements


def _parse_openvex(document: dict[str, Any]) -> list[dict[str, Any]]:
    raw_statements = document.get("statements")
    if not isinstance(raw_statements, list):
        raise VexIntakeError("OpenVEX document must carry a statements array")
    statements: list[dict[str, Any]] = []
    for entry in raw_statements:
        if not isinstance(entry, dict):
            raise VexIntakeError("OpenVEX statement must be an object")
        products = entry.get("products")
        if not isinstance(products, list):
            raise VexIntakeError("OpenVEX statement must carry a products array")
        purls = sorted(
            {
                purl
                for product in products
                for purl in (_openvex_product_purl(product),)
                if purl
            }
        )
        vuln = entry.get("vulnerability")
        vuln_id = None
        if isinstance(vuln, dict):
            vuln_id = vuln.get("name") or vuln.get("@id")
        statements.append(
            {
                "vulnerability_id": vuln_id,
                "status": entry.get("status"),
                "justification": entry.get("justification"),
                "detail": entry.get("impact_statement") or entry.get("action_statement"),
                "first_issued_utc": None,
                "last_updated_utc": None,
                "product_purls": purls,
            }
        )
    return statements


def parse_vex_document(payload: bytes) -> tuple[str, list[dict[str, Any]]]:
    """Parse a VEX document and return (format, raw_statements)."""
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VexIntakeError(f"VEX document is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise VexIntakeError("VEX document must be a JSON object")
    fmt = _detect_format(document)
    statements = (
        _parse_cyclonedx(document)
        if fmt == VEX_FORMAT_CYCLONEDX
        else _parse_openvex(document)
    )
    if not statements:
        raise VexIntakeError("VEX document carries no statements")
    return fmt, statements


# --------------------------------------------------------------------------- #
# Statement validation + canonical hash (mirror vex_consume.py:273-326)       #
# --------------------------------------------------------------------------- #


def validate_vex_statement(
    raw: dict[str, Any],
    *,
    vex_format: str,
    issuer_id: str,
    vex_document_sha256: str,
) -> dict[str, Any]:
    allowed_just = (
        CYCLONEDX_JUSTIFICATIONS
        if vex_format == VEX_FORMAT_CYCLONEDX
        else OPENVEX_JUSTIFICATIONS
    )
    vuln_id = raw.get("vulnerability_id")
    if not isinstance(vuln_id, str) or not vuln_id:
        raise VexIntakeError("VEX statement vulnerability_id must be a non-empty string")
    status = raw.get("status")
    if status not in ALLOWED_STATUSES:
        raise VexIntakeError(f"VEX statement status {status!r} is not in the allowed set")
    justification = raw.get("justification")
    if not isinstance(justification, str) or justification not in allowed_just:
        raise VexIntakeError("VEX statement justification must be a standard enum value")
    purls = raw.get("product_purls")
    if not isinstance(purls, list) or not purls:
        raise VexIntakeError("VEX statement must bind to at least one purl")
    for purl in purls:
        if not isinstance(purl, str) or not _PURL_RE.fullmatch(purl):
            raise VexIntakeError(f"VEX product reference is not a valid purl: {purl!r}")
    detail = raw.get("detail")
    if detail is not None and not isinstance(detail, str):
        raise VexIntakeError("VEX detail must be a string when present")
    return {
        "vulnerability_id": vuln_id,
        "vex_format": vex_format,
        "vex_document_sha256": vex_document_sha256,
        "issuer_id": issuer_id,
        "product_purls": list(purls),
        "status": status,
        "justification": justification,
        "detail": detail,
        "first_issued_utc": raw.get("first_issued_utc"),
        "last_updated_utc": raw.get("last_updated_utc"),
        "narrowing_eligible": status == NARROWING_STATUS,
    }


def _statement_sort_key(statement: dict[str, Any]) -> tuple[str, str]:
    return (statement["vulnerability_id"], "|".join(statement["product_purls"]))


def statements_canonical_sha256(statements: list[dict[str, Any]]) -> str:
    """Deterministic sha256 over the sorted validated-statement set."""
    canonical = canonical_json_bytes(sorted(statements, key=_statement_sort_key))
    return hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------- #
# Receipt structural validation (mirror vex_consume.py:377-407)               #
# --------------------------------------------------------------------------- #


def _require_sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LEN:
        raise VexIntakeError(f"{label} must be a {_SHA256_HEX_LEN}-char sha256 hex string")
    return value


def validate_vex_intake_receipt(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise VexIntakeError("intake receipt must be a dict")
    if set(receipt) != VEX_INTAKE_KEYS:
        raise VexIntakeError("intake receipt fields do not match the fixed schema")
    if receipt["schema_version"] != VEX_INTAKE_SCHEMA_VERSION:
        raise VexIntakeError("intake receipt schema_version is not supported")
    if receipt["vex_format"] not in {VEX_FORMAT_CYCLONEDX, VEX_FORMAT_OPENVEX}:
        raise VexIntakeError("intake receipt vex_format is not supported")
    for key in ("vex_document_sha256", "signature_sha256", "statements_canonical_sha256"):
        _require_sha256_hex(receipt[key], f"intake receipt {key}")
    if not isinstance(receipt["issuer_id"], str) or not receipt["issuer_id"]:
        raise VexIntakeError("intake receipt issuer_id must be a non-empty string")
    tool = receipt["cosign_tool_identity"]
    if not isinstance(tool, dict):
        raise VexIntakeError("intake receipt cosign_tool_identity must be a dict")
    _require_sha256_hex(tool.get("binary_sha256"), "cosign_tool_identity.binary_sha256")
    if not isinstance(receipt["statement_count"], int) or receipt["statement_count"] <= 0:
        raise VexIntakeError("intake receipt statement_count must be a positive int")
    if not isinstance(receipt["narrowing_eligible_count"], int) or receipt["narrowing_eligible_count"] < 0:
        raise VexIntakeError("intake receipt narrowing_eligible_count is invalid")
    if receipt["narrowing_eligible_count"] > receipt["statement_count"]:
        raise VexIntakeError("intake receipt narrowing_eligible_count cannot exceed statement_count")
    if not isinstance(receipt["boundary"], str) or not receipt["boundary"]:
        raise VexIntakeError("intake receipt boundary must be present")
    return receipt


# --------------------------------------------------------------------------- #
# Issuer allowlist (EUVD-specific, simplified schema — no cosign key fields)  #
# --------------------------------------------------------------------------- #


def load_issuer_allowlist(path: Path = ALLOWLIST_PATH) -> dict[str, dict[str, Any]]:
    """Load + validate the issuer allowlist. Returns {issuer_id: issuer_dict}.

    EUVD simplified schema (vs Workbench): no cosign public_key / acquisition
    fields (EUVD does not verify cosign signatures — trusts Workbench receipt).
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VexIntakeError(f"issuer allowlist load failed: {exc}") from exc
    if not isinstance(data, dict) or data.get("registry_type") != "vex-issuer-registry":
        raise VexIntakeError("issuer allowlist registry_type is not vex-issuer-registry")
    if data.get("schema_version") != ALLOWLIST_SCHEMA_VERSION:
        raise VexIntakeError(
            f"issuer allowlist schema_version must be {ALLOWLIST_SCHEMA_VERSION}"
        )
    issuers = data.get("issuers")
    if not isinstance(issuers, list) or not issuers:
        raise VexIntakeError("issuer allowlist must carry a non-empty issuers array")
    by_id: dict[str, dict[str, Any]] = {}
    for entry in issuers:
        if not isinstance(entry, dict):
            raise VexIntakeError("issuer allowlist entry must be an object")
        issuer_id = entry.get("issuer_id")
        if not isinstance(issuer_id, str) or not _ID_RE.fullmatch(issuer_id):
            raise VexIntakeError(f"issuer_id {issuer_id!r} is not a valid id")
        if issuer_id in by_id:
            raise VexIntakeError(f"issuer_id {issuer_id!r} duplicated in allowlist")
        status = entry.get("status")
        if status not in ISSUER_STATUSES:
            raise VexIntakeError(f"issuer {issuer_id!r} status {status!r} is not allowed")
        by_id[issuer_id] = entry
    return by_id


# --------------------------------------------------------------------------- #
# Full verification (mirror verify_vex_intake_binding + allowlist gate)       #
# --------------------------------------------------------------------------- #


def verify_vex_intake_receipt(
    vex_payload: bytes,
    receipt: dict[str, Any],
    issuer_id: str,
    *,
    allowlist: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Verify a Workbench M8-1 intake receipt against the VEX bytes.

    Re-derives vex_document_sha256 + statements_canonical_sha256 (byte-exact
    match to Workbench), checks the issuer is ADMITTED in the allowlist, and
    fails closed on any mismatch. Simplified: does NOT re-verify the cosign
    signature (trusts Workbench already verified it).

    Returns the freshly-validated statements on success.
    """
    validate_vex_intake_receipt(receipt)
    if issuer_id != receipt["issuer_id"]:
        raise VexIntakeError("intake receipt issuer_id does not match the verifier's issuer")
    registry = allowlist if allowlist is not None else load_issuer_allowlist()
    issuer = registry.get(issuer_id)
    if issuer is None:
        raise VexIntakeError(f"issuer {issuer_id!r} is not in the allowlist")
    if issuer.get("status") != "ADMITTED_FOR_VEX_INTAKE":
        raise VexIntakeError(f"issuer {issuer_id!r} is not ADMITTED_FOR_VEX_INTAKE")
    observed_doc_sha = hashlib.sha256(vex_payload).hexdigest()
    if observed_doc_sha != receipt["vex_document_sha256"]:
        raise VexIntakeError("intake receipt vex_document_sha256 does not match the VEX bytes")
    vex_format, raw_statements = parse_vex_document(vex_payload)
    if vex_format != receipt["vex_format"]:
        raise VexIntakeError("intake receipt vex_format does not match the VEX bytes")
    validated = [
        validate_vex_statement(
            raw,
            vex_format=vex_format,
            issuer_id=issuer_id,
            vex_document_sha256=observed_doc_sha,
        )
        for raw in raw_statements
    ]
    if len(validated) != receipt["statement_count"]:
        raise VexIntakeError("intake receipt statement_count does not match the VEX bytes")
    if statements_canonical_sha256(validated) != receipt["statements_canonical_sha256"]:
        raise VexIntakeError("intake receipt statements_canonical_sha256 does not re-derive")
    narrowing = sum(1 for s in validated if s["narrowing_eligible"])
    if narrowing != receipt["narrowing_eligible_count"]:
        raise VexIntakeError("intake receipt narrowing_eligible_count does not re-derive")
    return validated
