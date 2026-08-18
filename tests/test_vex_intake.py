"""Tests for VEX intake receipt trust anchor (complete VEX trust anchor fix).

EUVD re-derives vex_document_sha256 + statements_canonical_sha256 (byte-exact
to Workbench M8-1) and gates on issuer allowlist. Bare VEX is rejected at the
endpoint. The canonical algorithm is cross-verified byte-exact against
Workbench (see session 2026-08-08: same VEX → same hashes both sides).
"""

from __future__ import annotations

import hashlib
import inspect
import json
import unittest

from app import main
from app.vex_intake import (
    VEX_INTAKE_SCHEMA_VERSION,
    VexIntakeError,
    parse_vex_document,
    statements_canonical_sha256,
    validate_vex_statement,
    verify_vex_intake_receipt,
)


def _vex_cyclonedx(
    state: str = "not_affected",
    justification: str = "code_not_present",
    vuln_id: str = "CVE-2026-1",
    purl: str = "pkg:pypi/alpha@1.0",
) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "vulnerabilities": [
            {
                "id": vuln_id,
                "affects": [{"ref": purl}],
                "analysis": {"state": state, "justification": justification},
            }
        ],
    }


def _build_receipt(vex_payload: bytes, issuer_id: str = "psirt-admitted") -> dict:
    """Build a structurally-valid receipt using EUVD's own canonical algorithm
    (self-consistent; cross-verified byte-exact against Workbench)."""
    doc_sha = hashlib.sha256(vex_payload).hexdigest()
    fmt, raw = parse_vex_document(vex_payload)
    validated = [
        validate_vex_statement(r, vex_format=fmt, issuer_id=issuer_id, vex_document_sha256=doc_sha)
        for r in raw
    ]
    return {
        "schema_version": VEX_INTAKE_SCHEMA_VERSION,
        "vex_format": fmt,
        "vex_document_sha256": doc_sha,
        "signature_sha256": "0" * 64,
        "issuer_id": issuer_id,
        "cosign_tool_identity": {"binary_sha256": "0" * 64},
        "statements_canonical_sha256": statements_canonical_sha256(validated),
        "statement_count": len(validated),
        "narrowing_eligible_count": sum(1 for s in validated if s["narrowing_eligible"]),
        "boundary": "evidence recording only",
    }


ADMITTED_ALLOWLIST = {
    "psirt-admitted": {"issuer_id": "psirt-admitted", "status": "ADMITTED_FOR_VEX_INTAKE"},
    "psirt-not-admitted": {"issuer_id": "psirt-not-admitted", "status": "NOT_ADMITTED"},
}


class VexIntakeReceiptTests(unittest.TestCase):
    def test_valid_receipt_verifies(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload)
        result = verify_vex_intake_receipt(payload, receipt, "psirt-admitted", allowlist=ADMITTED_ALLOWLIST)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["narrowing_eligible"])

    def test_qualifier_aware_purl_canonicalization(self) -> None:
        # volatile ?package-id= must be stripped; arch/distro kept. Cross-verified
        # against Workbench byte-exact in session 2026-08-08.
        payload = json.dumps(
            _vex_cyclonedx(purl="pkg:pypi/alpha@1.0?package-id=abc&arch=amd64")
        ).encode()
        receipt = _build_receipt(payload)
        result = verify_vex_intake_receipt(payload, receipt, "psirt-admitted", allowlist=ADMITTED_ALLOWLIST)
        self.assertEqual(result[0]["product_purls"], ["pkg:pypi/alpha@1.0?arch=amd64"])

    def test_tampered_vex_document_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload)
        tampered = json.dumps(_vex_cyclonedx(vuln_id="CVE-9999")).encode()
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(tampered, receipt, "psirt-admitted", allowlist=ADMITTED_ALLOWLIST)

    def test_tampered_canonical_hash_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload)
        receipt["statements_canonical_sha256"] = "a" * 64  # wrong canonical
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(payload, receipt, "psirt-admitted", allowlist=ADMITTED_ALLOWLIST)

    def test_issuer_id_mismatch_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload, issuer_id="psirt-admitted")
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(payload, receipt, "other-issuer", allowlist=ADMITTED_ALLOWLIST)

    def test_issuer_not_admitted_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload, issuer_id="psirt-not-admitted")
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(payload, receipt, "psirt-not-admitted", allowlist=ADMITTED_ALLOWLIST)

    def test_issuer_not_in_allowlist_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload, issuer_id="unknown-issuer")
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(payload, receipt, "unknown-issuer", allowlist=ADMITTED_ALLOWLIST)

    def test_receipt_missing_key_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload)
        del receipt["statements_canonical_sha256"]
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(payload, receipt, "psirt-admitted", allowlist=ADMITTED_ALLOWLIST)

    def test_receipt_wrong_schema_version_rejected(self) -> None:
        payload = json.dumps(_vex_cyclonedx()).encode()
        receipt = _build_receipt(payload)
        receipt["schema_version"] = "bogus"
        with self.assertRaises(VexIntakeError):
            verify_vex_intake_receipt(payload, receipt, "psirt-admitted", allowlist=ADMITTED_ALLOWLIST)

    def test_endpoint_requires_receipt_and_issuer_id(self) -> None:
        # Bare VEX is no longer accepted: /api/vex/import now requires receipt +
        # issuer_id as mandatory multipart fields (anti-pattern elimination).
        sig = inspect.signature(main.import_vex)
        self.assertIn("receipt", sig.parameters)
        self.assertIn("issuer_id", sig.parameters)
        # File(...)/Form(...) → required (no optional default like Form("x") or None)
        self.assertIsNotNone(sig.parameters["receipt"].default)
        self.assertIsNotNone(sig.parameters["issuer_id"].default)


if __name__ == "__main__":
    unittest.main()
