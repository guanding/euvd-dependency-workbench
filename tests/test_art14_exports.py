from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from app.art14 import write_srp_xlsx


class SrpXlsxSecurityTests(unittest.TestCase):
    def test_user_controlled_values_never_become_excel_formulas(self) -> None:
        case = {
            "id": "case-formula-test",
            "project_name": "=HYPERLINK(\"https://example.invalid\",\"click\")",
            "project_version": "+1+1",
            "software_build": "-2+2",
            "component_name": "@SUM(A1:A2)",
            "workflow_status": "draft",
            "art14_decision": "not_assessed",
            "srp_fields": {
                "manufacturer_name": "=cmd|' /C calc'!A0",
                "title": "safe\x00title",
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "srp.xlsx"
            write_srp_xlsx(target, case, "early-warning")
            workbook = load_workbook(target, data_only=False)
            sheet = workbook["SRP草稿"]

            values = [cell.value for cell in sheet["B"] if cell.value]
            self.assertIn("'=HYPERLINK(\"https://example.invalid\",\"click\")", values)
            self.assertIn("'+1+1", values)
            self.assertIn("'-2+2", values)
            self.assertIn("'@SUM(A1:A2)", values)
            self.assertIn("'=cmd|' /C calc'!A0", values)
            self.assertIn("safetitle", values)
            self.assertFalse(any(cell.data_type == "f" for row in sheet for cell in row))


if __name__ == "__main__":
    unittest.main()
