"""Tests for D1: customer-template Metadata-sheet product-identity binding.

The customer xlsx template has a ``01_Metadata_元数据`` sheet laid out as a
label/value table (A=label, B=customer entry). _read_xlsx currently picks the
best *component* sheet and discards the rest, so the operator must hand-type
product name/version/build. D1 extracts that Metadata sheet into a binding
(product identity for input prefill + extra fields as audit evidence) without
forcing the operator (CRA human-confirmation principle: prefill, don't lock).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openpyxl import Workbook

from app.spreadsheet_io import read_sbom


def _save_workbook(path: Path, sheets: dict[str, list[list]]) -> None:
    wb = Workbook()
    first = True
    for title, rows in sheets.items():
        ws = wb.active if first else wb.create_sheet(title=title)
        ws.title = title
        for row in rows:
            ws.append(row)
        first = False
    wb.save(path)


PRO_METADATA = [
    ["Field 字段", "Customer entry 客户填写"],
    ["Product name 产品名称", "SGW-200"],
    ["Product version 产品版本", "FW 3.2.0"],
    ["Hardware revision 硬件修订", "HW Rev B"],
    ["Build ID 构建号", "build-sgw200-3.2.0+20260804.1"],
    ["Release date 发布日期", "2026-08-04"],
    ["SBOM version SBOM版本", "1"],
]
SBOM_ROWS = [
    ["Component name 组件名称", "Component version 组件版本"],
    ["openssl", "3.0.0"],
    ["curl", "8.1.0"],
]


class MetadataBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_extracts_product_identity_and_evidence(self) -> None:
        path = self.dir / "with_meta.xlsx"
        _save_workbook(
            path,
            {"01_Metadata_元数据": PRO_METADATA, "02_SBOM_Software": SBOM_ROWS},
        )
        binding = read_sbom(path)["metadata_binding"]
        self.assertIsNotNone(binding)
        self.assertEqual(binding["fields"]["product_name"], "SGW-200")
        self.assertEqual(binding["fields"]["product_version"], "FW 3.2.0")
        self.assertEqual(
            binding["fields"]["software_build"], "build-sgw200-3.2.0+20260804.1"
        )
        # evidence: not prefilled into inputs, but retained for audit
        self.assertEqual(binding["evidence"]["hardware_revision"], "HW Rev B")
        self.assertEqual(binding["evidence"]["release_date"], "2026-08-04")
        self.assertEqual(binding["evidence"]["sbom_version"], "1")
        self.assertEqual(binding["source_sheet"], "01_Metadata_元数据")

    def test_records_raw_label_value_pairs_for_audit(self) -> None:
        path = self.dir / "raw.xlsx"
        _save_workbook(
            path,
            {"01_Metadata_元数据": PRO_METADATA, "02_SBOM_Software": SBOM_ROWS},
        )
        binding = read_sbom(path)["metadata_binding"]
        # raw keeps every label->value, including header and unmapped fields
        self.assertIn("Product name 产品名称", binding["raw"])
        self.assertEqual(binding["raw"]["Product name 产品名称"], "SGW-200")

    def test_none_when_no_metadata_sheet(self) -> None:
        path = self.dir / "no_meta.xlsx"
        _save_workbook(path, {"02_SBOM_Software": SBOM_ROWS})
        self.assertIsNone(read_sbom(path)["metadata_binding"])

    def test_english_only_labels(self) -> None:
        rows = [
            ["Field", "Value"],
            ["Product name", "Widget"],
            ["Product version", "1.0"],
            ["Build ID", "build-1"],
        ]
        path = self.dir / "en.xlsx"
        _save_workbook(path, {"Metadata": rows, "SBOM": SBOM_ROWS})
        binding = read_sbom(path)["metadata_binding"]
        self.assertEqual(binding["fields"]["product_name"], "Widget")
        self.assertEqual(binding["fields"]["product_version"], "1.0")
        self.assertEqual(binding["fields"]["software_build"], "build-1")

    def test_csv_has_no_metadata_binding(self) -> None:
        path = self.dir / "s.csv"
        path.write_text("name,version\nopenssl,3.0.0\n", encoding="utf-8")
        self.assertIsNone(read_sbom(path)["metadata_binding"])


if __name__ == "__main__":
    unittest.main()
