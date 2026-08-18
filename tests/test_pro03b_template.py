from __future__ import annotations

import asyncio
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile

from app import main
from app.spreadsheet_io import build_components, infer_mapping, read_sbom, write_template


TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "assets"
    / "客户SBOM导入模板_PRO-03B_v1.4兼容版.xlsx"
)


class Pro03bTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._template_directory = tempfile.TemporaryDirectory()
        cls.generated_template = Path(cls._template_directory.name) / "blank-template.xlsx"
        write_template(cls.generated_template)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._template_directory.cleanup()

    def test_blank_customer_template_selects_sbom_sheet_and_maps_fields(self) -> None:
        parsed = read_sbom(self.generated_template)

        self.assertEqual(parsed["sheet"], "02_SBOM_Software")
        self.assertEqual(parsed["header_row"], 1)
        self.assertEqual(parsed["rows"], [])
        self.assertEqual(
            parsed["mapping"],
            {
                "name": "Component name 组件名称",
                "version": "Component version 组件版本",
                "vendor": "Component producer 组件生产者",
                "purl": "PURL Package URL",
                "cpe": "CPE",
                "scope": "Component category 组件类别",
                "license": "License 许可证",
                "cve": "CVE 漏洞编号",
                "euvd": "EUVD ID EUVD编号",
            },
        )

    def test_pro03b_compatible_headers_build_exact_demo_components(self) -> None:
        headers = [
            "Row ID 行号",
            "Component category 组件类别",
            "Component producer 组件生产者",
            "Component name 组件名称",
            "Component version 组件版本",
            "PURL Package URL",
            "CPE",
            "Internal ID 内部标识",
            "Dependency relationship 依赖关系",
            "Source / Evidence 来源/证据",
            "Used in product build 是否进入目标构建",
            "Security relevance 安全相关性",
            "Known uncertainty / gap 已知不确定性/缺口",
            "License 许可证",
            "CVE 漏洞编号",
            "EUVD ID EUVD编号",
            "Customer notes 客户备注",
        ]
        rows = [
            dict.fromkeys(headers, ""),
            dict.fromkeys(headers, ""),
        ]
        rows[0].update(
            {
                "Component category 组件类别": "Third-party component 第三方组件",
                "Component producer 组件生产者": "Apache Software Foundation",
                "Component name 组件名称": "log4j-core",
                "Component version 组件版本": "2.14.1",
                "PURL Package URL": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "License 许可证": "Apache-2.0",
                "CVE 漏洞编号": "CVE-2021-44228",
            }
        )
        rows[1].update(
            {
                "Component category 组件类别": "Third-party component 第三方组件",
                "Component producer 组件生产者": "Python Software Foundation",
                "Component name 组件名称": "requests",
                "Component version 组件版本": "2.31.0",
                "PURL Package URL": "pkg:pypi/requests@2.31.0",
                "License 许可证": "Apache-2.0",
                "CVE 漏洞编号": "CVE-2024-35195",
            }
        )

        mapping = infer_mapping(headers)
        components = build_components(
            {"header_row": 1, "rows": rows}, mapping, max_components=10
        )

        self.assertEqual([item.name for item in components], ["log4j-core", "requests"])
        self.assertEqual(
            [item.cve_ids for item in components],
            ["CVE-2021-44228", "CVE-2024-35195"],
        )
        self.assertEqual(components[0].purl, rows[0]["PURL Package URL"])
        self.assertEqual(components[1].scope, "Third-party component 第三方组件")

    def test_write_template_copies_versioned_asset_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "copied-template.xlsx"
            write_template(target)
            if TEMPLATE_PATH.is_file():
                self.assertEqual(
                    hashlib.sha256(target.read_bytes()).hexdigest(),
                    hashlib.sha256(TEMPLATE_PATH.read_bytes()).hexdigest(),
                )
            else:
                self.assertEqual(read_sbom(target)["sheet"], "02_SBOM_Software")

    def test_template_endpoint_uses_packaged_asset_not_stale_output_cache(self) -> None:
        response = asyncio.run(main.download_template())
        if TEMPLATE_PATH.is_file():
            self.assertEqual(Path(response.path), TEMPLATE_PATH)
            self.assertIn("PRO-03B_v1.4", response.headers["content-disposition"])
        else:
            self.assertIn("sbom-import-template.xlsx", response.headers["content-disposition"])
            self.assertGreater(len(response.body), 1000)

    def test_template_endpoint_generates_public_fallback_when_asset_is_absent(self) -> None:
        missing = Path(self._template_directory.name) / "rights-pending-asset.xlsx"
        with patch.object(main, "SBOM_TEMPLATE_PATH", missing):
            response = asyncio.run(main.download_template())
        self.assertIn("sbom-import-template.xlsx", response.headers["content-disposition"])
        self.assertGreater(len(response.body), 1000)

    def test_xlsx_upload_does_not_claim_pre7_item_level_observations(self) -> None:
        upload = UploadFile(
            filename=self.generated_template.name,
            file=io.BytesIO(self.generated_template.read_bytes()),
        )
        with tempfile.TemporaryDirectory() as directory:
            upload_dir = Path(directory)
            with patch.object(main, "UPLOAD_DIR", upload_dir):
                preview = asyncio.run(main.upload_preview(upload))

        self.assertEqual(preview["sheet"], "02_SBOM_Software")
        self.assertEqual(preview["row_count"], 0)
        self.assertFalse(
            preview["pre7_evidence_artifact"]["contains_item_level_observations"]
        )
        self.assertFalse(preview["automatic_conformity_decision"])


if __name__ == "__main__":
    unittest.main()
