from __future__ import annotations

import asyncio
import json
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import httpx


ROOT = Path(__file__).resolve().parents[1]
GUIDE_PATH = ROOT / "app" / "static" / "srp-guide.html"
sys.path.insert(0, str(ROOT))


class _GuideParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.ids: set[str] = set()
        self.links: list[dict[str, str]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {key: value or "" for key, value in attrs}
        self.tags.append(tag)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "a":
            self.links.append(values)


class SrpGuideContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.guide = GUIDE_PATH.read_text(encoding="utf-8")
        cls.index = (ROOT / "app" / "static" / "index.html").read_text(
            encoding="utf-8"
        )
        cls.css = (ROOT / "app" / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        cls.main_source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        cls.profile = json.loads(
            (ROOT / "config" / "srp-q16-2026-08-03.json").read_text(
                encoding="utf-8"
            )
        )
        cls.parser = _GuideParser()
        cls.parser.feed(cls.guide)

    def test_guide_has_a_small_accessible_static_surface(self) -> None:
        self.assertEqual(self.parser.tags.count("h1"), 1)
        self.assertIn("guide-main", self.parser.ids)
        self.assertIn('<a class="guide-skip-link" href="#guide-main">', self.guide)
        self.assertIn("<caption>", self.guide)
        self.assertIn(
            'class="guide-stage-table-wrap" role="region" '
            'aria-label="SRP 三阶段官方操作和最低回执表" tabindex="0"',
            self.guide,
        )
        self.assertEqual(self.guide.count('class="guide-disclosure"'), 4)
        self.assertNotIn("<details", self.guide)
        for forbidden_tag in ("script", "form", "input", "textarea", "iframe"):
            self.assertNotIn(forbidden_tag, self.parser.tags)

    def test_guide_preserves_reporting_boundaries(self) -> None:
        required_text = (
            "EUVD 是查，SRP 是报",
            "本地材料就绪不等于官方已提交",
            "本工具不会自动向官方 SRP 提交",
            "不是 CRA 规定必须由两名不同人员作出决定",
            "ENISA SRP FAQ Q16（2026-08-03）",
            "ENISA 当前计划 SRP 自 2026-09-11 起投入使用并用于 CRA 强制上报",
            "未经系统所有者许可实际利用该漏洞",
            "敏感或重要数据或功能",
            "在适当时通知所有用户",
            "只适用于 CRA Art.14(2)(b) 的 72h AEV 通知",
        )
        for text in required_text:
            with self.subTest(text=text):
                self.assertIn(text, self.guide)

    def test_internal_document_metadata_is_not_published(self) -> None:
        forbidden_text = (
            "CONTROLLED_LEARNING_NOTE",
            "CUSTOMER_GUIDE_DRAFT",
            "assessment_status",
            "作者：",
            "文档状态",
            "修订流程",
        )
        for text in forbidden_text:
            with self.subTest(text=text):
                self.assertNotIn(text, self.guide)

    def test_external_links_are_limited_to_official_sources(self) -> None:
        allowed_hosts = {
            "enisa.europa.eu",
            "www.enisa.europa.eu",
            "eur-lex.europa.eu",
        }
        external_links = 0
        for link in self.parser.links:
            href = link.get("href", "")
            parsed = urlparse(href)
            if parsed.scheme not in {"http", "https"}:
                continue
            external_links += 1
            self.assertEqual(parsed.scheme, "https")
            self.assertIn(parsed.hostname, allowed_hosts)
            self.assertEqual(link.get("target"), "_blank")
            rel_tokens = set(link.get("rel", "").split())
            self.assertTrue({"noopener", "noreferrer"}.issubset(rel_tokens))
        self.assertGreaterEqual(external_links, 3)

    def test_workbench_links_to_guide_and_explains_governance(self) -> None:
        self.assertIn('href="/srp-guide.html"', self.index)
        self.assertIn('target="_blank" rel="noopener noreferrer"', self.index)
        self.assertIn("组织审批与 Art.14 决策记录", self.index)
        self.assertIn("不代表 CRA 规定必须由两名不同人员决定", self.index)

    def test_baseline_comes_from_versioned_profile(self) -> None:
        self.assertEqual(self.profile["id"], "enisa-cra-srp-q16-2026-08-03")
        self.assertEqual(self.profile["faq_updated_at"], "2026-08-03")
        self.assertTrue(self.profile["portal_field_confirmation_required"])
        self.assertEqual(
            self.profile["submission_mode"], "human_confirmed_official_portal"
        )
        self.assertNotIn("interface_guidance_updated_at", self.profile)
        self.assertNotIn("interface_functions", self.profile["sources"])

    def test_guide_has_responsive_print_and_no_store_contracts(self) -> None:
        self.assertIn(".guide-body", self.css)
        self.assertIn("@media (max-width: 650px)", self.css)
        self.assertIn("@media print", self.css)
        self.assertIn(".guide-stage-table {\n    min-width: 0;", self.css)
        self.assertIn("table-layout: fixed", self.css)
        self.assertIn('"/srp-guide.html"', self.main_source)
        self.assertIn('response.headers["Cache-Control"] = "no-store"', self.main_source)

    def test_guide_is_served_with_security_headers(self) -> None:
        from app.main import app

        async def fetch_guide() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1",
            ) as client:
                return await client.get("/srp-guide.html")

        response = asyncio.run(fetch_guide())
        self.assertEqual(response.status_code, 200)
        self.assertIn("ENISA SRP 上报操作指南", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("default-src 'self'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
