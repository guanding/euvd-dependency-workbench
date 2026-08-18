"""Tests for CVE-exact-then-product-fallback (审查 HIGH#1 漏报修复).

确认 CVE 未在本地 cve_euvd_mapping 时回退产品候选搜索，不再静默漏报；
CVE 已映射仍精确优先（不回退）；回退仍无候选时如实记 unmapped（不杜撰）。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from app import matcher
from app.matcher import Component, EuvdClient, match_components


def _status_ok() -> dict:
    return {
        "status": "local_ready",
        "query_mode": "local-read-only-snapshot",
        "last_successful_to_date": "2026-07-28",
        "reference_data_freshness": "fresh",
        "source_db_sha256": "",
        "snapshot_created_at": "",
    }


def _product_item(euvd_id: str, product: str, vendor: str, cve: str, score=7.5):
    return {
        "id": euvd_id,
        "baseScore": score,
        "enisaIdProduct": [
            {"product": {"name": product, "vendor": {"name": vendor}},
             "product_version": "1.0"}
        ],
        "aliases": f"{cve}\n",
    }


class CveFallbackTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_data_dir = matcher.DATA_DIR
        self._orig_cache_db = matcher.CACHE_DB
        # EuvdClient.__init__ 会 mkdir(DATA_DIR) + 连 CACHE_DB；默认 /app/data
        # 在宿主只读，故重定向到临时目录
        matcher.DATA_DIR = Path(self._tmpdir.name) / "data"
        matcher.DATA_DIR.mkdir(parents=True, exist_ok=True)
        matcher.CACHE_DB = matcher.DATA_DIR / "euvd-cache.sqlite3"
        self._orig = {
            "local_snapshot_status": EuvdClient.local_snapshot_status,
            "cve_mapping": EuvdClient.cve_mapping,
            "kev_index": EuvdClient.kev_index,
            "detail": EuvdClient.detail,
            "search": EuvdClient.search,
        }
        # 避免接触真实 DB：local_snapshot_status 返回固定 ok 状态
        EuvdClient.local_snapshot_status = staticmethod(_status_ok)  # type: ignore[assignment]

    def tearDown(self) -> None:
        for key, value in self._orig.items():
            setattr(EuvdClient, key, value)
        matcher.DATA_DIR = self._orig_data_dir
        matcher.CACHE_DB = self._orig_cache_db
        self._tmpdir.cleanup()

    async def test_cve_unmapped_falls_back_to_product_search(self) -> None:
        # CVE-2024-9999 不在 cve_mapping → 精确分支零 match → 应回退产品候选
        EuvdClient.cve_mapping = AsyncMock(return_value=({}, {"mapping_source": "test"}))
        EuvdClient.kev_index = AsyncMock(return_value=({}, {}))
        EuvdClient.detail = AsyncMock(return_value=None)
        EuvdClient.search = AsyncMock(return_value=(
            [_product_item("EUVD-FALLBACK", "nginx", "nginx", "CVE-2024-9999")],
            {"query_mode": "product", "api_total": 1, "fetched_count": 1,
             "pages_fetched": 1, "truncated": False},
        ))
        component = Component(row_number=1, name="nginx", version="1.0",
                              vendor="nginx", cve_ids="CVE-2024-9999")
        result = await match_components([component])

        euvd_ids = [m["euvd_id"] for m in result["matches"]]
        self.assertIn("EUVD-FALLBACK", euvd_ids)
        self.assertTrue(EuvdClient.search.called, "回退时应调用产品候选搜索")
        # 不再是"未找到EUVD映射"（修复前会漏报成这个）
        self.assertNotEqual(result["components"][0]["result"], "未找到EUVD映射")
        # query_mode 标注发生了回退
        self.assertEqual(
            result["components"][0]["query_mode"],
            "identifier-exact-then-product-fallback",
        )

    async def test_cve_mapped_does_not_fallback(self) -> None:
        # CVE 已映射 → 精确匹配优先，search 不应被调用
        EuvdClient.cve_mapping = AsyncMock(return_value=(
            {"CVE-2024-1000": ["EUVD-EXACT"]}, {"mapping_source": "test"},
        ))
        EuvdClient.kev_index = AsyncMock(return_value=({}, {}))
        EuvdClient.detail = AsyncMock(return_value=_product_item(
            "EUVD-EXACT", "nginx", "nginx", "CVE-2024-1000", score=9.0))
        EuvdClient.search = AsyncMock(return_value=([], {
            "query_mode": "product", "api_total": 0, "fetched_count": 0,
            "pages_fetched": 0, "truncated": False,
        }))
        component = Component(row_number=1, name="nginx", version="1.0",
                              vendor="nginx", cve_ids="CVE-2024-1000")
        result = await match_components([component])

        self.assertIn("EUVD-EXACT", [m["euvd_id"] for m in result["matches"]])
        self.assertFalse(EuvdClient.search.called, "精确命中时不应回退")
        self.assertEqual(result["components"][0]["query_mode"], "identifier-exact")

    async def test_cve_unmapped_and_no_product_match_still_records_unmapped(self) -> None:
        # CVE 未映射 + 产品候选也无 → 如实记 unmapped（不杜撰候选）
        EuvdClient.cve_mapping = AsyncMock(return_value=({}, {"mapping_source": "test"}))
        EuvdClient.kev_index = AsyncMock(return_value=({}, {}))
        EuvdClient.detail = AsyncMock(return_value=None)
        EuvdClient.search = AsyncMock(return_value=([], {
            "query_mode": "product", "api_total": 0, "fetched_count": 0,
            "pages_fetched": 0, "truncated": False,
        }))
        component = Component(row_number=1, name="nginx", version="1.0",
                              vendor="nginx", cve_ids="CVE-2024-9999")
        result = await match_components([component])

        self.assertEqual(len(result["matches"]), 0)
        self.assertTrue(EuvdClient.search.called, "即使无候选也应尝试回退")
        self.assertEqual(result["components"][0]["result"], "未找到EUVD映射")


if __name__ == "__main__":
    unittest.main()
