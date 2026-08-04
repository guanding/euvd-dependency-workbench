"""版本号单一源一致性测试（D0，架构审查中危：版本号散落致 v2.3.0/v2.3.1 漂移）。

APP_VERSION (app/main.py) 是版本号唯一权威。本测试在 CI 中强制 docker-compose
镜像 tag 与之一致；若有人改 APP_VERSION 但忘了同步 docker-compose tag，本测试
失败。运行 `python scripts/check_version_consistency.py` 可人工核查（含 /api/health）。
"""

import importlib.util
import unittest
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "check_version_consistency.py"
)
_spec = importlib.util.spec_from_file_location("check_version_consistency", _SCRIPT)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class VersionConsistencyTests(unittest.TestCase):
    def test_compose_tag_equals_app_version(self):
        expected = _mod.app_version()
        tag = _mod.compose_tag()
        self.assertIsNotNone(
            tag, "docker-compose.yml 缺少 euvd-dependency-workbench image tag"
        )
        self.assertEqual(
            tag,
            expected,
            f"版本漂移：docker-compose tag '{tag}' != APP_VERSION '{expected}'。"
            "请将 docker-compose image tag 改为 APP_VERSION 值，"
            "或运行 scripts/check_version_consistency.py 核查。",
        )

    def test_app_version_is_semver_like(self):
        v = _mod.app_version()
        self.assertRegex(
            v,
            r"^\d+\.\d+\.\d+",
            f"APP_VERSION '{v}' 不像语义化版本 x.y.z",
        )


if __name__ == "__main__":
    unittest.main()
