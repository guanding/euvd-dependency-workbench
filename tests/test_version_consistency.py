"""版本号单一源一致性测试（防止应用版本与镜像标签漂移）。

APP_VERSION (app/version.py) 是版本号唯一权威。本测试在 CI 中强制 docker-compose
镜像 tag 与之一致；若有人改 APP_VERSION 但忘了同步 docker-compose tag，本测试
失败。运行 `python scripts/check_version_consistency.py` 可人工核查（含 /api/health）。
"""

import hashlib
import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from app.version import APP_VERSION, USER_AGENT
from release.build_public_candidate import _license_gate

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

    def test_release_candidate_version_and_license_are_expected(self):
        self.assertEqual(_mod.app_version(), "2.4.0-rc.1")
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(
            hashlib.sha256((root / "LICENSE").read_bytes()).hexdigest(),
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        )
        self.assertIn(
            "Copyright 2026 Ding Guan",
            (root / "NOTICE").read_text(encoding="utf-8").splitlines(),
        )
        review = json.loads((root / "release" / "rights_review.json").read_text(encoding="utf-8"))
        project = next(item for item in review["items"] if item["id"] == "project-source-code")
        self.assertEqual(project["status"], "APPROVED")
        self.assertEqual(project["license_expression"], "Apache-2.0")
        self.assertEqual(project["copyright_holder"], "Ding Guan")
        declaration = review["project_content_declaration"]
        self.assertEqual(declaration["declarant"], "Ding Guan")
        self.assertEqual(declaration["status"], "AUTHOR_DECLARED")
        self.assertEqual(review["overall_status"], "APPROVED_WITH_EXCLUSIONS")
        self.assertEqual(
            review["review_model"]["mode"],
            "SOLE_MAINTAINER_SELF_REVIEW",
        )
        self.assertFalse(review["review_model"]["independent_review_available"])
        for item_id in ("product-alias-registry", "public-cve-test-fixture"):
            item = next(item for item in review["items"] if item["id"] == item_id)
            self.assertEqual(item["status"], "APPROVED")
            self.assertEqual(item["license_expression"], "Apache-2.0")
            self.assertEqual(item["copyright_holder"], "Ding Guan")
        dependencies = next(
            item
            for item in review["items"]
            if item["id"] == "python-and-container-dependencies"
        )
        self.assertFalse(dependencies["included"])
        self.assertTrue(dependencies["referenced"])
        self.assertEqual(dependencies["status"], "REFERENCED_NOT_DISTRIBUTED")
        self.assertEqual(
            review["artifact_distribution"]["container_image"],
            "BLOCKED_NOT_OFFERED",
        )
        with tempfile.TemporaryDirectory() as directory_name:
            candidate = Path(directory_name)
            shutil.copy2(root / "LICENSE", candidate / "LICENSE")
            shutil.copy2(root / "NOTICE", candidate / "NOTICE")
            self.assertEqual(_license_gate(candidate), (True, None))
            (candidate / "LICENSE").write_text("tampered\n", encoding="utf-8")
            self.assertEqual(
                _license_gate(candidate),
                (False, "LICENSE_CONTENT_MISMATCH"),
            )

    def test_protocol_user_agent_uses_authoritative_version(self):
        self.assertEqual(USER_AGENT, f"EUVD-Dependency-Workbench/{APP_VERSION}")

    def test_container_distributes_project_license_and_notices(self):
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "COPY --chown=65532:65532 LICENSE NOTICE "
            "THIRD_PARTY_NOTICES.md ./licenses/",
            dockerfile,
        )

    def test_csv_detector_is_a_pinned_runtime_dependency(self):
        root = Path(__file__).resolve().parents[1]
        requirements = (root / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("charset-normalizer==3.4.9", requirements.splitlines())

    def test_container_sbom_scan_does_not_mount_docker_socket(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("/var/run/docker.sock", workflow)
        self.assertIn("docker-archive:/scan/image.tar", workflow)
        self.assertIn("Image Python graph matches requirements.lock", workflow)

    def test_runtime_lock_covers_direct_pins_and_records_hashes(self):
        root = Path(__file__).resolve().parents[1]
        direct_lines = [
            line.strip()
            for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        lock = (root / "requirements.lock").read_text(encoding="utf-8")
        self.assertNotIn("--index-url", lock)
        for direct in direct_lines:
            name, version = direct.split("==", 1)
            name = name.split("[", 1)[0]
            self.assertRegex(
                lock,
                rf"(?m)^{re.escape(name)}=={re.escape(version)}(?:\s|\\)",
            )
        headers = list(
            re.finditer(r"(?m)^[a-z0-9][a-z0-9_.-]*==[^\n]+", lock)
        )
        self.assertGreater(len(headers), len(direct_lines))
        for index, header in enumerate(headers):
            end = headers[index + 1].start() if index + 1 < len(headers) else len(lock)
            self.assertIn("--hash=sha256:", lock[header.start() : end])

    def test_runtime_installers_enforce_hash_lock(self):
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        setup = (root / "scripts" / "setup-runtime.ps1").read_text(encoding="utf-8")
        workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for text in (dockerfile, setup, workflow):
            self.assertIn("--require-hashes", text)
            self.assertIn("requirements.lock", text)
        self.assertIn("Requirements-Lock-SHA256", setup)
        self.assertNotIn("get-pip.py", setup)
        self.assertIn("$PipVersion = '26.2.1'", setup)
        self.assertIn('"pip-$PipVersion.pyz"', setup)
        self.assertIn(
            "91d5fd9f6f25549fd839c60536c6f1b945316ce3588d34a605635b6071c91526",
            setup,
        )

    def test_ci_tool_graph_is_hash_locked_and_isolated(self):
        root = Path(__file__).resolve().parents[1]
        direct = {
            line.strip()
            for line in (root / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        lock = (root / "requirements-dev.lock").read_text(encoding="utf-8")
        for requirement in direct:
            self.assertRegex(lock, rf"(?m)^{re.escape(requirement)}(?:\s|\\)")
        self.assertIn("--hash=sha256:", lock)
        for workflow_name in ("ci.yml", "security.yml"):
            workflow = (
                root / ".github" / "workflows" / workflow_name
            ).read_text(encoding="utf-8")
            self.assertIn("requirements-dev.lock", workflow)
            self.assertIn("--require-hashes", workflow)
            self.assertIn("${RUNNER_TEMP}/ci-tools", workflow)


if __name__ == "__main__":
    unittest.main()
