from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_portable_candidate.py"
SPEC = importlib.util.spec_from_file_location("build_portable_candidate", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class PortableExportTests(unittest.TestCase):
    def _fake_project(self, root: Path) -> None:
        for name in MODULE.REQUIRED_ROOT_FILES:
            (root / name).write_text(f"public {name}\n", encoding="utf-8")
        (root / "app").mkdir()
        (root / "app" / "version.py").write_text(
            'APP_VERSION = "2.4.0-rc.1"\n', encoding="utf-8"
        )
        (root / "app" / "public.py").write_text("ok = True\n", encoding="utf-8")
        (root / "config").mkdir()
        (root / "config" / "public.csv").write_text("a,b\n", encoding="utf-8")
        (root / "mirror").mkdir()
        (root / "mirror" / "README.md").write_text("public boundary\n", encoding="utf-8")
        (root / "scripts").mkdir()
        for name in MODULE.SCRIPT_FILES:
            (root / "scripts" / name).write_text("# public\n", encoding="utf-8")

        for forbidden in MODULE.FORBIDDEN_NAMES:
            path = root / forbidden
            path.mkdir()
            (path / "must-not-ship.txt").write_text("secret\n", encoding="utf-8")
        nested = root / "app" / "__pycache__"
        nested.mkdir()
        (nested / "module.pyc").write_bytes(b"cache")
        pending_asset = root / "app" / "assets"
        pending_asset.mkdir()
        (pending_asset / "rights-pending.xlsx").write_bytes(b"not public")

    def test_staging_is_allowlist_only_and_data_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            output = Path(directory) / "candidate"
            root.mkdir()
            self._fake_project(root)

            metadata = MODULE.stage_portable_candidate(output, project_dir=root)

            self.assertEqual(metadata["version"], "2.4.0-rc.1")
            self.assertFalse(metadata["includes_customer_data"])
            self.assertFalse(metadata["includes_euvd_database"])
            self.assertFalse(metadata["includes_python_runtime"])
            self.assertFalse(metadata["includes_rights_pending_binary_assets"])
            self.assertTrue((output / "app" / "public.py").is_file())
            self.assertTrue((output / "scripts" / "setup-runtime.ps1").is_file())
            self.assertFalse((output / "app" / "__pycache__").exists())
            self.assertFalse((output / "app" / "assets").exists())
            for forbidden in MODULE.FORBIDDEN_NAMES:
                self.assertFalse((output / forbidden).exists(), forbidden)

            manifest = json.loads(
                (output / "PORTABLE_CANDIDATE_METADATA.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["artifact_type"], "WINDOWS_PORTABLE_DATA_FREE_CANDIDATE")

    def test_existing_destination_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            output = Path(directory) / "candidate"
            root.mkdir()
            output.mkdir()
            self._fake_project(root)
            with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
                MODULE.stage_portable_candidate(output, project_dir=root)

    def test_symlink_cannot_escape_the_allowlisted_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            output = Path(directory) / "candidate"
            root.mkdir()
            self._fake_project(root)
            outside = Path(directory) / "customer-data.txt"
            outside.write_text("must not ship\n", encoding="utf-8")
            (root / "app" / "escape-link").symlink_to(outside)
            with self.assertRaisesRegex(SystemExit, "symlink is not allowed"):
                MODULE.stage_portable_candidate(output, project_dir=root)

    def test_powershell_with_data_switch_fails_before_staging(self) -> None:
        text = (SCRIPT.parent / "export-portable.ps1").read_text(encoding="utf-8")
        rejection = text.index("if ($WithData)")
        first_write = text.index("New-Item")
        self.assertLess(rejection, first_write)
        self.assertIn("must never contain customer data", text)

    def test_public_source_candidate_includes_portable_entrypoints(self) -> None:
        rules = (
            SCRIPT.parents[1] / "release" / "public_files.txt"
        ).read_text(encoding="utf-8").splitlines()
        for name in ("start.cmd", "stop.cmd", "export-portable.cmd"):
            self.assertIn(name, rules)


if __name__ == "__main__":
    unittest.main()
