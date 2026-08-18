#!/usr/bin/env python3
"""Stage a data-free Windows portable candidate from an explicit allowlist.

This module is also the implementation used by ``export-portable.ps1``.  Keep
the allowlist deliberately small: runtime state, customer inputs, databases,
Git metadata and local tooling must never enter a portable archive.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
REQUIRED_ROOT_FILES = (
    "README.md",
    "requirements.lock",
    "requirements.txt",
    "start.cmd",
    "stop.cmd",
    "export-portable.cmd",
)
OPTIONAL_ROOT_FILES = (
    "CONSTRAINTS.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
)
PUBLIC_DIRECTORIES = ("app", "config", "mirror")
SCRIPT_FILES = (
    "bootstrap_demo_snapshot.py",
    "setup-runtime.ps1",
    "stop.ps1",
    "export-portable.ps1",
)
FORBIDDEN_NAMES = frozenset(
    {
        ".git",
        ".serena",
        ".pytest_cache",
        ".artifact-work",
        "__pycache__",
        "assets",
        "backups",
        "data",
        "exports",
        "outputs",
        "runtime",
        "runtime-install",
        "self-test",
    }
)


def ignore_internal(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name.casefold() in FORBIDDEN_NAMES
        or name == ".DS_Store"
        or name.endswith((".pyc", ".pyo"))
    }


def app_version(project_dir: Path = PROJECT_DIR) -> str:
    text = (project_dir / "app" / "version.py").read_text(encoding="utf-8")
    match = re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if match is None:
        raise SystemExit("unable to read APP_VERSION from app/version.py")
    return match.group(1)


def _assert_data_free(output: Path) -> None:
    violations = sorted(
        str(path.relative_to(output))
        for path in output.rglob("*")
        if any(part.casefold() in FORBIDDEN_NAMES for part in path.relative_to(output).parts)
    )
    if violations:
        raise SystemExit(
            "portable allowlist violation: " + ", ".join(violations[:10])
        )


def _reject_symlinks(source: Path) -> None:
    if source.is_symlink():
        raise SystemExit(f"portable source symlink is not allowed: {source}")
    if source.is_dir():
        for path in source.rglob("*"):
            if path.is_symlink():
                raise SystemExit(f"portable source symlink is not allowed: {path}")


def stage_portable_candidate(
    output: Path,
    *,
    version: str | None = None,
    project_dir: Path = PROJECT_DIR,
) -> dict[str, object]:
    project_dir = project_dir.resolve()
    output = output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite portable candidate: {output}")
    output.mkdir(parents=True)

    for name in REQUIRED_ROOT_FILES:
        source = project_dir / name
        if not source.is_file():
            raise SystemExit(f"required portable file is missing: {source}")
        _reject_symlinks(source)
        shutil.copy2(source, output / name)
    for name in OPTIONAL_ROOT_FILES:
        source = project_dir / name
        if source.is_file():
            _reject_symlinks(source)
            shutil.copy2(source, output / name)
    for name in PUBLIC_DIRECTORIES:
        source = project_dir / name
        if not source.is_dir():
            raise SystemExit(f"required portable directory is missing: {source}")
        _reject_symlinks(source)
        shutil.copytree(source, output / name, ignore=ignore_internal)

    script_target = output / "scripts"
    script_target.mkdir()
    for name in SCRIPT_FILES:
        source = project_dir / "scripts" / name
        if not source.is_file():
            raise SystemExit(f"required portable script is missing: {source}")
        _reject_symlinks(source)
        shutil.copy2(source, script_target / name)

    metadata: dict[str, object] = {
        "artifact_type": "WINDOWS_PORTABLE_DATA_FREE_CANDIDATE",
        "version": version or app_version(project_dir),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "includes_customer_data": False,
        "includes_euvd_database": False,
        "includes_python_runtime": False,
        "includes_rights_pending_binary_assets": False,
        "release_authority": False,
        "conformity_decision": False,
        "important_boundary": (
            "Data-free candidate only. It contains no EUVD production mirror, "
            "customer input, reports or runtime. Provision an explicitly "
            "approved snapshot, or generate the synthetic demo snapshot."
        ),
    }
    (output / "PORTABLE_CANDIDATE_METADATA.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _assert_data_free(output)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version")
    args = parser.parse_args()
    output = args.output.resolve()
    metadata = stage_portable_candidate(output, version=args.version)
    print(
        json.dumps(
            {"status": "staged", "output": str(output), **metadata},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
