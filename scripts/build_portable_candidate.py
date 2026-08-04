#!/usr/bin/env python3
"""Stage a data-free Windows portable candidate for isolated SBOM testing."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
ROOT_FILES = (
    "README.md",
    "requirements.txt",
    "start.cmd",
    "stop.cmd",
    "export-portable.cmd",
)
DIRECTORIES = ("app", "config", "docs", "runtime")
SCRIPT_FILES = ("setup-runtime.ps1", "stop.ps1", "export-portable.ps1")


def ignore_internal(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name in {"__pycache__", ".DS_Store"} or name.endswith(".pyc")
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default="2.3.0-candidate")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite portable candidate: {output}")
    output.mkdir(parents=True)

    for name in ROOT_FILES:
        source = PROJECT_DIR / name
        if source.is_file():
            shutil.copy2(source, output / name)
    for name in DIRECTORIES:
        source = PROJECT_DIR / name
        if not source.is_dir():
            raise SystemExit(f"required portable directory is missing: {source}")
        shutil.copytree(source, output / name, ignore=ignore_internal)

    script_target = output / "scripts"
    script_target.mkdir()
    for name in SCRIPT_FILES:
        source = PROJECT_DIR / "scripts" / name
        if not source.is_file():
            raise SystemExit(f"required portable script is missing: {source}")
        shutil.copy2(source, script_target / name)
    (output / "data").mkdir()
    (output / "outputs").mkdir()
    metadata = {
        "artifact_type": "WINDOWS_PORTABLE_INTERNAL_CANDIDATE",
        "version": args.version,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "includes_customer_data": False,
        "includes_euvd_database": False,
        "release_authority": False,
        "conformity_decision": False,
        "important_boundary": (
            "This stage is only an internal SBOM test input. It is not a released "
            "customer package and cannot query the local EUVD mirror until an "
            "explicit data snapshot is provisioned."
        ),
    }
    (output / "PORTABLE_CANDIDATE_METADATA.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": "staged", "output": str(output), **metadata}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
