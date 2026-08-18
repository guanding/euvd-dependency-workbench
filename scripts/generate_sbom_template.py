#!/usr/bin/env python3
"""Regenerate the rights-neutral public blank SBOM workbook."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from openpyxl import load_workbook


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from app.template_builder import PUBLIC_TEMPLATE_FILENAME, write_public_template  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_DIR / "app" / "assets" / PUBLIC_TEMPLATE_FILENAME,
    )
    args = parser.parse_args()
    output = args.output.resolve()
    write_public_template(output)
    workbook = load_workbook(output, data_only=False)
    if any(cell.data_type == "f" for sheet in workbook for row in sheet for cell in row):
        raise SystemExit("unexpected formula found in generated customer template")
    print(f"WROTE {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
