#!/usr/bin/env python3
"""Run a synthetic template/upload/match/report smoke test against a local app."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx
from openpyxl import load_workbook


DEMO_CVE = "CVE-2099-999999"
DEMO_EUVD = "EUVD-DEMO-0001"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"demo assertion failed: {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8090")
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/template-demo"))
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    with httpx.Client(base_url=base_url, timeout=30) as client:
        response = client.get("/api/template")
        response.raise_for_status()
        template_path = output / "01-downloaded-customer-template.xlsx"
        template_path.write_bytes(response.content)

        workbook = load_workbook(template_path)
        metadata = workbook["01_Metadata_元数据"]
        sbom = workbook["02_SBOM_Software"]
        metadata["B3"] = "Synthetic Demo Product"
        metadata["B4"] = "2.4.0-rc.1-demo"
        metadata["B6"] = "synthetic-demo-build"
        sbom.append(
            [
                "S-001",
                "Third-party component 第三方组件",
                "Example Test Vendor",
                "Synthetic Demo Component",
                "1.0-demo",
                "pkg:generic/synthetic-demo-component@1.0-demo",
                "",
                "",
                "Synthetic direct dependency",
                "Clean-clone synthetic fixture",
                "Yes 是",
                "Smoke-test only",
                "Not customer evidence",
                "NOASSERTION",
                DEMO_CVE,
                DEMO_EUVD,
                "Synthetic local test only",
            ]
        )
        demo_path = output / "02-filled-demo-sbom.xlsx"
        workbook.save(demo_path)

        with demo_path.open("rb") as handle:
            preview_response = client.post(
                "/api/uploads/preview",
                files={
                    "file": (
                        demo_path.name,
                        handle,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                },
            )
        preview_response.raise_for_status()
        preview = preview_response.json()
        require(preview["row_count"] == 1, "one synthetic component parsed")
        require(not preview["automatic_conformity_decision"], "no automatic conformity decision")

        job_response = client.post(
            "/api/jobs",
            json={
                "upload_id": preview["upload_id"],
                "mapping": preview["mapping"],
                "project_name": "Synthetic Demo Product",
                "project_version": "2.4.0-rc.1-demo",
                "software_build": "synthetic-demo-build",
                "customer": "Synthetic local smoke test",
            },
        )
        job_response.raise_for_status()
        job = job_response.json()
        deadline = time.monotonic() + 180
        while job["status"] not in {"completed", "failed"} and time.monotonic() < deadline:
            time.sleep(0.5)
            poll = client.get(f"/api/jobs/{job['id']}")
            poll.raise_for_status()
            job = poll.json()
        require(job["status"] == "completed", f"job status is {job['status']}")
        matches = job.get("result", {}).get("matches", [])
        require(any(row.get("euvd_id") == DEMO_EUVD for row in matches), "synthetic EUVD match")
        require(
            all(row.get("art14_readiness") != "reportable" for row in matches),
            "no automatic CRA Article 14 reportability",
        )
        report = client.get(job["report_url"])
        report.raise_for_status()
        report_path = output / "03-synthetic-match-report.xlsx"
        report_path.write_bytes(report.content)

    result = {
        "status": "PASS",
        "source": "SYNTHETIC_DEMO_NOT_EUVD",
        "template_file": template_path.name,
        "demo_file": demo_path.name,
        "report_file": report_path.name,
        "job_id": job["id"],
        "compliance_boundary": (
            "PASS proves only the local synthetic software path. It is not current "
            "EUVD intelligence, customer evidence, CRA Article 14/SRP, conformity, "
            "customer delivery, or release approval."
        ),
    }
    (output / "DEMO_RESULT.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
