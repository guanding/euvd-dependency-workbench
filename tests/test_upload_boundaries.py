from __future__ import annotations

import asyncio
import io
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException, UploadFile

from app import main


def cyclonedx_payload(component_count: int) -> bytes:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-upload-boundary",
        "version": 1,
        "metadata": {"timestamp": "2026-08-04T00:00:00Z"},
        "components": [
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/example-{index}@1.0",
                "name": f"example-{index}",
                "version": "1.0",
                "purl": f"pkg:pypi/example-{index}@1.0",
            }
            for index in range(component_count)
        ],
        "dependencies": [],
    }
    return json.dumps(payload).encode("utf-8")


class UploadBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.upload_dir = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _upload(self, payload: bytes) -> dict[str, object]:
        upload = UploadFile(
            filename="test.cdx.json",
            file=io.BytesIO(payload),
        )
        with patch.object(main, "UPLOAD_DIR", self.upload_dir):
            return asyncio.run(main.upload_preview(upload))

    def test_preview_persists_compact_record_and_hash_bound_evidence(self) -> None:
        response = self._upload(cyclonedx_payload(2))
        self.assertNotIn("sbom_metadata", response)
        self.assertNotIn("dependencies", response)
        self.assertEqual(response["dependency_count"], 0)
        upload_id = str(response["upload_id"])
        record_path = self.upload_dir / f"{upload_id}.upload-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        raw_path = self.upload_dir / record["source_document_reference"]["file_name"]
        self.assertNotEqual(raw_path, record_path)
        self.assertEqual(
            hashlib.sha256(raw_path.read_bytes()).hexdigest(),
            record["source_sha256"],
        )
        for duplicate in (
            "source_document",
            "source_components",
            "sbom_metadata",
            "dependencies",
        ):
            self.assertNotIn(duplicate, record["parsed"])
        evidence = record["pre7_evidence_artifact"]
        self.assertTrue((self.upload_dir / evidence["file_name"]).is_file())
        rq07 = record["parsed"]["pre7_evidence_summary"]["requirements"][
            "PRE-7-RQ-07"
        ]
        self.assertEqual(rq07["item_count"], 2)
        self.assertNotIn("items", rq07)

    def test_component_limit_rejects_before_upload_record_persistence(self) -> None:
        with patch.object(main, "MAX_COMPONENTS", 2):
            with self.assertRaises(HTTPException) as caught:
                self._upload(cyclonedx_payload(3))
        self.assertEqual(caught.exception.status_code, 413)
        self.assertEqual(list(self.upload_dir.iterdir()), [])

    def test_purge_old_uploads_respects_dry_run_and_disabled(self) -> None:
        from app.main import _purge_old_uploads

        old = self.upload_dir / "old.json"
        old.write_text("x")
        past = time.time() - 10 * 24 * 3600
        os.utime(old, (past, past))
        new = self.upload_dir / "new.json"
        new.write_text("x")
        # dry_run reports the old file but deletes nothing
        self.assertEqual(
            _purge_old_uploads(self.upload_dir, 7, dry_run=True), ["old.json"]
        )
        self.assertTrue(old.exists())
        # real run deletes old, keeps new
        _purge_old_uploads(self.upload_dir, 7, dry_run=False)
        self.assertFalse(old.exists())
        self.assertTrue(new.exists())
        # purge_days<=0 disables purging entirely
        new2 = self.upload_dir / "new2.json"
        new2.write_text("x")
        os.utime(new2, (past, past))
        self.assertEqual(_purge_old_uploads(self.upload_dir, 0), [])
        self.assertTrue(new2.exists())


if __name__ == "__main__":
    unittest.main()
