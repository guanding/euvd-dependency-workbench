from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class VexUiContractTests(unittest.TestCase):
    def test_frontend_submits_all_required_fail_closed_fields(self) -> None:
        html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="vexFileInput"', html)
        self.assertIn('id="vexReceiptInput"', html)
        self.assertIn('id="vexIssuerId"', html)
        self.assertIn("默认 fail-closed", html)
        self.assertIn('form.append("file"', script)
        self.assertIn('form.append("receipt"', script)
        self.assertIn('form.append("issuer_id"', script)
        self.assertIn("请选择与 VEX 字节绑定", script)


if __name__ == "__main__":
    unittest.main()
