from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AccessibilityContractTests(unittest.TestCase):
    def test_core_keyboard_and_status_contracts_are_present(self) -> None:
        html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
        css = (ROOT / "app" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('id="dropZone" class="drop-zone" for="fileInput" role="button" tabindex="0"', html)
        self.assertIn('id="receiptZone" class="drop-zone drop-zone-secondary" for="receiptInput" role="button" tabindex="0"', html)
        self.assertIn('role="progressbar"', html)
        self.assertIn('aria-valuenow="0"', html)
        self.assertIn('aria-label="下载 SBOM 模板"', html)
        self.assertIn('aria-label="导入 SBOM"', html)
        self.assertIn('aria-pressed="true"', html)
        self.assertIn('event.key === "Enter" || event.key === " "', script)
        self.assertIn('setAttribute("aria-valuenow"', script)
        self.assertIn('setAttribute("aria-pressed"', script)
        self.assertIn("prefers-reduced-motion: reduce", css)
        self.assertIn("outline: 3px solid #075f69", css)


if __name__ == "__main__":
    unittest.main()
