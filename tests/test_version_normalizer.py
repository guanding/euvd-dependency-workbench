"""Tests for the version-expression normalizer (VALIDATION_REPORT §3 #3).

The strict patterns in ``version_is_affected`` leave ~44% of EUVD prose
unparsed (returns None). These tests cover the conservative fuzzy rescue
rules that decide True/False **only** for unambiguous range semantics.
Bare product+version mentions, "fixed in", and placeholders stay None —
human review — because guessing True there would over-include unrelated
older releases.
"""

from __future__ import annotations

import unittest

from app.matcher import version_is_affected


class VersionNormalizerTests(unittest.TestCase):
    # --- "V and later/above/newer" → lower inclusive (affected >= V) ---

    def test_and_later_is_lower_inclusive(self):
        self.assertIs(version_is_affected("2.0", "1.0.19 and later")[0], True)
        self.assertIs(version_is_affected("1.0.0", "1.0.19 and later")[0], False)

    def test_and_above_is_lower_inclusive(self):
        self.assertIs(version_is_affected("3.5", "3.0 and above")[0], True)
        self.assertIs(version_is_affected("2.9", "3.0 and above")[0], False)

    # --- "from X up to (and including) Y" → explicit range ---

    def test_from_up_to_including_is_range(self):
        expr = "from 1.5.0 up to and including 1.5.15"
        self.assertIs(version_is_affected("1.5.10", expr)[0], True)
        self.assertIs(version_is_affected("1.6.0", expr)[0], False)
        self.assertIs(version_is_affected("1.4.0", expr)[0], False)

    def test_from_up_to_without_including_is_range(self):
        expr = "from 1.5.0 up to 1.5.15"
        self.assertIs(version_is_affected("1.5.5", expr)[0], True)
        self.assertIs(version_is_affected("1.4.0", expr)[0], False)

    # --- "before <filler words> V" → upper exclusive (strip filler) ---

    def test_before_with_filler_strips_to_upper_exclusive(self):
        # strict `before V` fails because product-name words sit between
        # 'before' and the version; the normalizer strips them.
        self.assertIs(
            version_is_affected("1.0", "before Linux kernel 2.4.20")[0], True
        )
        self.assertIs(
            version_is_affected("3.0", "before Linux kernel 2.4.20")[0], False
        )

    def test_before_version_keyword_strips(self):
        # "before version 6.16" — 'version' filler between before and number.
        self.assertIs(version_is_affected("6.10", "6.x before version 6.16")[0], True)

    # --- Conservative: no unambiguous semantics → stay None ---

    def test_bare_product_version_stays_none(self):
        self.assertIsNone(version_is_affected("2.8.5", "ytnef 2.8.5")[0])

    def test_placeholder_stays_none(self):
        self.assertIsNone(version_is_affected("1.0", "n/a")[0])
        self.assertIsNone(version_is_affected("1.0", "unknown")[0])

    def test_fixed_in_stays_none(self):
        # "fixed in V" names the fix, not the affected lower bound; deciding
        # True would over-include unrelated older releases.
        self.assertIsNone(version_is_affected("1.0", "fixed in 3.0.1")[0])

    # --- Regression guard: fuzzy must not shadow existing strict matches ---

    def test_strict_patterns_unchanged(self):
        self.assertIs(version_is_affected("2.31.0", "< 2.32.0")[0], True)
        self.assertIs(version_is_affected("2.32.0", "< 2.32.0")[0], False)
        self.assertIs(version_is_affected("2.0", "1.0 through 3.0")[0], True)
        self.assertIs(version_is_affected("3.5", ">=3.0")[0], True)
        self.assertIsNone(version_is_affected("1.0", "selected legacy releases")[0])


if __name__ == "__main__":
    unittest.main()
