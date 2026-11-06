"""Tests for normalized binary CFG diffing."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.diff import diff_binaries
from tests.test_re_pe import create_minimal_pe


class TestBinaryDiffing(unittest.TestCase):
    def test_diff_two_versions(self):
        # Version 1: 2 functions (FnA and FnB)
        pe1_bytes = create_minimal_pe(
            bits=64,
            sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
            exports=[("FnA", 0x1010, 1), ("FnB", 0x1040, 2)],
        )

        # Version 2: FnA is same, FnB has different code, FnC is added
        pe2_bytes = create_minimal_pe(
            bits=64,
            sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
            exports=[("FnA", 0x1010, 1), ("FnB", 0x1050, 2), ("FnC", 0x1090, 3)],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "v1.dll"
            p2 = Path(tmpdir) / "v2.dll"
            p1.write_bytes(pe1_bytes)
            p2.write_bytes(pe2_bytes)

            res = diff_binaries(p1, p2)
            self.assertTrue(res["ok"])
            self.assertEqual(res["added_count"], 1)
            self.assertIn("FnC", res["added_functions"])
            self.assertEqual(res["removed_count"], 0)
            self.assertIn("FnA", res["matched_functions"])
            self.assertIn("FnB", res["matched_functions"])
