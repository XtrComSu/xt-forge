"""Tests for safe atomic binary patcher."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.patch import PatchError, apply_patch


class TestBinaryPatcher(unittest.TestCase):
    def test_apply_patch_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_file = Path(tmpdir) / "app.dll"
            # je 0x10 (74 0e) followed by padding
            data = bytearray(b"\x90" * 16 + b"\x74\x0e" + b"\x90" * 16)
            orig_file.write_bytes(data)

            # Patch 74 0e to 90 90 (NOP)
            res = apply_patch(
                orig_file,
                offset=16,
                patch_bytes=b"\x90\x90",
                original_bytes=b"\x74\x0e",
            )
            self.assertTrue(res["ok"])
            patched_path = Path(res["out_path"])
            self.assertTrue(patched_path.exists())
            patched_bytes = patched_path.read_bytes()
            self.assertEqual(patched_bytes[16:18], b"\x90\x90")
            # Original file remains untouched
            self.assertEqual(orig_file.read_bytes()[16:18], b"\x74\x0e")

    def test_original_bytes_mismatch_raises_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_file = Path(tmpdir) / "app.dll"
            orig_file.write_bytes(b"\x90" * 32)

            with self.assertRaises(PatchError):
                apply_patch(
                    orig_file,
                    offset=16,
                    patch_bytes=b"\xcc\xcc",
                    original_bytes=b"\x74\x0e",  # Expecting 74 0e, but it's 90 90
                )
