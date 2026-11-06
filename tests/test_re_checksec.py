"""Tests for checksec binary hardening analysis."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.native import checksec
from tests.test_re_pe import create_minimal_pe


class TestChecksec(unittest.TestCase):
    def test_checksec_pe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "test.dll"
            # create_minimal_pe has dll_chars = 0x8160 by default:
            # 0x0020 (HIGH_ENTROPY_VA), 0x0040 (DYNAMIC_BASE/ASLR), 0x0100 (NX_COMPAT), 0x8000 (TERMINAL_SERVER_AWARE)
            p_pe.write_bytes(create_minimal_pe(bits=64))
            res = checksec(p_pe)
            self.assertTrue(res["ok"])
            self.assertEqual(res["format"], "pe")
            mitigations = res["mitigations"]
            self.assertTrue(mitigations["aslr"])
            self.assertTrue(mitigations["dep_nx"])
            self.assertTrue(mitigations["high_entropy_va"])

    def test_checksec_elf(self):
        # We can test against a system binary like /bin/sh or /bin/ls if accessible
        sh_path = Path("/bin/sh")
        if sh_path.exists():
            res = checksec(sh_path)
            self.assertTrue(res["ok"])
            self.assertEqual(res["format"], "elf")
            self.assertIn("nx", res["mitigations"])
