"""Tests for behavioral capability detection."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.capa import detect_capabilities
from tests.test_re_pe import create_minimal_pe


class TestCapaEngine(unittest.TestCase):
    def test_detect_anti_debug_and_injection(self):
        pe_bytes = create_minimal_pe(
            bits=64,
            sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
            imports={
                "kernel32.dll": ["IsDebuggerPresent", "CreateRemoteThread", "VirtualAllocEx"],
                "advapi32.dll": ["AdjustTokenPrivileges", "OpenProcessToken"],
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "sample.exe"
            fpath.write_bytes(pe_bytes)

            res = detect_capabilities(fpath)
            self.assertTrue(res["ok"])
            caps = res.get("capabilities", [])
            cap_names = [c["name"] for c in caps]
            self.assertIn("anti_debugging", cap_names)
            self.assertIn("process_injection", cap_names)
            self.assertIn("privilege_manipulation", cap_names)
