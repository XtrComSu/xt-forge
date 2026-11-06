"""Tests for the reverse engineering CLI interface."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_re_pe import create_minimal_pe


class TestRECLI(unittest.TestCase):
    def test_re_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("cfg", res.stdout)
        self.assertIn("view", res.stdout)
        self.assertIn("xrefs", res.stdout)

    def test_re_pe_info_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "sample.exe"
            p_pe.write_bytes(
                create_minimal_pe(
                    bits=64,
                    sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
                    tls_callbacks=[0x140001050],
                )
            )

            res = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "re", "pe", "info", str(p_pe)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertTrue(data.get("ok"))
            self.assertEqual(data.get("format"), "PE32+")
            self.assertIn("0x140001050", data.get("tls_callbacks", []))

    def test_re_view_generates_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "sample.exe"
            p_pe.write_bytes(create_minimal_pe(bits=64))
            out_html = Path(tmpdir) / "view.html"

            res = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "re", "view", str(p_pe), "--out", str(out_html)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(out_html.exists())
            self.assertIn("XT-Forge Reverse Engineering Workbench", out_html.read_text(encoding="utf-8"))

    def test_re_pe_exports_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "sample.dll"
            p_pe.write_bytes(
                create_minimal_pe(
                    bits=64,
                    sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
                    exports=[("HookEntry", 0x1040, 1)],
                )
            )

            res = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "re", "pe", "exports", str(p_pe)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertTrue(data.get("ok"))
            self.assertEqual(data["exports"][0]["name"], "HookEntry")

    def test_re_capa_and_crash_cli(self):
        from tests.test_re_crash import create_synthetic_minidump
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "sample.exe"
            p_pe.write_bytes(
                create_minimal_pe(
                    bits=64,
                    sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
                    imports={"kernel32.dll": ["IsDebuggerPresent"]},
                )
            )

            res = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "re", "capa", str(p_pe)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertTrue(data.get("ok"))
            caps = [c["name"] for c in data.get("capabilities", [])]
            self.assertIn("anti_debugging", caps)

            p_dmp = Path(tmpdir) / "crash.dmp"
            p_dmp.write_bytes(create_synthetic_minidump())
            res_crash = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "re", "crash", str(p_dmp)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_crash.returncode, 0, res_crash.stderr)
            data_crash = json.loads(res_crash.stdout)
            self.assertTrue(data_crash.get("ok"))
            self.assertEqual(data_crash.get("format"), "minidump")
            self.assertEqual(data_crash["exception"]["code"], "0xc0000005")

