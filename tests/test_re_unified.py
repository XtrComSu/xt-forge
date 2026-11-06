"""Tests for unified multi-format reverse engineering abstractions."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.native import get_info, get_sections, get_symbols, sniff_format
from tests.test_re_pe import create_minimal_pe


class TestUnifiedRE(unittest.TestCase):
    def test_sniff_format_bytes(self):
        self.assertEqual(sniff_format(b"\x7fELF\x02\x01\x01\x00"), "elf")
        self.assertEqual(sniff_format(b"MZ\x90\x00\x03\x00\x00\x00"), "pe")
        self.assertEqual(sniff_format(b"GIF89a\x01\x00"), "unknown")
        self.assertEqual(sniff_format(b""), "unknown")

    def test_sniff_format_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_elf = Path(tmpdir) / "sample_elf"
            p_elf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\0" * 64)
            p_pe = Path(tmpdir) / "sample_pe.exe"
            p_pe.write_bytes(create_minimal_pe(bits=64))
            p_txt = Path(tmpdir) / "sample.txt"
            p_txt.write_bytes(b"hello world\n")

            self.assertEqual(sniff_format(p_elf), "elf")
            self.assertEqual(sniff_format(p_pe), "pe")
            self.assertEqual(sniff_format(p_txt), "unknown")

    def test_get_info_pe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "test.dll"
            p_pe.write_bytes(
                create_minimal_pe(
                    bits=64,
                    sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
                    tls_callbacks=[0x140001050],
                )
            )
            res = get_info(p_pe)
            self.assertTrue(res["ok"])
            self.assertEqual(res["format"], "PE32+")
            self.assertEqual(res["machine"], "x86-64")
            self.assertIn("0x140001050", res["tls_callbacks"])

    def test_get_sections_pe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "test.dll"
            p_pe.write_bytes(
                create_minimal_pe(
                    bits=64,
                    sections=[(".text", 0x1000, 0x1000, b"\x90\xc3" * 512, 0x60000020)],
                )
            )
            res = get_sections(p_pe)
            self.assertTrue(res["ok"])
            self.assertEqual(len(res["sections"]), 1)
            self.assertEqual(res["sections"][0]["name"], ".text")

    def test_get_symbols_pe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_pe = Path(tmpdir) / "test.dll"
            p_pe.write_bytes(
                create_minimal_pe(
                    bits=64,
                    sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
                    exports=[("ExportedFn", 0x1020, 1)],
                )
            )
            res = get_symbols(p_pe)
            self.assertTrue(res["ok"])
            self.assertGreaterEqual(len(res["symbols"]), 1)
            self.assertEqual(res["symbols"][0]["name"], "ExportedFn")
