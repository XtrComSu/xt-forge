"""Tests for self-contained, airgapped visual companion generator."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.companion import render_html_companion


class TestVisualCompanion(unittest.TestCase):
    def test_render_standalone_html(self):
        info = {
            "format": "PE32+",
            "machine": "x86-64",
            "entry_point": "0x1000",
            "image_base": "0x140000000",
            "sections": [
                {"name": ".text", "rva": "0x1000", "virtual_size": 4096, "raw_size": 4096, "entropy": 6.1},
                {"name": ".data", "rva": "0x2000", "virtual_size": 1024, "raw_size": 512, "entropy": 2.3},
            ],
        }
        cfg = {
            "symbol": "main",
            "blocks": [
                {
                    "id": "b_1000",
                    "start_rva": "0x1000",
                    "end_rva": "0x1008",
                    "instruction_count": 2,
                    "instructions": [
                        {"address": 0x1000, "hex_address": "0x1000", "mnemonic": "sub", "operands": "$0x8, %rsp"},
                        {"address": 0x1004, "hex_address": "0x1004", "mnemonic": "je", "operands": "0x1010"},
                    ],
                },
                {
                    "id": "b_1010",
                    "start_rva": "0x1010",
                    "end_rva": "0x1012",
                    "instruction_count": 1,
                    "instructions": [
                        {"address": 0x1010, "hex_address": "0x1010", "mnemonic": "ret", "operands": ""},
                    ],
                },
            ],
            "edges": [
                {"from": "b_1000", "to": "b_1010", "type": "conditional_true"},
            ],
        }

        html = render_html_companion("test.dll", info, cfg=cfg)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("XT-Forge Reverse Engineering Workbench", html)
        self.assertIn("test.dll", html)
        self.assertIn("b_1000", html)
        self.assertIn("b_1010", html)
        self.assertIn("conditional_true", html)
        # Verify strictly airgapped: no http or https script/link resources
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)

    def test_render_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "companion.html"
            info = {"format": "ELF64", "machine": "x86-64", "entry_point": "0x1000", "sections": []}
            render_html_companion("binary", info, cfg=None, out_path=out_file)
            self.assertTrue(out_file.exists())
            content = out_file.read_text(encoding="utf-8")
            self.assertIn("XT-Forge Reverse Engineering Workbench", content)
