"""Tests for dual-engine CFG reconstruction and cross-reference analysis."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.analysis import build_cfg, find_xrefs, get_block, parse_blocks_from_disasm
from tests.test_re_pe import create_minimal_pe

SAMPLE_ASM = """
0000000000001000 <func>:
    1000:	48 83 ec 08          	sub    $0x8,%rsp
    1004:	85 ff                	test   %edi,%edi
    1006:	74 08                	je     1010 <func+0x10>
    1008:	b8 01 00 00 00       	mov    $0x1,%eax
    100d:	59                   	pop    %rcx
    100e:	c3                   	ret
    1010:	31 c0                	xor    %eax,%eax
    1012:	59                   	pop    %rcx
    1013:	c3                   	ret
"""


class TestAnalysisEngine(unittest.TestCase):
    def test_parse_blocks_from_disasm(self):
        cfg = parse_blocks_from_disasm(SAMPLE_ASM, "func", 0x1000)
        self.assertEqual(len(cfg["blocks"]), 3)
        self.assertEqual(cfg["blocks"][0]["id"], "b_1000")
        self.assertEqual(cfg["blocks"][1]["id"], "b_1008")
        self.assertEqual(cfg["blocks"][2]["id"], "b_1010")

        # Check edge classifications
        edges = cfg["edges"]
        # Block b_1000 branches to b_1010 (conditional_true) and falls through to b_1008 (conditional_false)
        self.assertEqual(len(edges), 2)
        edge_types = {(e["from"], e["to"]): e["type"] for e in edges}
        self.assertEqual(edge_types.get(("b_1000", "b_1010")), "conditional_true")
        self.assertEqual(edge_types.get(("b_1000", "b_1008")), "conditional_false")

    def test_token_bounding_behavior(self):
        # When max_instructions is small, block instructions are omitted
        cfg = parse_blocks_from_disasm(SAMPLE_ASM, "func", 0x1000, max_instructions=2)
        self.assertTrue(cfg["truncated_instructions"])
        self.assertIsNone(cfg["blocks"][0]["instructions"])

        # When max_instructions is large enough, block instructions are present
        cfg_full = parse_blocks_from_disasm(SAMPLE_ASM, "func", 0x1000, max_instructions=50)
        self.assertFalse(cfg_full["truncated_instructions"])
        self.assertIsNotNone(cfg_full["blocks"][0]["instructions"])
        self.assertEqual(len(cfg_full["blocks"][0]["instructions"]), 3)

    def test_find_xrefs_in_disasm(self):
        sample_with_calls = """
0000000000001000 <caller1>:
    1000:	e8 1b 00 00 00       	call   1020 <target_fn>
    1005:	c3                   	ret

0000000000001010 <caller2>:
    1010:	e8 0b 00 00 00       	call   1020 <target_fn>
    1015:	c3                   	ret

0000000000001020 <target_fn>:
    1020:	31 c0                	xor    %eax,%eax
    1022:	c3                   	ret
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "test.bin"
            fpath.write_bytes(b"\x90" * 64)
            # Use find_xrefs with raw disassembly text or mock
            from xtforge.core.re.analysis import parse_xrefs_from_disasm
            refs = parse_xrefs_from_disasm(sample_with_calls, "target_fn")
            self.assertEqual(len(refs), 2)
            self.assertIn("caller1", [r["caller"] for r in refs])
            self.assertIn("caller2", [r["caller"] for r in refs])

    def test_rizin_fallback_when_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "test.bin"
            fpath.write_bytes(b"\x90" * 64)
            # When explicitly asking for rizin and it fails/missing, returns informative error
            res = build_cfg(fpath, engine="rizin")
            if not res.get("ok"):
                self.assertIn("rizin", res.get("err", "").lower())
            else:
                self.assertEqual(res.get("engine"), "rizin")
