"""Tests for advanced stack string and XOR string extraction."""
from __future__ import annotations

import unittest
from xtforge.core.re.native import extract_stack_strings, extract_xor_strings

SAMPLE_STACK_DISASM = """
0000000000001000 <build_secret>:
    1000:	c6 45 f0 68          	movb   $0x68,-0x10(%rbp)
    1004:	c6 45 f1 74          	movb   $0x74,-0xf(%rbp)
    1008:	c6 45 f2 74          	movb   $0x74,-0xe(%rbp)
    100c:	c6 45 f3 70          	movb   $0x70,-0xd(%rbp)
    1010:	c6 45 f4 3a          	movb   $0x3a,-0xc(%rbp)
    1014:	c6 45 f5 2f          	movb   $0x2f,-0xb(%rbp)
    1018:	c6 45 f6 2f          	movb   $0x2f,-0xa(%rbp)
    101c:	c6 45 f7 00          	movb   $0x0,-0x9(%rbp)
    1020:	c3                   	ret
"""


class TestAdvancedStrings(unittest.TestCase):
    def test_extract_stack_strings(self):
        res = extract_stack_strings(SAMPLE_STACK_DISASM)
        self.assertGreaterEqual(len(res), 1)
        found_strings = [s["string"] for s in res]
        self.assertIn("http://", found_strings)

    def test_extract_xor_strings(self):
        # "admin_bypass_token" XOR 0x5A
        plain = b"admin_bypass_token"
        xor_key = 0x5A
        cipher = bytes(b ^ xor_key for b in plain)
        blob = b"\x00" * 32 + cipher + b"\x00" * 32

        res = extract_xor_strings(blob, min_len=6)
        self.assertGreaterEqual(len(res), 1)
        matches = [r for r in res if r["key"] == xor_key]
        self.assertTrue(matches)
        self.assertEqual(matches[0]["string"], "admin_bypass_token")
