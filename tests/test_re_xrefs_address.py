"""Cross-reference lookup by address, in every spelling an address arrives in.

Found by spot-checking a "covered" row rather than an excluded one — the mirror of the exclusion
audit. `re xrefs <bin> 0x1139` and `re xrefs <bin> helper` both reported **0 cross-references**
for a function `objdump` plainly shows being called, and with no target at all it returned
"0 cross-references to None", which reads like a completed search.

Two separate defects were behind that:

  * `parse_xrefs_from_disasm` compared the caller's string against the operand text, but objdump
    writes branch targets with no `0x` prefix (`call 1139 <helper>`), so `0x1139` matched
    nothing.
  * the CLI captured the symbol positional into `xref_target` but never swapped `path` to the
    binary, so the binary was `helper` and the real target was discarded.

Both are asserted here against real objdump output, because the whole bug was a disagreement
about a string format and a fixture could encode the same wrong assumption.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import analysis

SOURCE = """
#include <stdio.h>
static int helper(int n) { return n * 3; }
static int other(int n) { return n + 1; }
int main(void) { printf("%d %d\\n", helper(6), other(6)); return 0; }
"""


class ParserTest(unittest.TestCase):
    """The operand comparison, against synthetic objdump text with known call targets."""

    DISASM = """0000000000001000 <f>:
    1000:\te8 34 00 00 00       \tcall   1039 <other>
    1005:\te8 34 01 00 00       \tcall   1139 <target>
    100a:\te8 2f 00 00 00       \tcall   103e <third>
"""

    def test_a_prefixed_hex_address_matches(self) -> None:
        """This is the bug: objdump writes `1139`, the caller passes `0x1139`."""
        found = analysis.parse_xrefs_from_disasm(self.DISASM, "0x1139")
        self.assertEqual(len(found), 1)
        self.assertIn("1139", found[0]["operands"])

    def test_a_bare_hex_address_matches(self) -> None:
        self.assertEqual(len(analysis.parse_xrefs_from_disasm(self.DISASM, "1139")), 1)

    def test_an_integer_address_matches(self) -> None:
        self.assertEqual(len(analysis.parse_xrefs_from_disasm(self.DISASM, 0x1139)), 1)

    def test_a_symbol_name_still_matches(self) -> None:
        found = analysis.parse_xrefs_from_disasm(self.DISASM, "target")
        self.assertEqual(len(found), 1)

    def test_neighbouring_addresses_do_not_collide(self) -> None:
        """`1139` must not match `11390`, and `1039` must not match `103e`."""
        for address, expected in (("0x1039", "other"), ("0x103e", "third"),
                                  ("0x1139", "target")):
            found = analysis.parse_xrefs_from_disasm(self.DISASM, address)
            self.assertEqual(len(found), 1, f"{address} matched {len(found)} lines")
            self.assertIn(expected, found[0]["operands"])
        self.assertEqual(analysis.parse_xrefs_from_disasm(self.DISASM, "0x113"), [])

    def test_an_absent_address_matches_nothing(self) -> None:
        self.assertEqual(analysis.parse_xrefs_from_disasm(self.DISASM, "0x9999"), [])


class RealBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("gcc") or not shutil.which("objdump"):
            raise unittest.SkipTest("needs gcc and objdump")
        cls.directory = tempfile.mkdtemp(prefix="xtxr-")
        source = Path(cls.directory) / "x.c"
        source.write_text(SOURCE)
        # -O0 and no inlining, so both helpers really are called.
        cls.binary = Path(cls.directory) / "x"
        built = subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-o", str(cls.binary),
                                str(source)], capture_output=True, text=True)
        if built.returncode != 0:
            raise unittest.SkipTest(f"build failed: {built.stderr[:150]}")
        cls.nm = subprocess.run(["nm", str(cls.binary)], capture_output=True,
                                text=True).stdout

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(getattr(cls, "directory", ""), ignore_errors=True)

    def address_of(self, name: str) -> str | None:
        for line in self.nm.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == name:
                return f"0x{int(parts[0], 16):x}"
        return None

    def test_by_symbol_finds_the_caller(self) -> None:
        report = analysis.find_xrefs(self.binary, "helper")
        self.assertTrue(report["ok"], report.get("err"))
        self.assertGreaterEqual(report["count"], 1)
        self.assertEqual(report["xrefs"][0]["caller"], "main")

    def test_by_address_finds_the_same_caller(self) -> None:
        """The claim that matters: both spellings answer the same question identically."""
        address = self.address_of("helper")
        self.assertIsNotNone(address, "nm did not report helper")
        by_symbol = analysis.find_xrefs(self.binary, "helper")
        by_address = analysis.find_xrefs(self.binary, address)
        self.assertEqual(by_address["count"], by_symbol["count"])
        self.assertEqual(by_address["xrefs"][0]["caller"],
                         by_symbol["xrefs"][0]["caller"])

    def test_the_caller_really_does_call_it(self) -> None:
        """Independent oracle: objdump's own text must show the call this reports."""
        address = self.address_of("helper")
        text = subprocess.run(["objdump", "-d", str(self.binary)],
                              capture_output=True, text=True).stdout
        calls = [line for line in text.splitlines()
                 if "call" in line and address[2:] in line]
        self.assertTrue(calls, "objdump shows no call to the address under test")

    def test_two_different_targets_do_not_share_callers(self) -> None:
        """A too-loose match would make every lookup return every caller."""
        helper = analysis.find_xrefs(self.binary, "helper")
        other = analysis.find_xrefs(self.binary, "other")
        self.assertNotEqual([item["address"] for item in helper["xrefs"]],
                            [item["address"] for item in other["xrefs"]],
                            "both targets resolved to the same call sites")


class RefusalTest(RealBinaryTest):
    def test_no_target_is_refused_rather_than_listing_everything(self) -> None:
        """With no target the engine returned 98 rows headed "cross-references to :"."""
        from xtforge.cli import build_parser
        parsed = build_parser().parse_args(["re", "xrefs", "/bin/ls"])
        self.assertEqual(parsed.value, "/bin/ls")
        self.assertFalse(parsed.path, "the second positional should be empty")

    def _run_cli(self, *argv: str) -> dict:
        """Drive `cmd_re` itself, because the bug was in its dispatch, not the parser.

        Asserting only on `build_parser` output proved nothing: removing the `path` swap left
        every test green while the CLI still searched for a binary named `helper`.
        """
        import json
        import types
        import contextlib
        import io
        from xtforge.cli import scan_cmd
        args = types.SimpleNamespace(
            re_verb="xrefs", value=argv[0], path=(argv[1] if len(argv) > 1 else None),
            extra=[], json=True, limit=50, symbol=None, target=None, format=None)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            try:
                scan_cmd.cmd_re(args)
            except SystemExit:
                pass
        text = buffer.getvalue().strip()
        self.assertTrue(text, "cmd_re produced no output")
        return json.loads(text)

    def test_the_cli_searches_the_binary_not_the_symbol(self) -> None:
        """`re xrefs <bin> helper` must treat `helper` as the target, not as the file."""
        address = self.address_of("helper")
        by_symbol = self._run_cli(str(self.binary), "helper")
        self.assertTrue(by_symbol.get("ok"), by_symbol)
        self.assertGreaterEqual(by_symbol["count"], 1)
        self.assertEqual(by_symbol["path"], str(self.binary),
                         "the binary path was replaced by the symbol")
        by_address = self._run_cli(str(self.binary), address)
        self.assertEqual(by_address["count"], by_symbol["count"])

    def test_the_cli_refuses_an_empty_target(self) -> None:
        report = self._run_cli(str(self.binary))
        self.assertFalse(report.get("ok"))
        self.assertIn("needs a target", report["error"])


if __name__ == "__main__":
    unittest.main()
