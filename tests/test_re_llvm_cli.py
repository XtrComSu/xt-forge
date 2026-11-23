"""CLI tests for the `re llvm` subcommands."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from xtforge.core.re import llvm

TOOL_NAMES = {"objdump", "readobj", "nm", "otool", "dwarfdump"}


class TestReLlvmCli(unittest.TestCase):
    def _cli(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "--json", "re", "llvm", *argv],
            capture_output=True,
            text=True,
        )

    def test_available_prints_five_tool_names(self):
        res = self._cli("available")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"))
        self.assertEqual(set(data.get("tools", {})), TOOL_NAMES)
        for name in sorted(TOOL_NAMES):
            self.assertIn(name, res.stdout)

    def test_tools_alias_matches_available(self):
        res = self._cli("tools")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"))
        self.assertEqual(set(data.get("tools", {})), TOOL_NAMES)

    @unittest.skipUnless(all(llvm.available()[t] for t in ("objdump", "readobj")),
                         "LLVM section tools not installed")
    def test_sections_on_real_binary_returns_list(self):
        res = self._cli("sections", sys.executable)
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"))
        self.assertIsInstance(data.get("sections"), list)

    @unittest.skipUnless(llvm.available()["nm"], "llvm-nm not installed")
    def test_symbols_on_real_binary_returns_list(self):
        res = self._cli("symbols", sys.executable)
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"))
        self.assertIsInstance(data.get("symbols"), list)

    def test_unknown_verb_exits_nonzero_with_error(self):
        res = self._cli("not-a-verb")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("error", (res.stdout + res.stderr).lower())
        data = json.loads(res.stdout)
        self.assertFalse(data.get("ok"))


if __name__ == "__main__":
    unittest.main()
