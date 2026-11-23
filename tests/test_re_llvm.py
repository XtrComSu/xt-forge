"""Tests for the read-only LLVM toolchain bridge."""
from __future__ import annotations

import sys
import unittest

from xtforge.core.re import llvm


class LLVMBridgeTests(unittest.TestCase):
    def test_tool_path_bogus_name(self) -> None:
        self.assertIsNone(llvm.tool_path("definitely-not-a-real-tool"))

    def test_available_keys_and_values(self) -> None:
        result = llvm.available()
        self.assertEqual(set(result), set(llvm.LLVM_TOOLS))
        self.assertEqual(len(result), 5)
        for value in result.values():
            self.assertIsInstance(value, bool)

    def test_run_tool_missing_tool(self) -> None:
        result = llvm.run_tool("nope", [])
        self.assertFalse(result["ok"])
        self.assertIn("error", result)
        self.assertEqual(result["tool"], "nope")

    def test_sections_nonexistent_path(self) -> None:
        self.assertEqual(llvm.sections("/no/such/file-here"), [])

    def test_symbols_nonexistent_path(self) -> None:
        self.assertEqual(llvm.symbols("/no/such/file-here"), [])

    @unittest.skipUnless(llvm.tool_path("nm"), "llvm-nm not installed")
    def test_run_tool_on_python_binary(self) -> None:
        result = llvm.run_tool("nm", ["-a", "--no-sort", sys.executable])
        self.assertTrue(result["ok"], msg=result.get("error", ""))
        self.assertIn("stdout", result)
        self.assertIsNone(result.get("error"))

    @unittest.skipUnless(llvm.tool_path("readobj"), "llvm-readobj not installed")
    def test_sections_parses_elf(self) -> None:
        rows = llvm.sections("/bin/ls")
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(set(row), {"name", "address", "size"})
            self.assertIsInstance(row["name"], str)
            self.assertIsInstance(row["address"], int)
            self.assertIsInstance(row["size"], int)


if __name__ == "__main__":
    unittest.main()
