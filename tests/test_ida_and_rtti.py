"""Tests for IDA Pro bridge + offline Borer/Ghidra fallback and stripped C++ ELF RTTI recovery."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.adapters.ida_mcp import TOOLS, _handle, _handle_tool
from xtforge.core.re import ida, rtti


class TestIdaAndStrippedRtti(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xt_ida_rtti_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ida_mcp_surface_and_status(self) -> None:
        self.assertGreaterEqual(len(TOOLS), 14)
        init = _handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIsNotNone(init)
        self.assertEqual(init["result"]["serverInfo"]["name"], "xt-forge-ida-mcp")
        st = _handle_tool("ida_status", {})
        self.assertTrue(st["ok"])
        self.assertIn("fallback_engines", st)

    def test_idb_container_inspection(self) -> None:
        fake_bin = self.tmp / "sample.bin"
        fake_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)
        fake_i64 = self.tmp / "sample.i64"
        fake_i64.write_bytes(b"IDA2" + b"\x00" * 60)
        res = ida.inspect_idb(fake_i64)
        self.assertTrue(res["ok"])
        self.assertEqual(res["bitness"], 64)
        self.assertEqual(res["companion_binary"], str(fake_bin))

    def test_stripped_elf_itanium_rtti_recovery(self) -> None:
        cxx = shutil.which("g++") or shutil.which("clang++")
        if not cxx:
            self.skipTest("g++ or clang++ not installed")
        src = self.tmp / "rtti_sample.cpp"
        out_bin = self.tmp / "rtti_sample"
        src.write_text(
            "class BaseOp { public: virtual ~BaseOp() = default; virtual int tag() const = 0; };\n"
            "class AlphaOp : public BaseOp { public: int tag() const override { return 0x41; } };\n"
            "class BetaOp : public BaseOp { public: int tag() const override { return 0x42; } };\n"
            "int main(int argc, char **) {\n"
            "    BaseOp *op = argc > 1 ? static_cast<BaseOp*>(new AlphaOp()) : static_cast<BaseOp*>(new BetaOp());\n"
            "    return op->tag();\n"
            "}\n",
            encoding="utf-8",
        )
        proc = subprocess.run([cxx, "-O2", "-s", str(src), "-o", str(out_bin)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = rtti.extract_rtti(out_bin)
        self.assertTrue(res["ok"], res)
        names = {c["name"] for c in res["classes"]}
        self.assertIn("AlphaOp", names)
        self.assertIn("BetaOp", names)
        alpha = next(c for c in res["classes"] if c["name"] == "AlphaOp")
        self.assertGreaterEqual(alpha["method_count"], 1)
        decompiled = ida.ida_decompile(out_bin, alpha["methods"][-1])
        self.assertTrue(decompiled.get("ok"), decompiled)


if __name__ == "__main__":
    unittest.main()
