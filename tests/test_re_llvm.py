"""Tests for the read-only LLVM toolchain bridge."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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

    @unittest.skipUnless(llvm.tool_path("readobj"), "llvm-readobj not installed")
    def test_elf_sections_have_real_values_not_just_real_types(self) -> None:
        """Types passing is how a zeroed PE survived.

        The test above asserts `address` is an int, and 0 is an int. A parser that
        returned nothing but zeros satisfied it. These assertions are about the
        values: /bin/ls has a mapped .text of nonzero size, and at least one
        section must carry a nonzero address.
        """
        rows = llvm.sections("/bin/ls")
        self.assertTrue(rows, "llvm.sections returned nothing for /bin/ls")
        named = {row["name"]: row for row in rows}
        self.assertIn(".text", named, "no .text section for a real executable")
        self.assertGreater(named[".text"]["size"], 0,
                           ".text reports size 0 on a real binary")
        self.assertTrue(any(row["address"] > 0 for row in rows),
                        "every section reports address 0; the mapping was not parsed")

    @unittest.skipUnless(shutil.which("clang") and shutil.which("lld-link"),
                         "clang and lld-link are required to build a PE fixture")
    def test_pe_sections_report_address_and_size(self) -> None:
        """A PE reported `.text` at address 0 size 0, which reads as an answer.

        Two independent faults produced it: `--macho` was forced on llvm-objdump,
        which emits nothing for a PE while exiting 0, and the readobj fallback
        looked only for COFF's `Address:`/`Size:` fields — COFF calls them
        `VirtualAddress`/`VirtualSize`, so both defaulted to 0.

        The address is compared against llvm-objdump's own VMA rather than merely
        being asserted nonzero, because "nonzero" would also pass for the wrong
        number.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "t.c"
            src.write_text("int main(void){return 42;}\n")
            obj = Path(tmpdir) / "t.obj"
            exe = Path(tmpdir) / "t.exe"
            built = subprocess.run(
                ["clang", "--target=x86_64-pc-windows-msvc", "-c", str(src),
                 "-o", str(obj)], capture_output=True, text=True)
            if built.returncode != 0:  # pragma: no cover - environment dependent
                self.skipTest(f"could not compile a PE object: {built.stderr[:300]}")
            linked = subprocess.run(
                ["lld-link", "/entry:main", "/subsystem:console", f"/out:{exe}",
                 str(obj), "/nodefaultlib"], capture_output=True, text=True)
            if linked.returncode != 0:  # pragma: no cover - environment dependent
                self.skipTest(f"could not link a PE: {linked.stderr[:300]}")

            rows = llvm.sections(str(exe))
            self.assertTrue(rows, "no sections parsed from a valid PE")
            named = {row["name"]: row for row in rows}
            self.assertIn(".text", named,
                          f".text missing from PE sections; got {sorted(named)}")
            self.assertGreater(named[".text"]["size"], 0,
                               "PE .text reports size 0, so the size field was not read")
            self.assertGreater(named[".text"]["address"], 0,
                               "PE .text reports address 0, so the address field was not read")

            # Oracle: llvm-objdump's own VMA for the same section.
            oracle = llvm.run_tool("objdump", ["--section-headers", str(exe)])
            found = [line.split() for line in oracle["stdout"].splitlines()
                     if line.strip().split()[1:2] == [".text"]]
            self.assertTrue(found, f"objdump did not report .text:\n{oracle['stdout'][:400]}")
            oracle_vma = int(found[0][3], 16)
            self.assertEqual(named[".text"]["address"], oracle_vma,
                             "PE .text address disagrees with llvm-objdump's VMA")

    @unittest.skipUnless(shutil.which("clang") and shutil.which("ld64.lld"),
                         "clang and ld64.lld are required to build a Mach-O fixture")
    def test_macho_sections_still_work_without_the_macho_flag(self) -> None:
        """Removing `--macho` must not break the format it was there for."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "m.c"
            src.write_text("int helper(int x){return x+1;}\nint main(void){return 7;}\n")
            obj = Path(tmpdir) / "m.o"
            out = Path(tmpdir) / "m.bin"
            compiled = subprocess.run(
                ["clang", "--target=arm64-apple-macos11", "-c", str(src), "-o", str(obj)],
                capture_output=True, text=True)
            if compiled.returncode != 0:  # pragma: no cover
                self.skipTest(f"could not compile a Mach-O object: {compiled.stderr[:300]}")
            linked = subprocess.run(
                ["ld64.lld", "-arch", "arm64", "-platform_version", "macos", "11.0",
                 "11.0", "-o", str(out), str(obj), "-e", "_main"],
                capture_output=True, text=True)
            if linked.returncode != 0:  # pragma: no cover
                self.skipTest(f"could not link a Mach-O: {linked.stderr[:300]}")

            rows = llvm.sections(str(out))
            self.assertTrue(rows, "no sections parsed from a valid Mach-O")
            named = {row["name"]: row for row in rows}
            self.assertIn("__text", named)
            self.assertGreater(named["__text"]["address"], 0)
            self.assertGreater(named["__text"]["size"], 0)


if __name__ == "__main__":
    unittest.main()
