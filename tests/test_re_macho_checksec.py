"""Mach-O hardening checks.

`re checksec` answered for ELF and PE only, so iOS and macOS binaries — where these
questions matter most — got a format complaint.

Two mistakes were made and caught here, both worth keeping as regressions:

* MH_ALLOW_STACK_EXECUTION was written as 0x10000, which is **MH_BINDS_TO_WEAK**. That
  made a hardened iOS app report no NX stack. The real value is 0x20000, confirmed against
  `llvm-objdump`, which prints BINDS_TO_WEAK for a header word with 0x10000 set.
* undefined-symbol detection checked only N_EXT and not N_TYPE, so every **defined**
  symbol counted as an import — a freestanding binary reported three.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import macho


def _macho(tmp: str) -> Path:
    source = Path(tmp) / "h.c"
    source.write_text("int helper(int x){return x+1;}\nint main(){return helper(2);}\n")
    obj, binary = Path(tmp) / "h.o", Path(tmp) / "h.bin"
    subprocess.run(["clang", "-target", "arm64-apple-ios13.0", "-c", str(source),
                    "-o", str(obj)], check=True, capture_output=True)
    subprocess.run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0",
                    "13.0", "-e", "_main", str(obj), "-o", str(binary)],
                   check=True, capture_output=True)
    return binary


@unittest.skipUnless(shutil.which("clang") and shutil.which("ld64.lld"),
                     "Mach-O toolchain required")
class TestMachOChecksec(unittest.TestCase):
    def test_pie_and_nx_stack_on_a_modern_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = _macho(tmp)
            result = macho.checksec(binary)
        self.assertTrue(result["pie"], "a modern Mach-O should be PIE")
        self.assertTrue(result["nx_stack"],
                        "nx_stack False means the header sets stack execution — check the "
                        "constant, 0x20000 not 0x10000")

    def test_defined_symbols_are_not_imports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = _macho(tmp)
            result = macho.checksec(binary)
        # The fixture defines _main and _helper and imports nothing.
        self.assertEqual(result["imports"], 0,
                         f"imports: {result['undefined_sample']}")
        self.assertFalse(result["stack_canary"])
        self.assertFalse(result["arc"])

    def test_matches_llvm_nm_undefined_count(self) -> None:
        if not shutil.which("llvm-nm"):
            self.skipTest("llvm-nm unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            binary = _macho(tmp)
            result = macho.checksec(binary)
            oracle = subprocess.run(["llvm-nm", "-u", str(binary)],
                                    capture_output=True, text=True).stdout.split()
        self.assertEqual(result["imports"], len(oracle),
                         "import count disagrees with llvm-nm -u")

    def test_dylib_count_counts_occurrences_not_types(self) -> None:
        # command_set collapses duplicate command types, so a real iOS app with 13
        # LC_LOAD_DYLIB plus 14 LC_LOAD_WEAK_DYLIB reported 2. Counting must look at the
        # command list. A synthetic image with three dylib commands pins it without
        # needing an iOS SDK to link against.
        import struct
        header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 3, 3 * 24,
                             0x00200000, 0)
        command = struct.pack("<2I", 0xC, 24) + b"\x00" * 16
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "synthetic.bin"
            binary.write_bytes(header + command * 3)
            result = macho.checksec(binary)
        self.assertEqual(result["dylibs"], 3,
                         "duplicate command types were collapsed into one")

    def test_arch_names_are_friendly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = _macho(tmp)
            result = macho.checksec(binary)
        self.assertEqual(result["arch"], "arm64")
