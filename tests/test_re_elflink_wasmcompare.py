"""Tests for ELF .gnu_debuglink and WebAssembly interface comparison.

Both fixtures are built here from source, because the point is to check the reader
against a value that is known independently:

  * .gnu_debuglink carries a CRC-32 of the separate debug file, and the oracle is
    `zlib.crc32` over that file — a completely separate implementation. If the
    reader took the wrong bytes (or the wrong end of the section), the comparison
    fails.
  * WASM comparison needs two modules whose exports differ by exactly one name.
    clang can target wasm32, so v1 exports `add` and v2 exports `add` plus `mul`,
    and the assertion is that the difference is precisely `['mul']` — not "some
    difference was found".
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from xtforge.core.re import elfmeta, wasm


def _tool(*names: str) -> str | None:
    return next((c for c in names if shutil.which(c)), None)


def build_debuglink_pair(directory: Path) -> tuple[Path, Path] | None:
    """Compile a binary + stripped copy carrying .gnu_debuglink, plus the debug file."""
    compiler = _tool("clang", "cc", "gcc")
    objcopy = _tool("llvm-objcopy", "objcopy")
    if not compiler or not objcopy:
        return None
    src = directory / "a.c"
    src.write_text("int f(int x){return x+1;}\nint main(void){return f(1);}\n")
    full = directory / "a.bin"
    if subprocess.run([compiler, "-O0", "-g", str(src), "-o", str(full)],
                      capture_output=True).returncode != 0:
        return None
    debug = directory / "a.debug"
    if subprocess.run([objcopy, "--only-keep-debug", str(full), str(debug)],
                      capture_output=True).returncode != 0:
        return None
    stripped = directory / "a2.bin"
    if subprocess.run([objcopy, "--strip-debug",
                       f"--add-gnu-debuglink={debug}", str(full), str(stripped)],
                      capture_output=True).returncode != 0:
        return None
    return stripped, debug


def build_wasm_pair(directory: Path) -> tuple[Path, Path] | None:
    compiler = _tool("clang")
    if not compiler:
        return None
    v1 = directory / "v1.c"
    v1.write_text("int add(int a,int b){return a+b;}\n")
    v2 = directory / "v2.c"
    v2.write_text("int add(int a,int b){return a+b;}\n"
                  "int mul(int a,int b){return a*b;}\n")
    outputs = []
    for src, name in ((v1, "v1.wasm"), (v2, "v2.wasm")):
        target = directory / name
        completed = subprocess.run(
            [compiler, "--target=wasm32", "-nostdlib", "-Wl,--no-entry",
             "-Wl,--export-all", "-o", str(target), str(src)],
            capture_output=True)
        if completed.returncode != 0 or not target.is_file():
            return None
        outputs.append(target)
    return outputs[0], outputs[1]


class ElfDebuglinkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pair = build_debuglink_pair(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.pair is None:
            self.skipTest("no clang/objcopy available to build the debuglink pair")
        self.binary, self.debug = self.pair
        self.report = elfmeta.report(self.binary)
        self.link = self.report["debuglink"]

    def test_debuglink_is_present_with_the_right_filename(self) -> None:
        self.assertTrue(self.link["present"])
        self.assertEqual(self.link["file"], self.debug.name)

    def test_crc32_matches_zlib_over_the_debug_file(self) -> None:
        """The CRC is zlib CRC-32 of the whole separate debug file.

        zlib is the independent oracle: reading the wrong offset, the wrong length,
        or the CRC from the unaligned position all produce a different number.
        """
        expected = f"0x{zlib.crc32(self.debug.read_bytes()) & 0xFFFFFFFF:08x}"
        self.assertEqual(self.link["crc32"], expected)

    def test_absent_debuglink_is_reported_as_absent(self) -> None:
        """A binary stripped without --add-gnu-debuglink has no section."""
        report = elfmeta.report(self.debug)
        self.assertFalse(report["debuglink"]["present"])
        self.assertTrue(report["debuglink"]["warnings"])

    def test_real_system_binary_is_handled(self) -> None:
        """An honest host binary, whichever it is, must not raise."""
        report = elfmeta.report("/bin/ls")
        self.assertTrue(report["ok"])
        self.assertIn("debuglink", report)


class WasmCompareTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pair = build_wasm_pair(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.pair is None:
            self.skipTest("clang cannot target wasm32 here")
        self.v1, self.v2 = self.pair

    def test_exact_export_difference(self) -> None:
        """v2 adds `mul`; nothing else may be reported as changed.

        Asserting "a difference exists" would pass even if the comparison reported
        every export as added, which is the failure mode of comparing by index
        rather than by name.
        """
        report = wasm.compare(self.v1, self.v2)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertFalse(report["interface_identical"])
        self.assertEqual(report["exports_added"], ["mul"])
        self.assertEqual(report["exports_removed"], [])
        self.assertEqual(report["exports_kind_changed"], [])

    def test_identical_modules_compare_identical(self) -> None:
        report = wasm.compare(self.v1, self.v1)
        self.assertTrue(report["interface_identical"])
        self.assertEqual(report["exports_added"], [])
        self.assertEqual(report["exports_removed"], [])

    def test_reverse_direction_reports_removal(self) -> None:
        """The comparison is directional: swapping arguments swaps add/remove."""
        report = wasm.compare(self.v2, self.v1)
        self.assertEqual(report["exports_added"], [])
        self.assertEqual(report["exports_removed"], ["mul"])

    def test_bad_input_is_an_error_not_an_empty_interface(self) -> None:
        """A malformed module must not compare as 'no exports'.

        An empty interface would make the summary say "interfaces are identical",
        which is the opposite of the truth.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.wasm"
            bad.write_bytes(b"not wasm at all")
            report = wasm.compare(self.v1, bad)
        self.assertFalse(report["ok"])
        self.assertIn("error", report)
        self.assertNotIn("interface_identical", report)

    def test_summary_is_human_readable(self) -> None:
        report = wasm.compare(self.v1, self.v2)
        self.assertIn("1 added", report["summary"])


if __name__ == "__main__":
    unittest.main()
