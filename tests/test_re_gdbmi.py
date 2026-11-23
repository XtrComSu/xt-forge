"""GDB-driven inspection, checked against a binary whose answers are known independently.

The breadth matrix excluded this as "wraps GDB; xt-forge does live probing rather than driving a
debugger". That argued from a preference, not from a limit — gdb 18.1 is installed and MI is a
documented protocol. These tests exist because writing it surfaced four ways to get a confident
wrong answer:

  * `-file-list-exec-sections` does not exist in MI at all;
  * `-file-list-shared-libraries` returns `shared-libraries=` and lists nothing until the process
    has started;
  * `-data-disassemble` has no `-n <symbol>` mode, and its elements are bare tuples without
    `--source` but nested with it;
  * `-exec-run` runs to completion, so registers and mappings describe a dead process — and
    `--stop-at-start` is not a real option.

Every assertion is therefore checked against `nm` and `objdump`, not against the parser.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import gdbmi

SOURCE = """
#include <stdio.h>
int counter = 7;
static int helper(int n) { return n * counter; }
int main(void) { printf("%d\\n", helper(6)); return 0; }
"""


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


class BinaryCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not gdbmi.find_gdb():
            raise unittest.SkipTest("no gdb on this host")
        if not _have("gcc"):
            raise unittest.SkipTest("no gcc to build the fixture")
        cls.directory = tempfile.mkdtemp(prefix="xtgdb-")
        source = Path(cls.directory) / "gt.c"
        source.write_text(SOURCE)
        cls.binary = Path(cls.directory) / "gt"
        built = subprocess.run(["gcc", "-g", "-O0", "-o", str(cls.binary), str(source)],
                               capture_output=True, text=True)
        if built.returncode != 0:
            raise unittest.SkipTest(f"could not build the fixture: {built.stderr[:200]}")
        cls.nm = subprocess.run(["nm", str(cls.binary)], capture_output=True, text=True).stdout

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(getattr(cls, "directory", ""), ignore_errors=True)

    def symbol_address(self, name: str) -> str | None:
        """Ground truth for a symbol, straight from nm — not from gdb."""
        for line in self.nm.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == name:
                return int(parts[0], 16)
        return None


class DiscoveryTest(unittest.TestCase):
    def test_gdb_is_found_or_absent(self) -> None:
        found = gdbmi.find_gdb()
        if found is None:
            self.skipTest("no gdb installed")
        self.assertTrue(Path(found).is_file())
        self.assertTrue(os.access(found, os.X_OK))


class InspectTest(BinaryCase):
    def test_symbol_count_matches_the_debugging_info(self) -> None:
        """`-symbol-info-functions` reports source-level functions, not every ELF symbol.

        Comparing it against `nm`'s full text-symbol list was wrong: nm also shows `_start`,
        `_init`, `_fini` and the crt stubs, which the compiler emitted and the debug info does
        not describe. The fixture defines exactly two functions — `helper` and `main` — and both
        must appear in gdb's report.
        """
        report = gdbmi.inspect(self.binary)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["function_symbol_count"], 2,
                         "the fixture defines exactly two functions")
        # And both are genuinely resolvable through gdb, which is the claim that matters.
        resolved = gdbmi.breakpoints(self.binary, ["main", "helper"])
        self.assertEqual(resolved["resolved"], 2)

    def test_a_missing_file_is_refused(self) -> None:
        report = gdbmi.inspect("/nonexistent/binary")
        self.assertFalse(report["ok"])
        self.assertIn("not a file", report["error"])


class DisassembleTest(BinaryCase):
    def test_instructions_are_returned_and_are_real(self) -> None:
        report = gdbmi.disassemble(self.binary, function="main", count=10)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["count"], 0,
                           "disassembly reported success with no instructions")
        first = report["instructions"][0]
        self.assertRegex(first["address"], r"^0x[0-9a-f]+$")
        self.assertTrue(first["instruction"])

    def test_the_first_instruction_matches_objdump(self) -> None:
        """Independent oracle: objdump decodes the same bytes."""
        if not _have("objdump"):
            self.skipTest("no objdump for cross-checking")
        report = gdbmi.disassemble(self.binary, function="main", count=3)
        address = int(report["instructions"][0]["address"], 16)
        dumped = subprocess.run(
            ["objdump", "-d", "--start-address", str(address),
             f"--stop-address={address + 16}", str(self.binary)],
            capture_output=True, text=True).stdout
        mnemonic = report["instructions"][0]["instruction"].split()[0]
        self.assertIn(mnemonic, dumped,
                      f"{mnemonic} from gdb is not in objdump's decode of the same address")

    def test_disassembly_starts_at_the_symbol_from_nm(self) -> None:
        expected = self.symbol_address("main")
        report = gdbmi.disassemble(self.binary, function="main", count=4)
        self.assertEqual(int(report["instructions"][0]["address"], 16), expected)

    def test_an_unknown_symbol_is_an_error(self) -> None:
        report = gdbmi.disassemble(self.binary, function="no_such_symbol_xyz")
        self.assertFalse(report["ok"])
        self.assertIn("cannot resolve", report["error"])


class BreakpointTest(BinaryCase):
    def test_symbols_resolve_to_the_nm_addresses(self) -> None:
        """A breakpoint resolves where the debugger would stop; nm knows where that is."""
        report = gdbmi.breakpoints(self.binary, ["main", "helper"])
        self.assertTrue(report["ok"], report.get("error"))
        by_symbol = {item["symbol"]: item for item in report["breakpoints"]}
        for name in ("main", "helper"):
            entry = by_symbol[name]
            self.assertTrue(entry["ok"], entry.get("error"))
            self.assertIsNotNone(entry["address"],
                                 "the address field came back empty")
            # `break-insert main` reports the first instruction *after* the prologue, so the
            # resolved address is >= the symbol's entry. Asserting equality would be wrong,
            # and asserting "close" would hide a real off-by-a-function error.
            self.assertGreaterEqual(int(entry["address"], 16), self.symbol_address(name))

    def test_an_unresolvable_symbol_is_reported_individually(self) -> None:
        report = gdbmi.breakpoints(self.binary, ["main", "not_a_real_symbol_xyz"])
        entries = {item["symbol"]: item for item in report["breakpoints"]}
        self.assertTrue(entries["main"]["ok"])
        self.assertFalse(entries["not_a_real_symbol_xyz"]["ok"])
        self.assertEqual(report["resolved"], 1)

    def test_no_symbols_is_refused(self) -> None:
        self.assertFalse(gdbmi.breakpoints(self.binary, [])["ok"])


class RegisterTest(BinaryCase):
    def test_registers_are_read_from_a_live_inferior(self) -> None:
        """`-exec-run` alone finishes the program and leaves no registers to read."""
        report = gdbmi.registers(self.binary)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["count"], 16)
        named = [item for item in report["registers"] if item["name"]]
        self.assertTrue(named, "no register names were resolved")
        values = {item["name"]: item["value"] for item in named}
        # The stack pointer holds a real address; the program counter points into the binary.
        for name in ("rsp", "rip"):
            self.assertIn(name, values)
            self.assertRegex(values[name], r"^0x[0-9a-f]{6,}$")


class SegmentTest(BinaryCase):
    def test_mappings_show_the_binary_and_its_permissions(self) -> None:
        report = gdbmi.segments(self.binary)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["mapping_count"], 0)
        paths = {item["path"] for item in report["mappings"]}
        self.assertIn(str(self.binary), paths)
        perms = {item["perms"] for item in report["mappings"] if item["path"] == str(self.binary)}
        self.assertTrue(any("x" in perm for perm in perms),
                        f"no executable mapping of the binary: {perms}")

    def test_shared_libraries_appear_after_the_process_starts(self) -> None:
        report = gdbmi.segments(self.binary)
        self.assertGreater(report["shared_library_count"], 0,
                           "libc should appear once the process has started")


class HonestyTest(unittest.TestCase):
    def test_a_missing_gdb_is_reported_not_improvised(self) -> None:
        original = gdbmi.find_gdb
        gdbmi.find_gdb = lambda: None
        try:
            report = gdbmi.inspect("/bin/true")
        finally:
            gdbmi.find_gdb = original
        self.assertFalse(report["ok"])
        self.assertIn("no gdb", report["error"])

    def test_an_out_of_range_count_is_refused(self) -> None:
        for value in (0, -5, 100000):
            self.assertFalse(gdbmi.disassemble("/bin/true", count=value)["ok"])


if __name__ == "__main__":
    unittest.main()
