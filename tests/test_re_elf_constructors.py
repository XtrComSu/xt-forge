"""Recovering the functions an ELF runs before `main`.

`re hooks` reported PLT trampolines and syscall stubs. It did not report initialisers, which is
the part of "constructors and initializers" that runs attacker-chosen code before `main` gets
control — and, because `.init_array` entries are function *pointers* rather than call sites, no
disassembly scan can ever see them. Adding a better scanner would not have helped; the data is in
a different structure.

Each test builds a real ELF with gcc and checks against `readelf`, so the oracle is independent of
the reader.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import elf

GCC = shutil.which("gcc")
READELF = shutil.which("readelf")

SOURCE = """
#include <stdio.h>
__attribute__((constructor(200))) static void later_ctor(void) { }
__attribute__((constructor)) static void early_ctor(void) { }
__attribute__((destructor)) static void teardown(void) { }
int main(void){ return 0; }
"""


@unittest.skipUnless(GCC, "needs gcc to build a real ELF")
class ConstructorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = Path(tempfile.mkdtemp(prefix="xtelfctor-"))
        source = cls.directory / "c.c"
        source.write_text(SOURCE)
        cls.binary = cls.directory / "probe"
        built = subprocess.run([GCC, "-o", str(cls.binary), str(source)],
                               capture_output=True, text=True)
        if built.returncode != 0:
            raise unittest.SkipTest(f"gcc failed: {built.stderr[:200]}")
        cls.report = elf.constructors(cls.binary)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.directory, ignore_errors=True)

    def test_both_constructors_are_found(self) -> None:
        names = {entry.get("function") for entry in self.report["constructors"]}
        self.assertIn("early_ctor", names, f"constructors were {names}")
        self.assertIn("later_ctor", names)

    def test_the_destructor_is_found_and_classified(self) -> None:
        destructors = [entry for entry in self.report["constructors"]
                       if entry.get("kind") == "destructor"]
        self.assertTrue(destructors)
        self.assertIn("teardown", {entry.get("function") for entry in destructors})

    def test_a_lower_priority_number_runs_first(self) -> None:
        """Section order is execution order, and a *smaller* number runs sooner.

        I first asserted the opposite, on the assumption that `constructor(200)` meant "twentieth
        in a natural ordering" and would land after an unannotated constructor. It does not:
        GCC's default priority is 65535, so `constructor(200)` comes first. Confirmed with a
        three-way binary — `constructor(101)`, `constructor(200)` and unannotated — where
        `readelf -x .init_array` lists them 101, 200, then the default. The test was wrong and
        the reader was right, which is why the expectation is spelled out here rather than
        written to match whatever the code happened to emit.
        """
        arrays = [entry for entry in self.report["constructors"]
                  if entry.get("section") == ".init_array"]
        self.assertGreaterEqual(len(arrays), 2)
        names = [entry.get("function") for entry in arrays]
        self.assertLess(names.index("later_ctor"), names.index("early_ctor"),
                        f"priority 200 should precede the default 65535: {names}")

    def test_dt_init_is_reported_separately_from_the_array(self) -> None:
        """`_init` runs first and appears in no `.init_array`; it is a real distinct entry."""
        sources = {entry.get("section") for entry in self.report["constructors"]}
        self.assertIn("DT_INIT", sources)

    @unittest.skipUnless(READELF, "needs readelf as an independent oracle")
    def test_the_addresses_match_readelf(self) -> None:
        """The oracle that matters: the same pointers `readelf -x .init_array` prints."""
        dump = subprocess.run([READELF, "-x", ".init_array", str(self.binary)],
                              capture_output=True, text=True).stdout
        expected = set()
        for line in dump.splitlines():
            # `  0x00003dc0 56110000 00000000 30110000 00000000  V.......0.......`
            if not line.strip().startswith("0x"):
                continue
            words = line.split()[1:]
            # readelf prints each 8-byte pointer as two 4-byte words in memory order, so the
            # pointer is the two words' *bytes* concatenated and read little-endian. Building it
            # as `int(high_word + low_word, 16)` reverses nothing and yields 0x20110000 for a
            # pointer that is really 0x1120 — an oracle that is confidently wrong.
            for offset in range(0, len(words) - 1, 2):
                try:
                    raw = bytes.fromhex(words[offset]) + bytes.fromhex(words[offset + 1])
                except ValueError:
                    continue
                if len(raw) != 8:
                    continue
                value = int.from_bytes(raw, "little")
                if value:
                    expected.add(value)
        if not expected:
            self.skipTest("readelf printed no pointers to compare")
        reported = {int(entry["address"], 16) for entry in self.report["constructors"]
                    if entry.get("section") == ".init_array"}
        missing = expected - reported
        self.assertFalse(missing, f"readelf has {sorted(map(hex, missing))} that we missed")

    def test_a_stripped_binary_still_reports_addresses(self) -> None:
        """Naming is a convenience; the finding must survive `strip`."""
        if not shutil.which("strip"):
            self.skipTest("no strip")
        stripped = self.directory / "stripped"
        shutil.copy(self.binary, stripped)
        subprocess.run(["strip", str(stripped)], capture_output=True)
        report = elf.constructors(stripped)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreaterEqual(report["constructor_count"], 2,
                                "constructors vanished when the symbol table did")
        self.assertTrue(any(entry.get("address") for entry in report["constructors"]))

    def test_a_non_elf_is_refused(self) -> None:
        junk = self.directory / "junk"
        junk.write_bytes(b"not an elf at all")
        with self.assertRaises(Exception):
            elf.constructors(junk)

    def test_a_truncated_section_does_not_raise(self) -> None:
        raw = self.binary.read_bytes()
        for cut in (64, 200, len(raw) // 2):
            partial = self.directory / f"cut{cut}"
            partial.write_bytes(raw[:cut])
            try:
                elf.constructors(partial)
            except (ValueError, OSError, Exception) as exc:  # noqa: BLE001
                # A clean refusal is fine; an IndexError from deep inside the walk is not.
                self.assertNotIsInstance(exc, IndexError,
                                         f"cut at {cut} raised IndexError")


@unittest.skipUnless(GCC, "needs gcc to build a real ELF")
class HooksVerbTest(unittest.TestCase):
    """The verb, not just the reader — the reader was unreachable for a while."""

    def test_the_verb_survives_and_reports_constructors(self) -> None:
        directory = Path(tempfile.mkdtemp(prefix="xthooks-"))
        try:
            source = directory / "c.c"
            source.write_text(SOURCE)
            binary = directory / "probe"
            if subprocess.run([GCC, "-o", str(binary), str(source)],
                              capture_output=True).returncode != 0:
                self.skipTest("gcc failed")
            root = Path(__file__).resolve().parent.parent
            launcher = root / "bin" / "xtforge"
            if not launcher.is_file():
                self.skipTest("no launcher in this checkout")
            import json
            completed = subprocess.run([str(launcher), "re", "hooks", str(binary), "--json"],
                                       capture_output=True, text=True, timeout=180)
            payload = json.loads(completed.stdout)
            self.assertTrue(payload.get("ok"), payload.get("error"))
            # `re hooks` once crashed on every invocation with `name 'shutil' is not defined`,
            # because the dispatch used shutil.which without importing it. An ImportError in one
            # branch is invisible to the rest of the suite, so the verb itself is exercised here.
            self.assertIn("constructor_count", payload)
            self.assertGreaterEqual(payload["constructor_count"], 2)
        finally:
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
