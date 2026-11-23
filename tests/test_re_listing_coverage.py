"""Listing verbs must agree across formats, or say clearly that they do not.

Three defects were found by asking "do two verbs reading the same file agree?":

* `re sections` returned nothing for a Mach-O while `re overview` listed 40 sections.
* `re needed` answered "not an ELF file" for a Mach-O that `re overview` showed 13 dylibs
  for.
* `re symbols` answered "unrecognized binary format" with no indication of what it does
  support, and nothing about the names the engine had already recovered.

All three now fall back to the engine, and the symbols fallback is labelled so it cannot
be mistaken for a symbol-table dump.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*argv: str) -> dict:
    proc = subprocess.run([sys.executable, "-m", "xtforge.cli", "re", *argv, "--json"],
                          capture_output=True, text=True, cwd=str(ROOT))
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise AssertionError(f"not JSON: {proc.stdout!r} {proc.stderr!r}")


def _macho(tmp: str) -> Path:
    source = Path(tmp) / "d.c"
    source.write_text("int f(int x){return x+1;}\nint main(void){return f(2);}\n")
    obj = Path(tmp) / "d.o"
    binary = Path(tmp) / "d.bin"
    subprocess.run(["clang", "-O1", "-fno-inline", "-target", "arm64-apple-ios13.0",
                    "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
    subprocess.run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0",
                    "13.0", "-e", "_main", str(obj), "-o", str(binary)],
                   check=True, capture_output=True)
    return binary


@unittest.skipUnless(shutil.which("clang") and shutil.which("ld64.lld"),
                     "Mach-O toolchain required")
class TestListingCoverage(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.binary = _macho(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_needed_answers_for_macho(self) -> None:
        # The fixture is linked with -nostdlib, so it genuinely has no dylibs. The point
        # of the test is that the answer is "nothing", not "not an ELF file".
        result = _run("needed", str(self.binary))
        self.assertTrue(result.get("ok"), result)
        needed = result.get("needed")
        self.assertIsInstance(needed, list, "needed must be a list even when empty")
        self.assertEqual(len(needed), len(set(needed)),
                         "dependencies were duplicated across slices")

    def test_symbols_is_labelled_when_it_is_not_a_symbol_table(self) -> None:
        result = _run("symbols", str(self.binary))
        if not result.get("ok"):
            self.assertIn("ELF and PE", result.get("error", ""),
                          "a refusal must name the formats that are supported")
            return
        self.assertIn("note", result, "a fallback list must say what it is")
        self.assertIn("not a symbol-table", result["note"])
        self.assertTrue(result["symbols"])

    def test_sections_and_overview_agree(self) -> None:
        sections = _run("sections", str(self.binary))
        overview = _run("overview", str(self.binary))
        self.assertTrue(sections.get("ok"), sections)
        native = len(overview["images"][0]["sections"])
        self.assertEqual(len(sections["sections"]), native,
                         "sections and overview disagree about the same file")
