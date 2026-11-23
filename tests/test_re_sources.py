"""The single place that decides which layer answers.

Four verbs each grew their own format reader and failed on everything but ELF and PE.
The fixes were identical, which is why they belong in one module: adding a format should
be one change, not five. These tests pin the dispatcher's contract directly, so the verbs
built on it cannot drift apart again.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import sources


def _macho(tmp: str) -> Path:
    source = Path(tmp) / "s.c"
    source.write_text("int f(int x){return x+1;}\nint main(void){return f(2);}\n")
    obj, binary = Path(tmp) / "s.o", Path(tmp) / "s.bin"
    subprocess.run(["clang", "-O1", "-fno-inline", "-target", "arm64-apple-ios13.0",
                    "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
    subprocess.run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0",
                    "13.0", "-e", "_main", str(obj), "-o", str(binary)],
                   check=True, capture_output=True)
    return binary


class TestSources(unittest.TestCase):
    def test_hub_format_identifies_macho(self) -> None:
        if not (shutil.which("clang") and shutil.which("ld64.lld")):
            self.skipTest("Mach-O toolchain unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(sources.hub_format(_macho(tmp)), "macho")

    def test_sections_and_needed_come_back(self) -> None:
        if not (shutil.which("clang") and shutil.which("ld64.lld")):
            self.skipTest("Mach-O toolchain unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            binary = _macho(tmp)
            rows = sources.sections_from_hub(binary)
            self.assertTrue(rows)
            self.assertIn("__TEXT,__text", [row["name"] for row in rows])
            # A freestanding binary has no dylibs; the answer is an empty list, not None.
            self.assertEqual(sources.needed_from_hub(binary), [])

    def test_unrecognised_file_is_reported_honestly(self) -> None:
        # The engine does not refuse an unknown file: it reports format "unknown" with a
        # hash, entropy and a bounded preview, and no sections. The dispatcher must pass
        # that through rather than inventing a failure.
        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp) / "junk"
            junk.write_bytes(b"plain text, not a binary")
            overview = sources.hub_overview(junk)
            self.assertIsNotNone(overview)
            self.assertEqual(overview["format"], "unknown")
            self.assertIsNone(sources.sections_from_hub(junk))
            self.assertEqual(sources.needed_from_hub(junk), [])

    def test_unsupported_names_the_formats_and_the_actual_format(self) -> None:
        if not (shutil.which("clang") and shutil.which("ld64.lld")):
            self.skipTest("Mach-O toolchain unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            refusal = sources.unsupported("checksec", _macho(tmp))
        self.assertFalse(refusal["ok"])
        self.assertIn("ELF", refusal["error"])
        self.assertIn("PE", refusal["error"])
        self.assertIn("macho", refusal["error"])
        self.assertEqual(refusal["err"], refusal["error"])
