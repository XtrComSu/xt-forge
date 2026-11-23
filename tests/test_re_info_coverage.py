"""`re info` must answer for every format the engine reads.

It covered ELF and PE, so a Mach-O or an archive fell through to "unrecognized binary
format" — while `re overview` parsed the same file without complaint. The fallback also
had to handle the hub's archive payload, which is a plain member list rather than a
wrapper object.
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
    return json.loads(proc.stdout)


@unittest.skipUnless(shutil.which("clang"), "clang required")
class TestInfoCoverage(unittest.TestCase):
    def test_macho_answers(self) -> None:
        if not shutil.which("ld64.lld"):
            self.skipTest("ld64.lld unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "i.c"
            source.write_text("int main(void){return 0;}\n")
            obj, binary = Path(tmp) / "i.o", Path(tmp) / "i.bin"
            subprocess.run(["clang", "-target", "arm64-apple-ios13.0", "-c", str(source),
                            "-o", str(obj)], check=True, capture_output=True)
            subprocess.run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios",
                            "13.0", "13.0", "-e", "_main", str(obj), "-o", str(binary)],
                           check=True, capture_output=True)
            result = _run("info", str(binary))
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("engine"), "xtforge-hub")
        self.assertEqual(result.get("machine"), "arm64")

    def test_archive_reports_members(self) -> None:
        if not shutil.which("ar"):
            self.skipTest("ar unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "a.c"
            source.write_text("int helper(int x){return x;}\n")
            obj = Path(tmp) / "a.o"
            subprocess.run(["clang", "-c", str(source), "-o", str(obj)],
                           check=True, capture_output=True)
            lib = Path(tmp) / "liba.a"
            subprocess.run(["ar", "rcs", str(lib), str(obj)], check=True, capture_output=True)
            result = _run("info", str(lib))
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("members"), 1)
        self.assertEqual(result.get("member_names"), ["a.o"])

    def test_elf_and_pe_unchanged(self) -> None:
        # The fallback must not displace the Python readers, which report richer detail.
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "h.c"
            source.write_text("int main(void){return 0;}\n")
            binary = Path(tmp) / "h"
            subprocess.run(["clang", "-O0", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            result = _run("info", str(binary))
        self.assertTrue(result.get("ok"), result)
        self.assertNotEqual(result.get("engine"), "xtforge-hub",
                            "ELF must still use the Python reader")
        self.assertTrue(result.get("build_id") or result.get("class"))
