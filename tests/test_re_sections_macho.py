"""`re sections` must cover the same formats the engine can read.

It covered ELF and PE only, so a Mach-O returned a bare failure while `re overview`
listed 40 sections from the same file. Format coverage should not depend on which layer
answers; anything the native hub can read is now handled.

The failing path also reported `{"ok": false, "err": ...}` while the rest of the CLI uses
`error`, so a client checking `error` got a failure with no message. Both keys are now
emitted.
"""
from __future__ import annotations

import json
import os
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


class TestSectionsCoverage(unittest.TestCase):
    def test_macho_sections_come_from_the_hub(self) -> None:
        if not shutil.which("ld64.lld") or not shutil.which("clang"):
            self.skipTest("Mach-O toolchain unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "m.c"
            source.write_text("int f(int x){return x+1;}\nint main(void){return f(2);}\n")
            obj = Path(tmp) / "m.o"
            binary = Path(tmp) / "m.bin"
            subprocess.run(["clang", "-O1", "-fno-inline", "-target", "arm64-apple-ios13.0",
                            "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
            subprocess.run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios",
                            "13.0", "13.0", "-e", "_main", str(obj), "-o", str(binary)],
                           check=True, capture_output=True)
            result = _run("sections", str(binary))
        self.assertTrue(result.get("ok"), result)
        names = [s["name"] for s in result["sections"]]
        self.assertTrue(names, "no sections reported for a Mach-O")
        self.assertIn("__TEXT,__text", names)
        self.assertEqual(result.get("engine"), "xtforge-hub")

    def test_failure_carries_both_error_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp) / "junk.bin"
            junk.write_bytes(b"not a binary at all")
            result = _run("sections", str(junk))
        self.assertFalse(result.get("ok"))
        self.assertTrue(result.get("error"), "a failure must carry an `error` message")
        self.assertEqual(result.get("error"), result.get("err"),
                         "the two keys must agree when both are present")
