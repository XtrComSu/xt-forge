"""Flags must not be accepted and silently ignored.

Three cases were found by auditing the presentation layer rather than the analysis:

* `--target` on `re annotate` stored the name at 0x0 (the command read `--rva`).
* `--grep` on `re strings` returned the unfiltered list.
* `--confirm` on `re patch` could never mean anything, because patching is copy-only.

The first two now work; the third is refused with an explanation. This test pins the
third, and the safety behaviour of `--orig-bytes`, which is the flag that stops a patch
landing on the wrong bytes.
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


@unittest.skipUnless(shutil.which("clang"), "clang required")
class TestPatchFlags(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.home = base / "home"
        self.home.mkdir()
        source = base / "p.c"
        source.write_text("int b(int x){return x*2;}\nint main(void){return b(3);}\n",
                          encoding="utf-8")
        self.binary = base / "pbin"
        subprocess.run(["clang", "-O1", "-fno-inline", str(source), "-o", str(self.binary)],
                       check=True, capture_output=True)
        self.before = self.binary.read_bytes()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *argv: str) -> tuple[int, dict]:
        env = {**os.environ, "XT_HOME": str(self.home)}
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", *argv, "--json"],
            capture_output=True, text=True, env=env, cwd=str(ROOT))
        try:
            return proc.returncode, json.loads(proc.stdout)
        except ValueError:
            self.fail(f"not JSON: {proc.stdout!r} {proc.stderr!r}")

    def test_confirm_is_refused_not_ignored(self) -> None:
        code, result = self._run("patch", str(self.binary), "--offset", "0x0",
                                 "--patch-bytes", "90", "--confirm", "yes")
        self.assertNotEqual(code, 0)
        self.assertFalse(result["ok"])
        self.assertIn("--out", result["error"],
                      "the refusal must tell the user what to use instead")

    def test_patch_is_copy_only(self) -> None:
        code, result = self._run("patch", str(self.binary), "--offset", "0x0",
                                 "--patch-bytes", "90")
        self.assertEqual(code, 0)
        self.assertTrue(result["ok"])
        self.assertNotEqual(result["out_path"], str(self.binary),
                            "patching must never overwrite the input")
        self.assertEqual(self.binary.read_bytes(), self.before,
                         "the input file changed; patch is supposed to be copy-only")

    def test_orig_bytes_mismatch_is_refused(self) -> None:
        code, result = self._run("patch", str(self.binary), "--offset", "0x0",
                                 "--patch-bytes", "90", "--orig-bytes", "deadbeef")
        self.assertNotEqual(code, 0)
        self.assertFalse(result["ok"])
        self.assertIn("mismatch", result["error"])
