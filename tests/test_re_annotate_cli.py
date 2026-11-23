"""Annotation CLI ergonomics.

Two silent traps were fixed here, and both cost real work:

* `re annotate <path> --target 0x1130 --name x` stored the annotation at **0x0**, because
  the command read `--rva` while every other RE verb calls an address `--target`. Nothing
  failed; the name simply never appeared.
* `re annotate <path> --name x` with no subverb fell through to "list" and wrote nothing.

Both now behave the way the flags read.
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


def _build_fixture(directory: Path) -> Path:
    source = directory / "ann.c"
    source.write_text(
        "int b(int x){return x*2;}\nint main(void){return b(3);}\n", encoding="utf-8")
    binary = directory / "annbin"
    subprocess.run(["clang", "-O1", "-fno-inline", str(source), "-o", str(binary)],
                   check=True, capture_output=True)
    return binary


@unittest.skipUnless(shutil.which("clang"), "clang required")
class TestAnnotateCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.binary = _build_fixture(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *argv: str) -> dict:
        env = {**os.environ, "XT_HOME": str(self.home)}
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", *argv, "--json"],
            capture_output=True, text=True, env=env, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def _function_address(self) -> int:
        listing = self._run("functions", str(self.binary), "--limit", "50")
        for function in listing["images"][0]["functions"]:
            if function.get("name") == "b":
                return function["address"]
        self.skipTest("fixture has no symbol b")

    def test_target_flag_is_honoured(self) -> None:
        address = self._function_address()
        result = self._run("annotate", str(self.binary), "--target", hex(address),
                           "--name", "renamed_b")
        self.assertEqual(result["action"], "rename")
        self.assertEqual(result["rva"], hex(address),
                         "--target must store the annotation at the requested address")
        listing = self._run("functions", str(self.binary), "--limit", "50")
        names = {f.get("name") for f in listing["images"][0]["functions"]}
        self.assertIn("renamed_b", names)

    def test_name_without_subverb_renames(self) -> None:
        address = self._function_address()
        result = self._run("annotate", str(self.binary), "--rva", hex(address),
                           "--name", "inferred_b")
        self.assertEqual(result["action"], "rename",
                         "supplying --name with no subverb must not silently list")
        listing = self._run("functions", str(self.binary), "--limit", "50")
        names = {f.get("name") for f in listing["images"][0]["functions"]}
        self.assertIn("inferred_b", names)

    def test_list_still_lists(self) -> None:
        # The list payload carries no "action" key; it reports the stored rows instead.
        result = self._run("annotate", str(self.binary))
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["annotations"], [])
