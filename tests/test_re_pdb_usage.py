"""Usage errors on the PDB verbs must say which verb to use.

`re pdb <path>` takes a **PE binary** and finds its symbol file; `re pdb-types <path>` reads
a `.pdb` directly. Handing a PDB to `re pdb` — the obvious thing to try — produced
"not a binary format", which names neither the problem nor the fix.
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


@unittest.skipUnless(shutil.which("clang-cl") and shutil.which("lld-link"),
                     "Windows toolchain required")
class TestPdbVerbUsage(unittest.TestCase):
    def _pdb(self, tmp: str) -> Path:
        source = Path(tmp) / "u.c"
        source.write_text("struct S { int a; double b; };\nint main(void){ struct S s = {0}; return s.a; }\n")
        obj, exe = Path(tmp) / "u.obj", Path(tmp) / "u.exe"
        subprocess.run(["clang-cl", "-Z7", "-c", str(source), "-o", str(obj)],
                       check=True, capture_output=True)
        subprocess.run(["lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib",
                        "/debug", "/out:" + str(exe), str(obj), "/force:unresolved"],
                       check=True, capture_output=True)
        pdb = Path(tmp) / "u.pdb"
        self.assertTrue(pdb.is_file(), "fixture did not produce a PDB")
        return pdb

    def test_pdb_file_gets_a_pointed_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pdb = self._pdb(tmp)
            result = _run("pdb", str(pdb))
        self.assertFalse(result.get("ok"))
        self.assertIn("pdb-types", result["error"],
                      "the message must name the verb that reads a .pdb")
        self.assertEqual(result.get("suggestion"), "pdb-types")

    def test_pdb_types_reads_the_same_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pdb = self._pdb(tmp)
            result = _run("pdb-types", str(pdb))
        self.assertTrue(result.get("ok"), result)
        names = [a["name"] for a in result.get("aggregates") or []]
        self.assertIn("S", names)
