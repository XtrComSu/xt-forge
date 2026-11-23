"""CLI tests for the `re pdb-types` type census and signature verb."""
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


class TestRePdbTypes(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _cli(self, path: str | Path, *extra: str,
             json_output: bool = True) -> subprocess.CompletedProcess[str]:
        # The native hub enforces an allowlist: include the fixture, repo and
        # interpreter directories like the other native RE verb tests.
        roots = ",".join(str(p) for p in (
            self.dir, ROOT, Path(sys.executable).resolve().parent,
            "/bin", "/usr/bin",
        ))
        env = dict(os.environ, XT_ROOTS=roots)
        argv = [sys.executable, "-m", "xtforge.cli"]
        if json_output:
            argv.append("--json")
        argv.extend(["re", "pdb-types", str(path), *extra])
        return subprocess.run(argv, capture_output=True, text=True,
                              env=env, cwd=ROOT)

    def _build_pdb(self) -> Path:
        clang, lld = shutil.which("clang"), shutil.which("lld-link")
        if not clang or not lld:
            self.skipTest("clang + lld-link unavailable")
        source = self.dir / "q.c"
        obj, exe, pdb = (self.dir / n for n in ("q.obj", "q.exe", "q.pdb"))
        source.write_text(
            "int helper_add(int a, int b) { return a + b; }\n"
            "int compute(int a, int b) { return helper_add(a, b) * 2; }\n"
            "int main(void) { return compute(2, 3); }\n",
            encoding="utf-8",
        )
        steps = (
            [clang, "-target", "x86_64-pc-windows-msvc", "-O1", "-g",
             "-gcodeview", "-c", str(source), "-o", str(obj)],
            [lld, "/entry:main", "/subsystem:console", "/nodefaultlib",
             "/debug", f"/pdb:{pdb}", f"/out:{exe}", str(obj)],
        )
        for step in steps:
            built = subprocess.run(step, capture_output=True, text=True)
            if built.returncode != 0:
                self.skipTest(f"{step[0]} failed (toolchain incomplete): {built.stderr.strip()}")
        if not pdb.is_file():
            self.skipTest("linker produced no PDB")
        return pdb

    def test_pdb_types_rejects_non_pdb(self):
        res = self._cli(ROOT / "VERSION")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertFalse(data.get("ok"), data)
        self.assertTrue(data.get("error"), data)

    def test_pdb_types_reads_real_pdb(self):
        pdb = self._build_pdb()
        res = self._cli(pdb)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"), data)
        self.assertGreater(data["census"]["record_count"], 0, data)
        self.assertTrue(data["signatures"], data)
        self.assertTrue(any("(" in sig.get("rendered", "")
                            and ")" in sig.get("rendered", "")
                            for sig in data["signatures"]), data["signatures"])

    def test_pdb_types_human_output(self):
        pdb = self._build_pdb()
        res = self._cli(pdb, json_output=False)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("type records", res.stdout)


if __name__ == "__main__":
    unittest.main()
