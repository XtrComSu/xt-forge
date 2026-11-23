"""CLI tests for the `re pdb` symbol-provenance verb."""
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


class TestRePdbVerb(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _cli(self, verb: str, path: str | Path, *extra: str) -> subprocess.CompletedProcess[str]:
        # The native hub enforces an allowlist: include the fixture, repo and
        # ELF directories (and both spellings of /bin/ls on this host).
        roots = ",".join(str(p) for p in (
            self.dir, ROOT, Path(sys.executable).resolve().parent,
            "/bin", "/usr/bin",
        ))
        env = dict(os.environ, XT_ROOTS=roots)
        return subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "--json", "re", verb,
             str(path), *extra],
            capture_output=True, text=True, env=env, cwd=ROOT,
        )

    @property
    def elf(self) -> str:
        for candidate in ("/bin/ls", sys.executable):
            path = Path(candidate)
            if path.is_file() and path.read_bytes()[:4] == b"\x7fELF":
                return str(path)
        self.skipTest("no ELF binary available")

    def test_pdb_rejects_non_pe(self):
        path = ROOT / "tests" / ".." / "README.md"
        res = self._cli("pdb", path)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertFalse(data.get("ok"), data)
        self.assertTrue(data.get("error"), data)

    def test_pdb_on_elf_is_ok_without_symbol_file(self):
        res = self._cli("pdb", self.elf)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        for key in ("ok", "pdb", "matched", "warnings"):
            self.assertIn(key, data)
        self.assertTrue(data["ok"], data)
        self.assertIsNone(data["pdb"], data)
        self.assertFalse(data["matched"], data)
        self.assertIsInstance(data["warnings"], list)

    def test_pdb_shape_with_real_pe_and_debug_symbols(self):
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

        # The metadata must survive the same one-function limit the verb uses.
        raw = self._cli("functions", exe, "--limit", "1")
        self.assertEqual(raw.returncode, 0, raw.stdout + raw.stderr)
        image = (json.loads(raw.stdout).get("images") or [{}])[0]
        self.assertTrue(image.get("truncated"), image)
        self.assertTrue(image.get("pdb"), image)

        res = self._cli("pdb", exe, "--limit", "1")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        for key in ("ok", "pdb", "matched", "warnings"):
            self.assertIn(key, data)
        self.assertTrue(data["ok"], data)
        self.assertIsInstance(data["pdb"], dict)
        self.assertTrue(data["pdb"].get("guid"), data["pdb"])
        self.assertEqual(data["pdb"].get("path"), str(pdb))
        self.assertTrue(data["matched"], data)
        self.assertIsInstance(data["warnings"], list)


if __name__ == "__main__":
    unittest.main()
