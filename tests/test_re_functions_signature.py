"""CLI tests for the PDB signature column in human `re functions` output."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestReFunctionsSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        cls.pe = None
        cls.build_error = None
        clang, lld = shutil.which("clang"), shutil.which("lld-link")
        if not clang or not lld:
            cls.build_error = "clang + lld-link unavailable"
            return
        source = cls.dir / "q.c"
        obj, exe, pdb = (cls.dir / n for n in ("q.obj", "q.exe", "q.pdb"))
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
                cls.build_error = (
                    f"{step[0]} failed (toolchain incomplete): {built.stderr.strip()}")
                return
        if not pdb.is_file():
            cls.build_error = "linker produced no PDB"
            return
        cls.pe = exe

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _require_pe(self) -> Path:
        if self.pe is None:
            self.skipTest(self.build_error or "PE fixture unavailable")
        return self.pe

    def _cli(self, path: str | Path, *, json_output: bool = False) -> subprocess.CompletedProcess[str]:
        # The native hub enforces an allowlist: include the fixture and ELF dirs.
        roots = ",".join(str(p) for p in (
            self.dir, ROOT, Path(sys.executable).resolve().parent, "/bin", "/usr/bin",
        ))
        env = dict(os.environ, XT_ROOTS=roots)
        argv = [sys.executable, "-m", "xtforge.cli"]
        if json_output:
            argv.append("--json")
        argv.extend(["re", "functions", str(path)])
        return subprocess.run(argv, capture_output=True, text=True,
                              env=env, cwd=ROOT)

    @property
    def elf(self) -> str:
        for candidate in (Path(sys.executable).resolve(), Path("/bin/ls")):
            if not candidate.is_file():
                continue
            with candidate.open("rb") as fh:
                if fh.read(4) == b"\x7fELF":
                    return str(candidate)
        self.skipTest("no ELF binary available")

    def test_human_output_shows_pdb_signature(self):
        res = self._cli(self._require_pe())
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("helper_add", res.stdout)
        self.assertRegex(
            res.stdout,
            r"helper_add\s+[^\n]*\([^)]*\)",
            f"no parenthesised type after helper_add: {res.stdout}",
        )

    def test_elf_output_has_no_signature_column(self):
        res = self._cli(self.elf)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        seen = 0
        for line in res.stdout.splitlines():
            match = re.match(r"^0x[0-9a-fA-F]+(?:\s+(\S+))?(?:\s+(.*))?$", line)
            if not match:
                continue
            seen += 1
            remainder = (match.group(2) or "").lstrip()
            self.assertFalse(
                remainder.startswith("("),
                f"unexpected signature immediately after the name column: {line}",
            )
        self.assertGreater(seen, 0, f"no function rows rendered: {res.stdout[:400]}")

    def test_json_output_keeps_signature_key(self):
        res = self._cli(self._require_pe(), json_output=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        signed = [fn for image in data.get("images", [])
                  for fn in image.get("functions", [])
                  if isinstance(fn, dict) and fn.get("signature")]
        self.assertTrue(signed, data)
        helper = [fn for fn in signed if fn.get("name") == "helper_add"]
        self.assertTrue(helper, signed)
        self.assertIn("(", helper[0]["signature"])
        self.assertIn(")", helper[0]["signature"])


if __name__ == "__main__":
    unittest.main()
