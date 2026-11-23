"""Annotation overlay behavior on the XT-Forge-SYS analysis surface."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = "int main(void) { return 3; }\n"


def hub_available() -> bool:
    binary = ROOT / "native" / "xtforge-go" / ("xtforge-hub.exe" if os.name == "nt" else "xtforge-hub")
    return binary.is_file() and os.access(binary, os.X_OK)


@unittest.skipUnless(hub_available(), "requires the built xtforge-hub native runtime")
@unittest.skipUnless(shutil.which("cc"), "requires a C compiler")
class AnnotationOverlayTest(unittest.TestCase):
    """Analyst renames must survive a disassembly pass."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="xtf-overlay-")
        cls.root = Path(cls.temp.name)
        source = cls.root / "sample.c"
        source.write_text(
            "__attribute__((noinline)) int target(int value) { return value + 7; }\n"
            "__attribute__((noinline)) int caller(int value) { return target(value) * 2; }\n"
            "int main(void) { return caller(5); }\n",
            encoding="utf-8",
        )
        cls.binary = cls.root / "sample"
        subprocess.run(["cc", "-O1", str(source), "-o", str(cls.binary)], check=True,
                       capture_output=True)
        index = cls._functions(cls.binary)
        cls.target = next(fn for fn in index if fn.get("name") == "target")
        cls.caller = next(fn for fn in index if fn.get("name") == "caller")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def env(cls) -> dict:
        # XT_HOME relocates the overlay database, keeping test annotations out
        # of the analyst's real overlay store.
        env = dict(os.environ)
        env["XT_HOME"] = str(cls.root / "home")
        return env

    @classmethod
    def _functions(cls, binary: Path) -> list[dict]:
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", "functions", str(binary),
             "--limit", "200", "--json"],
            capture_output=True, text=True, env=cls.env(), cwd=ROOT,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        return json.loads(proc.stdout)["images"][0]["functions"]

    def _re(self, verb: str, binary: Path, options: list[str]) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", verb, str(binary), *options, "--json"],
            capture_output=True, text=True, env=self.env(), cwd=ROOT,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        return json.loads(proc.stdout)

    def _annotate(self, action: str, rva: int, options: list[str]) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", "annotate", action,
             str(self.binary), "--rva", hex(rva), *options, "--json"],
            capture_output=True, text=True, env=self.env(), cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return json.loads(proc.stdout)

    def test_function_index_reports_rename_and_keeps_symbol(self):
        self._annotate("rename", self.target["address"], ["--name", "analyst_name"])
        functions = self._functions(self.binary)
        renamed = next(fn for fn in functions if fn["address"] == self.target["address"])
        self.assertEqual(renamed["name"], "analyst_name")
        self.assertEqual(renamed["name_source"], "annotation")
        self.assertEqual(renamed["symbol_name"], "target")

    def test_analysis_accepts_the_annotated_name_as_a_target(self):
        self._annotate("rename", self.target["address"], ["--name", "callable"])
        disasm = self._re("disasm-native", self.binary, ["--target", "callable"])
        self.assertTrue(disasm["ok"], disasm)
        self.assertEqual(disasm["address"], self.target["address"])
        self.assertEqual(disasm["name"], "callable")
        self.assertEqual(disasm["symbol_name"], "target")

    def test_comment_is_attached_to_the_annotated_function(self):
        self._annotate("comment", self.caller["address"], ["--comment", "hot path"])
        disasm = self._re("disasm-native", self.binary, ["--target", "caller"])
        self.assertEqual(disasm["comment"], "hot path")

    def test_unannotated_binary_reports_no_overlay(self):
        # A byte-for-byte copy shares the overlay key (the SHA-256), so compile a
        # different program to represent a binary nobody has annotated.
        source = self.root / "other.c"
        source.write_text("int main(void) { return 11; }\n", encoding="utf-8")
        other = self.root / "other"
        subprocess.run(["cc", "-O1", str(source), "-o", str(other)], check=True,
                       capture_output=True)
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", "functions", str(other),
             "--limit", "50", "--json"],
            capture_output=True, text=True, env=self.env(), cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertNotIn("annotations", result)
        self.assertEqual(result["images"][0]["total"] >= 1, True)


if __name__ == "__main__":
    unittest.main()
