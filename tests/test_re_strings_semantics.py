"""`re strings` publishes distinct strings, and must say so.

A file with 83 printable runs and 79 distinct ones reports 79. Compared against
`strings(1)` — which lists every occurrence — the numbers disagree, and without a stated
`count`/`unique` the difference looks like a bug in whichever tool the reader trusts less.
"""
from __future__ import annotations

import json
import re
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
class TestStringSemantics(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.binary = Path(self.tmp.name) / "s"
        source = Path(self.tmp.name) / "s.c"
        source.write_text("int main(void){return 0;}\n")
        subprocess.run(["clang", "-O1", str(source), "-o", str(self.binary)],
                       check=True, capture_output=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_count_is_published_and_matches_the_list(self) -> None:
        result = _run("strings", str(self.binary), "--min-len", "4")
        self.assertTrue(result.get("ok"), result)
        self.assertIn("count", result, "a count must be published, not left to len()")
        self.assertEqual(result["count"], len(result["strings"]))
        self.assertTrue(result.get("unique"),
                        "the result must state that it is de-duplicated")

    def test_distinct_matches_an_independent_extractor(self) -> None:
        result = _run("strings", str(self.binary), "--min-len", "4")
        runs = [m.group().decode() for m in
                re.finditer(rb"[ -~]{4,}", Path(self.binary).read_bytes())]
        self.assertEqual(set(result["strings"]), set(runs),
                         "the string set disagrees with a printable-run extractor")
        if len(runs) != len(set(runs)):
            self.assertEqual(result["count"], len(set(runs)),
                             "count must be distinct strings when duplicates exist")

    def test_grep_keeps_the_count_honest(self) -> None:
        result = _run("strings", str(self.binary), "--grep", "LIB")
        self.assertEqual(result["count"], len(result["strings"]))
