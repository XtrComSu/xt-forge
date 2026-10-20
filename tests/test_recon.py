"""Contract tests for the recon ledger (breadth phase 2, A3).

Acceptance: the report regenerates byte-identical from the ledger.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import recon as reconmod  # noqa: E402


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="recon-")
        self._old = os.environ.get("XT_HOME")
        os.environ["XT_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old

    def test_init_creates_workspace(self):
        res = reconmod.init("example.com")
        self.assertTrue(Path(res["path"]).is_dir())
        self.assertEqual(res["target"], "example.com")

    def test_target_is_a_label_not_a_path(self):
        self.assertEqual(reconmod.sanitize_target("../../etc/passwd"),
                         "etc_passwd")
        with self.assertRaises(ValueError):
            reconmod.sanitize_target("   ")

    def test_findings_are_stored_and_counted(self):
        reconmod.add_finding("example.com", severity="high", title="one")
        reconmod.add_finding("example.com", severity="critical", title="two")
        stats = reconmod.stats("example.com")
        self.assertEqual(stats["findings"], 2)
        self.assertEqual(stats["by_severity"]["critical"], 1)

    def test_severity_is_validated(self):
        with self.assertRaises(ValueError):
            reconmod.add_finding("example.com", severity="catastrophic",
                                 title="x")

    def test_finding_needs_a_title(self):
        with self.assertRaises(ValueError):
            reconmod.add_finding("example.com", severity="low", title="   ")

    def test_report_is_byte_identical(self):
        """The acceptance: same ledger, same report, every time."""
        reconmod.add_finding("example.com", severity="high", title="one",
                             detail="d", evidence="e", tags=["auth"])
        reconmod.add_note("example.com", "observed something")
        first = reconmod.report("example.com")
        second = reconmod.report("example.com")
        self.assertEqual(first, second)
        self.assertEqual(first.encode(), second.encode())

    def test_report_tracks_the_ledger(self):
        reconmod.add_finding("example.com", severity="high", title="one")
        before = reconmod.report("example.com")
        reconmod.add_finding("example.com", severity="low", title="two")
        after = reconmod.report("example.com")
        self.assertNotEqual(before, after)
        self.assertIn("two", after)

    def test_report_sorts_by_severity(self):
        reconmod.add_finding("example.com", severity="low", title="minor")
        reconmod.add_finding("example.com", severity="critical", title="urgent")
        text = reconmod.report("example.com")
        self.assertLess(text.index("urgent"), text.index("minor"))

    def test_empty_ledger_report(self):
        reconmod.init("blank")
        self.assertIn("(empty ledger)", reconmod.report("blank"))


class TestCliRecon(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="reconcli-")
        self._old = os.environ.get("XT_HOME")
        os.environ["XT_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old

    def run_cli(self, *args, expect_ok: bool = True):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "recon", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc

    def test_full_flow_over_cli(self):
        self.run_cli("new", "target.test")
        self.run_cli("finding", "target.test", "--severity", "high",
                     "--title", "panel exposed", "--evidence", "https://x")
        self.run_cli("note", "target.test", "--text", "observed")
        stats = json.loads(self.run_cli("stats", "target.test", "--json").stdout)
        self.assertEqual(stats["findings"], 1)
        self.assertEqual(stats["notes"], 1)

    def test_report_matches_between_calls(self):
        self.run_cli("new", "stable.test")
        self.run_cli("finding", "stable.test", "--severity", "medium",
                     "--title", "thing")
        first = self.run_cli("report", "stable.test", "--json").stdout
        second = self.run_cli("report", "stable.test", "--json").stdout
        self.assertEqual(json.loads(first)["report"],
                         json.loads(second)["report"])

    def test_report_to_file(self):
        self.run_cli("new", "file.test")
        out = str(Path(self.tmp) / "report.md")
        self.run_cli("report", "file.test", "--path", out)
        self.assertTrue(Path(out).is_file())

    def test_bad_severity_is_reported(self):
        self.run_cli("new", "bad.test")
        proc = self.run_cli("finding", "bad.test", "--severity", "nope",
                            "--title", "x", "--json", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("severity", (proc.stdout + proc.stderr).lower())


if __name__ == "__main__":
    unittest.main()
