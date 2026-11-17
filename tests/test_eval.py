"""Contract tests for the eval recorder (breadth phase 2, B1).

Acceptance: the three bench scripts re-express into runs and agree on numbers.
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

from xtforge.core import eval as evalmod  # noqa: E402


class TestEvalStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="eval-")
        self._old = os.environ.get("XT_HOME")
        os.environ["XT_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old

    def test_record_flattens_metrics(self):
        run = evalmod.record("mem-recall",
                             {"hybrid": {"recall": 0.9}, "k": 5})
        self.assertEqual(run["metrics"]["hybrid.recall"], 0.9)
        self.assertEqual(run["metrics"]["k"], 5.0)
        self.assertEqual(run["direction"], "higher")

    def test_suite_name_is_sanitised(self):
        self.assertEqual(evalmod._safe("../../etc/passwd"), "etcpasswd")
        with self.assertRaises(ValueError):
            evalmod._safe("   ")

    def test_list_and_latest(self):
        evalmod.record("mem-recall", {"a": 1}, now=100)
        evalmod.record("mem-recall", {"a": 2}, now=200)
        runs = evalmod.list_runs("mem-recall")
        self.assertEqual(len(runs), 2)
        self.assertEqual(evalmod.latest("mem-recall")["metrics"]["a"], 2.0)

    def test_compare_calls_regressions(self):
        base = evalmod.record("mem-recall", {"recall": 0.9, "mrr": 0.8})
        cur = evalmod.record("mem-recall", {"recall": 0.7, "mrr": 0.9})
        verdict = evalmod.compare(base, cur)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["regressions"], 1)
        by_metric = {row["metric"]: row["verdict"] for row in verdict["rows"]}
        self.assertEqual(by_metric["recall"], "regressed")
        self.assertEqual(by_metric["mrr"], "better")

    def test_lower_is_better_for_context_pack(self):
        base = evalmod.record("context-pack", {"tokens_per_hit": 5000})
        cur = evalmod.record("context-pack", {"tokens_per_hit": 900})
        verdict = evalmod.compare(base, cur)
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["direction"], "lower")
        self.assertEqual(verdict["rows"][0]["verdict"], "better")

    def test_compare_marks_added_and_removed(self):
        base = evalmod.record("mem-recall", {"a": 1, "gone": 2})
        cur = evalmod.record("mem-recall", {"a": 1, "new": 3})
        verdict = evalmod.compare(base, cur)
        by_metric = {row["metric"]: row["verdict"] for row in verdict["rows"]}
        self.assertEqual(by_metric["new"], "added")
        self.assertEqual(by_metric["gone"], "removed")

    def test_report_renders(self):
        evalmod.record("mem-recall", {"recall": 0.9})
        text = evalmod.report("mem-recall")
        self.assertIn("Eval: mem-recall", text)
        self.assertIn("recall=0.9", text)

    def test_report_without_runs(self):
        self.assertIn("no runs", evalmod.report("never-recorded"))


class TestCliEval(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="evalcli-")
        self._old = os.environ.get("XT_HOME")
        os.environ["XT_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old

    def run_cli(self, *args, expect_ok: bool = True, input_data: str = ""):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "eval", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60,
            input=input_data)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc

    def test_record_without_body_is_an_error(self):
        proc = self.run_cli("record", "mem-recall", "--body-file", "-",
                            "--json", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("payload", proc.stdout)

    def test_full_flow(self):
        self.run_cli("record", "mem-recall", "--body", '{"recall": 0.9}',
                     "--json")
        self.run_cli("record", "mem-recall", "--body", '{"recall": 0.95}',
                     "--json")
        runs = json.loads(self.run_cli("list", "mem-recall", "--json").stdout)
        self.assertEqual(len(runs), 2)
        verdict = json.loads(self.run_cli("compare", "mem-recall",
                                          "--json").stdout)
        self.assertTrue(verdict["ok"])

    def test_compare_flags_regression_with_exit_code(self):
        self.run_cli("record", "mem-recall", "--body", '{"recall": 0.9}')
        self.run_cli("record", "mem-recall", "--body", '{"recall": 0.5}')
        proc = self.run_cli("compare", "mem-recall", "--json", expect_ok=False)
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(json.loads(proc.stdout)["ok"])

    def test_benches_agree_with_recorded_numbers(self):
        """The acceptance: a bench's own JSON equals what eval stored."""
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench_mem_recall.py"),
             "--json", "--no-gate"],
            capture_output=True, text=True, cwd=str(ROOT), timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        run = json.loads(self.run_cli(
            "record", "mem-recall", "--body", proc.stdout, "--json").stdout)
        self.assertEqual(run["metrics"]["hybrid.recall"],
                         float(payload["hybrid"]["recall"]))
        self.assertEqual(run["metrics"]["lexical.mrr"],
                         float(payload["lexical"]["mrr"]))


if __name__ == "__main__":
    unittest.main()
