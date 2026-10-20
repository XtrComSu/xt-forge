"""Contract tests for the model-eval harness (quality gates for distillation)."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location(
    "eval_model", ROOT / "scripts" / "eval_model.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

from xtforge.core import eval as evalmod  # noqa: E402

FIXTURE = json.loads(
    (ROOT / "tests" / "fixtures" / "model_eval.json").read_text(encoding="utf-8"))


class TestChecks(unittest.TestCase):
    def check(self, kind, value, output):
        return harness.check_output(output, {"type": kind, "value": value})[0]

    def test_contains(self):
        self.assertTrue(self.check("contains", "Ada", "ada lovelace"))
        self.assertFalse(self.check("contains", "bob", "ada lovelace"))

    def test_not_contains(self):
        self.assertTrue(self.check("not_contains", "TODO", "done"))

    def test_regex(self):
        self.assertTrue(self.check("regex", r"^BANANA\.?$", "BANANA"))
        self.assertFalse(self.check("regex", r"^BANANA\.?$", "sure, BANANA"))

    def test_starts_with(self):
        self.assertTrue(self.check("starts_with", "{", '{"a": 1}'))

    def test_json(self):
        self.assertTrue(self.check("json", None, '{"a": 1}'))
        self.assertFalse(self.check("json", None, '```json\n{"a": 1}\n```'))

    def test_length_bounds(self):
        self.assertTrue(self.check("max_chars", 10, "short"))
        self.assertFalse(self.check("max_chars", 2, "too long"))
        self.assertTrue(self.check("min_chars", 2, "enough"))

    def test_refusal_detection(self):
        self.assertTrue(self.check("refuses", True, "I cannot help with that."))
        self.assertFalse(self.check("refuses", True, "here is the answer"))
        self.assertTrue(self.check("refuses", False, "here is the answer"))

    def test_unknown_check_fails_closed(self):
        ok, label = harness.check_output("x", {"type": "nonsense"})
        self.assertFalse(ok)
        self.assertIn("unknown", label)


class TestScoring(unittest.TestCase):
    def test_all_checks_must_pass(self):
        case = {"checks": [{"type": "contains", "value": "a"},
                           {"type": "contains", "value": "z"}]}
        self.assertFalse(harness.score_case("a", case)["passed"])
        self.assertTrue(harness.score_case("a z", case)["passed"])

    def test_no_checks_means_nonempty_output(self):
        self.assertTrue(harness.score_case("hello", {})["passed"])
        self.assertFalse(harness.score_case("   ", {})["passed"])


class TestHarness(unittest.TestCase):
    def test_cases_fixture_is_valid(self):
        cases = FIXTURE["cases"]
        self.assertGreaterEqual(len(cases), 15)
        known = {"contains", "not_contains", "regex", "starts_with", "json",
                 "max_chars", "min_chars", "refuses"}
        for case in cases:
            self.assertTrue(case["checks"], case["id"])
            for check in case["checks"]:
                self.assertIn(check["type"], known, case["id"])

    def test_evaluate_with_stub_backend(self):
        harness.BACKENDS["stub"] = lambda model, prompt, timeout: ('{"a": 1}', 0.01)
        try:
            report = harness.evaluate("stub-model", FIXTURE["cases"][:3],
                                      "stub", 10)
        finally:
            harness.BACKENDS.pop("stub", None)
        self.assertEqual(report["model"], "stub-model")
        self.assertEqual(report["cases"], 3)
        self.assertIn("cases.pass_rate", report)
        self.assertTrue(report["results"])

    def test_failure_is_reported_by_id(self):
        harness.BACKENDS["stub"] = lambda model, prompt, timeout: ("", 0.01)
        try:
            report = harness.evaluate("stub-model", FIXTURE["cases"][:2],
                                      "stub", 10)
        finally:
            harness.BACKENDS.pop("stub", None)
        self.assertEqual(len(report["failed"]), 2)

    def test_unknown_backend_is_an_error(self):
        with self.assertRaises(ValueError):
            harness.evaluate("m", [], "not-a-backend", 1)


class TestModelEvalSuite(unittest.TestCase):
    def test_latency_is_lower_is_better(self):
        base = evalmod.record("model-eval",
                              {"cases": {"pass_rate": 0.5},
                               "latency": {"mean_s": 20.0}})
        cur = evalmod.record("model-eval",
                             {"cases": {"pass_rate": 0.9},
                              "latency": {"mean_s": 5.0}})
        verdict = evalmod.compare(base, cur)
        by_metric = {row["metric"]: row["verdict"] for row in verdict["rows"]}
        self.assertEqual(by_metric["cases.pass_rate"], "better")
        self.assertEqual(by_metric["latency.mean_s"], "better")
        self.assertTrue(verdict["ok"])

    def test_slower_is_a_regression(self):
        base = evalmod.record("model-eval", {"latency": {"mean_s": 5.0}})
        cur = evalmod.record("model-eval", {"latency": {"mean_s": 20.0}})
        verdict = evalmod.compare(base, cur)
        self.assertEqual(verdict["rows"][0]["verdict"], "regressed")
        self.assertFalse(verdict["ok"])


if __name__ == "__main__":
    unittest.main()
