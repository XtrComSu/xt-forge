"""Contract tests for round 5: code structure, ranked grep, context packing.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.code import parse as codeparse  # noqa: E402
from xtforge.core.route import pack as packmod  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
MINI = FIXTURES / "mini_project"


class TestCodeSymbols(unittest.TestCase):
    def test_python_symbols_use_ast(self):
        info = codeparse.symbols(MINI / "worker.py")
        self.assertEqual(info["method"], "ast")
        self.assertEqual(info["language"], "python")
        names = {s["name"] for s in info["symbols"]}
        self.assertIn("backoff", names)
        self.assertIn("Worker", names)
        self.assertIn("Worker.drain", names)

    def test_symbols_carry_line_spans(self):
        info = codeparse.symbols(MINI / "worker.py")
        backoff = next(s for s in info["symbols"] if s["name"] == "backoff")
        self.assertGreater(backoff["end"], backoff["line"])
        self.assertIn("backoff(", backoff["signature"])

    def test_outline_nests_methods_under_class(self):
        info = codeparse.outline(MINI / "worker.py")
        worker = next(n for n in info["tree"] if n["name"] == "Worker")
        child_names = {c["name"] for c in worker["children"]}
        self.assertIn("Worker.run_once", child_names)

    def test_syntax_error_degrades_to_regex(self):
        broken = FIXTURES / "mini_project" / "_broken.py"
        broken.write_text("def ok():\n    return 1\ndef bad(:\n", encoding="utf-8")
        try:
            info = codeparse.symbols(broken)
            self.assertEqual(info["method"], "regex")
            self.assertIn("syntax_error", info.get("error", ""))
            self.assertTrue(any(s["name"] == "ok" for s in info["symbols"]))
        finally:
            broken.unlink()

    def test_missing_file_is_data_not_crash(self):
        info = codeparse.symbols(MINI / "does_not_exist.py")
        self.assertEqual(info["count"], 0)
        self.assertEqual(info["method"], "none")
        self.assertIn("unreadable", info.get("error", ""))

    def test_refs_find_definition_and_uses(self):
        info = codeparse.refs(MINI, "backoff", limit=20)
        self.assertGreaterEqual(info["count"], 2)
        self.assertTrue(any(r["definition"] for r in info["refs"]))
        self.assertTrue(all("backoff" in r["text"] for r in info["refs"]))

    def test_detection_by_extension(self):
        self.assertEqual(codeparse.detect("a.py"), "python")
        self.assertEqual(codeparse.detect("a.rs"), "rust")
        self.assertEqual(codeparse.detect("a.weird"), "text")


class TestRankedGrep(unittest.TestCase):
    def test_ranking_puts_definitions_first(self):
        matches = packmod.rank_lines(MINI, "backoff", limit=10)
        self.assertTrue(matches)
        self.assertIn("def backoff", matches[0]["text"])
        self.assertGreaterEqual(matches[0]["score"], matches[-1]["score"])

    def test_stopwords_do_not_match_everything(self):
        matches = packmod.rank_lines(MINI, "the is of in", limit=5)
        self.assertEqual(matches, [])

    def test_ranking_is_deterministic(self):
        a = packmod.rank_lines(MINI, "cache ttl eviction", limit=10)
        b = packmod.rank_lines(MINI, "cache ttl eviction", limit=10)
        self.assertEqual(a, b)

    def test_identifier_parts_match(self):
        """MAX_ATTEMPTS is findable by asking for 'attempts'."""
        matches = packmod.rank_lines(MINI, "attempts", limit=10)
        self.assertTrue(any("MAX_ATTEMPTS" in m["text"] for m in matches))


class TestContextPacking(unittest.TestCase):
    def test_packing_stays_within_budget(self):
        for budget in (200, 600, 1200, 2400):
            out = packmod.pack(str(MINI), "how is the retry delay calculated",
                               token_budget=budget)
            self.assertTrue(out["ok"])
            data = out["data"]
            self.assertLessEqual(packmod._tokens(data["context"]), budget + 80,
                                 f"budget {budget}")
            self.assertLessEqual(data["estimated_tokens"], budget + 40)

    def test_packing_is_deterministic(self):
        a = packmod.pack(str(MINI), "where are one shot tokens minted")
        b = packmod.pack(str(MINI), "where are one shot tokens minted")
        self.assertEqual(a["data"]["context"], b["data"]["context"])

    def test_evidence_survives_packing(self):
        out = packmod.pack(str(MINI), "how is the retry delay calculated",
                           token_budget=1200)
        self.assertIn("delay = min(BASE_DELAY", out["data"]["context"])

    def test_error_lines_survive_budget_pressure(self):
        out = packmod.pack(str(MINI), "confirm token missing denied raise",
                           token_budget=200)
        context = out["data"]["context"]
        self.assertTrue("raise Denied" in context or "confirm" in context)

    def test_empty_query_is_rejected(self):
        out = packmod.pack(str(MINI), "  the the  ")
        self.assertFalse(out["ok"])

    def test_query_packing_beats_map_packing(self):
        """The round-5 claim, asserted: fewer tokens per recovered answer."""
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bench_context_pack.py"),
             "--json", "--no-gate"],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["pass"], payload)
        self.assertGreaterEqual(payload["query_aware"]["accuracy"],
                                payload["baseline"]["accuracy"])
        self.assertGreaterEqual(payload["tokens_per_hit_reduction"], 0.30)


class TestCliRound5(unittest.TestCase):
    def run_cli(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc.stdout

    def test_code_symbols_over_cli(self):
        payload = json.loads(self.run_cli(
            "code", "symbols", str(MINI / "cache.py"), "--json"))
        self.assertEqual(payload["method"], "ast")
        self.assertTrue(any(s["name"] == "TtlCache" for s in payload["symbols"]))

    def test_code_refs_over_cli(self):
        payload = json.loads(self.run_cli(
            "code", "refs", "issue_token", str(MINI), "--json"))
        self.assertGreaterEqual(payload["count"], 1)

    def test_route_grep_rank_over_cli(self):
        payload = json.loads(self.run_cli(
            "route", "grep", str(MINI), "--pattern", "backoff", "--rank",
            "--limit", "5", "--json"))
        self.assertIn("def backoff", payload["matches"][0]["text"])

    def test_route_context_query_over_cli(self):
        payload = json.loads(self.run_cli(
            "route", "context", str(MINI), "--query", "how is retry delay computed",
            "--token-budget", "800", "--json"))
        self.assertTrue(payload["ok"])
        self.assertIn("retry", payload["data"]["query"])
        self.assertGreater(payload["data"]["windows"], 0)

    def test_route_context_without_query_is_unchanged(self):
        payload = json.loads(self.run_cli(
            "route", "context", str(MINI), "--token-budget", "600", "--json"))
        self.assertNotIn("query", payload["data"])
        self.assertIn("context", payload["data"])


if __name__ == "__main__":
    unittest.main()
