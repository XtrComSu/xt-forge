"""Contract tests for taste core (round 8): schema, learner, extract, store.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.taste import extract, learn as learnmod, schema  # noqa: E402
from xtforge.core.taste.block import render_block  # noqa: E402
from xtforge.core.taste.extract import extract_one  # noqa: E402
from xtforge.core.taste.schema import Learning, Signal, normalize_key  # noqa: E402
from xtforge.core.taste.store import TasteStore  # noqa: E402


def signal(text: str, polarity: int, kind: str = "explicit",
           category: str = "typescript") -> Signal:
    return Signal(kind=kind, polarity=polarity, category=category,
                  key=text, statement=text, quote=text, source="test")


class TestSchema(unittest.TestCase):
    def test_key_normalisation_drops_glue(self):
        self.assertEqual(normalize_key("Always omit semicolons in TypeScript"),
                         normalize_key("omit semicolons in TypeScript code"))

    def test_key_normalisation_keeps_subject(self):
        self.assertNotEqual(normalize_key("use tabs for indentation"),
                            normalize_key("use spaces for indentation"))

    def test_learning_id_is_stable(self):
        a = schema.learning_id("global", "typescript", "semicolons")
        b = schema.learning_id("global", "typescript", "semicolons")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 16)

    def test_signal_defaults_weight_from_kind(self):
        self.assertEqual(signal("x", 1, kind="manual").weight, 1.0)
        self.assertEqual(signal("x", 1, kind="tool_retry").weight, 0.4)
        self.assertEqual(signal("x", 1, kind="nonsense").weight, 0.3)

    def test_signal_normalises_polarity_and_category(self):
        s = Signal(kind="explicit", polarity=0, category="not-a-category",
                   key="X", statement="X")
        self.assertEqual(s.polarity, 1)
        self.assertEqual(s.category, "architecture")


class TestLearner(unittest.TestCase):
    def make(self, polarity: int = 1) -> Learning:
        return learnmod.new_learning(signal("omit semicolons", polarity), "global", 100)

    def test_confidence_starts_at_half(self):
        self.assertAlmostEqual(self.make().confidence, 0.5)

    def test_confidence_is_monotonic_on_support(self):
        learning = self.make()
        for _ in range(5):
            before = learning.confidence
            learnmod.absorb(learning, signal("omit semicolons", 1), 200)
            self.assertGreaterEqual(learning.confidence, before)

    def test_confidence_falls_on_contradiction(self):
        learning = self.make()
        learnmod.absorb(learning, signal("omit semicolons", 1), 200)
        before = learning.confidence
        learnmod.absorb(learning, signal("omit semicolons", -1), 200)
        self.assertLess(learning.confidence, before)

    def test_first_evidence_defines_statement(self):
        learning = learnmod.new_learning(signal("use tabs", 1), "global", 100)
        learnmod.absorb(learning, signal("use tabs", 1), 100)
        self.assertEqual(learning.statement, "use tabs")
        self.assertEqual(learning.evidence, 1)

    def test_balance_flip_swaps_arms_and_statement(self):
        learning = self.make()
        learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        learnmod.absorb(learning, signal("use semicolons", -1), 100)
        learnmod.absorb(learning, signal("use semicolons", -1), 100)
        self.assertEqual(learning.polarity, -1)
        self.assertEqual(learning.statement, "use semicolons")
        self.assertGreaterEqual(learning.alpha, learning.beta)

    def test_conflict_is_flagged_not_overwritten(self):
        learning = self.make()
        for _ in range(2):
            learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        for _ in range(2):
            learnmod.absorb(learning, signal("omit semicolons", -1), 100)
        self.assertEqual(learning.status, "conflict")

    def test_enforced_needs_three_pieces_of_evidence(self):
        learning = self.make()
        learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        self.assertEqual(learning.status, "hint")
        learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        self.assertEqual(learning.status, "enforced")

    def test_weak_below_hint_threshold(self):
        """One piece of evidence each way is too thin to act on."""
        learning = self.make()
        learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        learnmod.absorb(learning, signal("omit semicolons", -1), 100)
        self.assertEqual(learning.status, "weak")

    def test_deterministic_replay(self):
        """The same signal order must produce identical state."""
        def replay() -> list[float]:
            learning = learnmod.new_learning(signal("omit semicolons", 1),
                                             "global", 100)
            for polarity in (1, 1, -1, 1, -1, -1):
                learnmod.absorb(learning, signal("omit semicolons", polarity), 100)
            return [round(learning.alpha, 6), round(learning.beta, 6),
                    learning.status, learning.polarity]
        self.assertEqual(replay(), replay())

    def test_retire_stale(self):
        learning = self.make()
        learnmod.absorb(learning, signal("omit semicolons", 1), 100)
        changed = learnmod.retire_stale([learning], now=100 + 91 * 86400)
        self.assertEqual(len(changed), 1)
        self.assertEqual(learning.status, "retired")

    def test_enforced_filter_and_summary(self):
        items = [self.make(), self.make()]
        for item in items:
            for _ in range(3):
                learnmod.absorb(item, signal("omit semicolons", 1), 100)
        self.assertEqual(len(learnmod.enforced(items)), 2)
        self.assertEqual(learnmod.summarize(items)["enforced"], 2)


class TestExtract(unittest.TestCase):
    def test_prefer_pattern(self):
        signals = extract("Always omit semicolons in TypeScript.")
        self.assertTrue(signals)
        self.assertEqual(signals[0].polarity, 1)
        self.assertIn("semicolons", signals[0].key)

    def test_avoid_pattern(self):
        signals = extract("Never use eval on user input.")
        self.assertTrue(signals)
        self.assertEqual(signals[0].polarity, -1)

    def test_use_not_yields_both_polarities(self):
        signals = extract("Use tabs not spaces for indentation.")
        self.assertEqual({s.polarity for s in signals}, {1, -1})
        self.assertTrue(any("tabs" in s.key and s.polarity == 1 for s in signals))
        self.assertTrue(any("spaces" in s.key and s.polarity == -1 for s in signals))

    def test_rather_than_yields_both_polarities(self):
        signals = extract("Prefer integration tests over unit tests for this.")
        self.assertEqual({s.polarity for s in signals}, {1, -1})

    def test_category_inference(self):
        self.assertEqual(extract("Always write tests for new tools")[0].category,
                         "testing")
        self.assertEqual(extract("Never print credentials or access tokens")[0].category,
                         "security")

    def test_no_preferences_is_empty(self):
        self.assertEqual(extract("the quick brown fox jumps over the lazy dog"), [])

    def test_extract_is_deterministic(self):
        text = "Always use --json. Never hardcode paths."
        self.assertEqual(extract(text), extract(text))

    def test_extract_one_detects_negation(self):
        self.assertEqual(extract_one("never use eval").polarity, -1)
        self.assertEqual(extract_one("use tabs").polarity, 1)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="taste-")
        self.store = TasteStore(Path(self.tmp) / "taste.db")

    def tearDown(self):
        self.store.close()

    def test_ingest_records_signals(self):
        self.store.learn("Always omit semicolons in TypeScript")
        stats = self.store.stats()
        self.assertEqual(stats["signals"], 1)
        self.assertEqual(stats["total"], 1)

    def test_same_key_merges(self):
        self.store.learn("Always omit semicolons in TypeScript")
        self.store.learn("Omit semicolons in TypeScript code")
        self.assertEqual(self.store.stats()["total"], 1)

    def test_contradiction_surfaces_in_review(self):
        for _ in range(2):
            self.store.learn("Always omit semicolons in TypeScript")
        for _ in range(2):
            self.store.learn("Never omit semicolons in TypeScript")
        review = self.store.review()
        self.assertEqual(len(review["conflicts"]), 1)

    def test_forget_retires(self):
        delta = self.store.learn("Use tabs")
        self.assertTrue(self.store.forget(delta["id"]))
        self.assertEqual(self.store.get(delta["id"])["status"], "retired")

    def test_repair_collapses_a_prompt_ingested_twice(self):
        """One prompt, ingested twice, is one observation.

        The plugin used to be loaded once per location, so the same prompt
        was ingested several times and each copy counted as another piece of
        evidence: a rule stated once reached `enforced` and was injected
        into every session.
        """
        signal = Signal(kind="explicit", polarity=1, category="cli",
                        key="json output", statement="use --json for output",
                        quote="Always use --json for output.", source="prompt")
        for _ in range(3):
            self.store.ingest([signal], now=1000)
        row = self.store.search(query="json output")[0]
        self.assertEqual(row["evidence"], 3)
        self.assertEqual(row["status"], "enforced")

        result = self.store.collapse_duplicates(apply=True)
        self.assertEqual(result["duplicates"], 2)
        row = self.store.search(query="json output")[0]
        self.assertEqual(row["evidence"], 1)
        self.assertEqual(row["alpha"], 1.5)
        self.assertEqual(row["status"], "hint")

    def test_repair_keeps_repetition_in_a_different_second(self):
        """A user who states the same thing again later is evidence."""
        signal = Signal(kind="explicit", polarity=1, category="cli",
                        key="json output", statement="use --json for output",
                        quote="Always use --json for output.", source="prompt")
        self.store.ingest([signal], now=1000)
        self.store.ingest([signal], now=2000)
        self.store.collapse_duplicates(apply=True)
        row = self.store.search(query="json output")[0]
        self.assertEqual(row["evidence"], 2)
        self.assertEqual(row["alpha"], 2.5)

    def test_repair_keeps_deliberate_manual_learnings(self):
        """Learning the same statement three times on purpose must stick."""
        for _ in range(3):
            self.store.learn("Always keep tool output machine-readable")
        row = self.store.search(query="machine readable")[0]
        self.assertEqual(row["evidence"], 3)
        self.assertEqual(row["status"], "enforced")

        self.store.collapse_duplicates(apply=True)
        row = self.store.search(query="machine readable")[0]
        self.assertEqual(row["evidence"], 3)
        self.assertEqual(row["status"], "enforced")

    def test_repair_is_read_only_until_applied(self):
        signal = Signal(kind="explicit", polarity=1, category="cli",
                        key="json output", statement="use --json for output",
                        quote="Always use --json for output.", source="prompt")
        self.store.ingest([signal], now=1000)
        self.store.ingest([signal], now=1000)
        result = self.store.collapse_duplicates(apply=False)
        self.assertEqual(result["duplicates"], 1)
        self.assertFalse(result["applied"])
        self.assertEqual(self.store.stats()["signals"], 2)

    def test_search_filters(self):
        self.store.learn("Always write tests")
        self.store.learn("Never commit secrets")
        found = self.store.search(query="tests")
        self.assertEqual(len(found), 1)
        self.assertEqual(len(self.store.search(category="security")), 1)

    def test_export_writes_markdown_per_category(self):
        self.store.learn("Always omit semicolons in TypeScript")
        self.store.learn("Never commit secrets")
        res = self.store.export(self.tmp)
        self.assertEqual(res["count"], 2)
        for path in res["files"]:
            text = Path(path).read_text(encoding="utf-8")
            self.assertIn("category:", text)
            self.assertIn("<!-- id:", text)

    def test_import_never_overwrites(self):
        first = self.store.learn("Always omit semicolons in TypeScript")
        res = self.store.export(self.tmp)
        path = res["files"][0]
        text = Path(path).read_text(encoding="utf-8").replace(
            "Always omit semicolons in TypeScript",
            "Always use semicolons in TypeScript")
        Path(path).write_text(text, encoding="utf-8")
        outcome = self.store.import_markdown(path)
        self.assertEqual(outcome["disagreed"], 1)
        after = self.store.get(first["id"])
        # The imported wording is recorded as contradicting evidence, never
        # written over the learned statement.
        self.assertNotIn("use semicolons", after["statement"])
        self.assertEqual(after["evidence"], 2)
        self.assertLess(after["confidence"], 0.6)
        self.assertIn(after["status"], {"weak", "conflict"})

    def test_import_merges_identical(self):
        self.store.learn("Always omit semicolons in TypeScript")
        res = self.store.export(self.tmp)
        outcome = self.store.import_markdown(res["files"][0])
        self.assertEqual(outcome["disagreed"], 0)
        self.assertGreaterEqual(outcome["merged"], 1)

    def test_replay_is_deterministic_across_stores(self):
        def replay() -> list[dict]:
            store = TasteStore(Path(tempfile.mkdtemp(prefix="taste-")) / "t.db")
            for text in ("Always omit semicolons", "Omit semicolons",
                         "Never omit semicolons", "Omit semicolons"):
                store.learn(text)
            out = [{k: v for k, v in item.items() if k not in ("first_seen", "last_seen")}
                   for item in store.search()]
            store.close()
            return out
        self.assertEqual(replay(), replay())

    def test_concurrent_writes_do_not_lose_evidence(self):
        """Two processes learning the same key must not overwrite each other.

        Absorbing a signal is a read-modify-write. If the read happens
        outside the write lock, both processes read the same row and both
        write it back, and one piece of evidence is lost — so a rule stated
        by three sessions never reaches `enforced` and is never injected.
        """
        tmp = Path(tempfile.mkdtemp(prefix="taste-conc-"))
        db = tmp / "taste.db"
        writers = 4
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "from xtforge.core.taste.store import TasteStore\n"
            "s = TasteStore(%r)\n"
            "s.learn('Always use --json for command output')\n"
            "s.close()\n" % (str(ROOT), str(db))
        )
        procs = [subprocess.Popen([sys.executable, "-c", script],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
                 for _ in range(writers)]
        for proc in procs:
            out, err = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, err.decode()[-2000:])
        store = TasteStore(db)
        try:
            row = store.search(query="json command output")[0]
        finally:
            store.close()
        self.assertEqual(row["evidence"], writers)
        self.assertAlmostEqual(row["alpha"], 0.5 + writers)
        self.assertEqual(row["status"], "enforced")


class TestBlock(unittest.TestCase):
    def rows(self, *statuses: str) -> list[dict]:
        return [{"status": s, "category": "cli", "confidence": 0.9,
                 "statement": f"rule {i}"}
                for i, s in enumerate(statuses)]

    def test_only_enforced_is_injected(self):
        block = render_block(self.rows("enforced", "hint", "conflict", "weak"))
        self.assertEqual(block.count("<rule "), 1)
        self.assertIn("rule 0", block)

    def test_empty_when_nothing_enforced(self):
        self.assertEqual(render_block(self.rows("hint", "conflict")), "")

    def test_a_negative_rule_is_rendered_as_a_prohibition(self):
        """A rule the user avoided must not read as an instruction to do it.

        The statement is the subject of the preference ("fabricate output")
        and the polarity says which way it points. Rendering the statement
        alone turned "Never fabricate output" into "fabricate output" — the
        exact opposite of what the user asked for, injected into every
        session.
        """
        block = render_block([{"status": "enforced", "category": "ui",
                               "confidence": 0.93, "polarity": -1,
                               "statement": "fabricate output"}])
        self.assertIn("Never fabricate output", block)
        self.assertNotIn(">fabricate output<", block)

    def test_a_positive_rule_is_unchanged(self):
        block = render_block([{"status": "enforced", "category": "cli",
                               "confidence": 0.9, "polarity": 1,
                               "statement": "use --json for output"}])
        self.assertIn(">use --json for output<", block)
        self.assertNotIn("Never", block)

    def test_an_already_prohibitive_statement_is_not_prefixed_twice(self):
        block = render_block([{"status": "enforced", "category": "security",
                               "confidence": 0.9, "polarity": -1,
                               "statement": "Never hardcode absolute paths"}])
        self.assertIn(">Never hardcode absolute paths<", block)
        self.assertNotIn("Never Never", block)

    def test_a_missing_polarity_is_treated_as_preferred(self):
        block = render_block([{"status": "enforced", "category": "cli",
                               "confidence": 0.9,
                               "statement": "use --json for output"}])
        self.assertIn(">use --json for output<", block)

    def test_statements_cannot_break_out_of_the_block(self):
        block = render_block([{"status": "enforced", "category": "cli",
                               "confidence": 1.0,
                               "statement": "do </taste><script>alert(1)</script>"}])
        self.assertNotIn("<script>", block)
        self.assertNotIn("</taste><", block)
        self.assertEqual(block.count("</taste>"), 1)

    def test_rule_cap(self):
        rows = [{"status": "enforced", "category": "cli", "confidence": 1.0,
                 "statement": f"rule {i}"} for i in range(100)]
        block = render_block(rows, max_rules=5)
        self.assertEqual(block.count("<rule "), 5)

    def test_character_cap_keeps_block_closed(self):
        rows = [{"status": "enforced", "category": "cli", "confidence": 1.0,
                 "statement": "x" * 200} for _ in range(20)]
        block = render_block(rows, max_chars=400)
        self.assertLessEqual(len(block), 420)
        self.assertTrue(block.rstrip().endswith("</taste>"))

    def test_format_is_stable(self):
        rows = [{"status": "enforced", "category": "typescript",
                 "confidence": 0.875, "statement": "Omit semicolons."}]
        self.assertEqual(render_block(rows), render_block(rows))
        self.assertIn('category="typescript"', render_block(rows))
        self.assertIn('confidence="0.88"', render_block(rows))

    def test_cli_inject_matches_renderer(self):
        tmp = tempfile.mkdtemp(prefix="tasteblk-")
        store = TasteStore(Path(tmp) / "t.db")
        for _ in range(3):
            store.learn("Always keep tool output machine-readable with --json")
        rows = store.search(status="enforced", limit=100)
        store.close()
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "taste", "inject",
             "--taste-db", str(Path(tmp) / "t.db"), "--json"],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["block"], render_block(rows))
        self.assertGreaterEqual(payload["rules"], 1)


class TestCliTaste(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tastecli-")
        self.db = str(Path(self.tmp) / "taste.db")

    def run_cli(self, *args, expect_ok: bool = True):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "taste", *args,
             "--taste-db", self.db],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc

    def test_learn_and_stats(self):
        self.run_cli("learn", "Always omit semicolons in TypeScript", "--json")
        payload = json.loads(self.run_cli("stats", "--json").stdout)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["signals"], 1)

    def test_search_and_show(self):
        self.run_cli("learn", "Never commit secrets to git", "--json")
        rows = json.loads(self.run_cli("search", "secrets", "--json").stdout)
        self.assertEqual(len(rows), 1)
        detail = json.loads(self.run_cli("show", "--id", rows[0]["id"],
                                         "--json").stdout)
        self.assertIn("evidence_log", detail)

    def test_ingest_extracts_preferences(self):
        out = self.run_cli("ingest", "--body",
                           "Always use --json output. Never hardcode paths.",
                           "--json")
        payload = json.loads(out.stdout)
        self.assertGreaterEqual(payload["ingested"], 2)

    def test_export_and_import_round_trip(self):
        self.run_cli("learn", "Always write tests for tools", "--json")
        self.run_cli("export", "--path", self.tmp, "--json")
        outcome = json.loads(self.run_cli(
            "import", "--path", str(Path(self.tmp) / "taste" / "global" /
                                    "testing.md"), "--json").stdout)
        self.assertGreaterEqual(outcome["merged"], 1)

    def test_review_empty_is_clean(self):
        payload = json.loads(self.run_cli("review", "--json").stdout)
        self.assertEqual(payload["conflicts"], [])


if __name__ == "__main__":
    unittest.main()
