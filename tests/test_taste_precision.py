"""Precision tests for the taste extractor.

The profile is only worth anything if it holds the user's preferences and
nothing else. The prompts that reach the plugin are mostly work orders —
"TASK: Use error-based SQLi to extract the version" is an instruction for
this run, not a rule for every run. A loose extractor turned those into
learnings, and a learning that nobody can reproduce is noise that still
counts as evidence.

These cases come from the live profile: every one of them was a real key
that the old rules invented.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.taste.extract import extract  # noqa: E402

# Work orders and prose. None of these is a durable preference.
JUNK = [
    "TASK: Use error-based SQLi to extract the MySQL/MariaDB version WITHOUT "
    "dumping user data.",
    "V-21: Target app.example.com:443. Use openssl s_client to test TLS 1.0, "
    "1.1, 1.2, 1.3 support.",
    "- Use a scratch dir under /tmp/opencode/v31/ ; persist machine-readable "
    "evidence as JSON with one record per request.",
    "I request you use the free opencode go + opencode default options to "
    "delegate 5-10 agents all at once.",
    "cant you use Q4-Q5 to use it?",
    "can you just make the introduction abit more indepth? it feels too empty "
    "to really make sense of anything something like subtle foreshadowing "
    "instead of being clear and direct aswell",
    "please add proper animation + 3d backgrounds (dont add code names and "
    "version control)",
    "Map the schema via the filename SQLi. Use UNION or boolean/time-based "
    "extraction via the filename parameter.",
    "1. Exim version/CVE exposure: confirm the exact Exim version and use a "
    "web search / advisory lookup.",
    "also ensure to use least 15-30 BEAM free agents",
    "you can download node and java if needed so find alternatives if you "
    "dont wana use it perferabl",
]

# Durable preferences. These must survive.
REAL = [
    ("Always use ruff for linting Python.", "ruff linting python"),
    ("Always prefer ruff for linting Python.", "ruff linting python"),
    ("Please use ruff for linting Python.", "ruff linting python"),
    ("Never hardcode absolute paths.", "hardcode absolute paths"),
    ("Never print secrets in tool output.", "print secrets tool output"),
    ("Always add a --json flag to every command.", "add json flag every command"),
    ("Use tabs not spaces for indentation.", "tabs"),
]


class TestPrecision(unittest.TestCase):
    def test_work_orders_create_no_learning(self):
        for text in JUNK:
            with self.subTest(text=text[:48]):
                signals = extract(text, source="prompt")
                self.assertEqual(signals, [],
                                 f"invented a key from a work order: {text[:48]}")

    def test_durable_preferences_survive(self):
        for text, key in REAL:
            with self.subTest(text=text):
                signals = extract(text, source="prompt")
                self.assertTrue(signals, f"lost a real preference: {text}")
                self.assertIn(key, [s.key for s in signals])

    def test_a_bare_use_is_not_a_preference(self):
        self.assertEqual(extract("use pytest for tests", source="prompt"), [])

    def test_a_preference_word_is_what_makes_it_one(self):
        signals = extract("always use pytest for tests", source="prompt")
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].key, "pytest tests")

    def test_contrasting_prose_is_not_a_preference(self):
        # "instead of" alone is not a cue: it appears in every contrast.
        signals = extract("use subtle foreshadowing instead of a plain intro",
                          source="prompt")
        self.assertEqual(signals, [])

    def test_an_explicit_comparison_is_a_preference(self):
        signals = extract("I prefer pytest over unittest", source="prompt")
        keys = {s.key: s.polarity for s in signals}
        self.assertEqual(keys.get("pytest"), 1)
        self.assertEqual(keys.get("unittest"), -1)


class TestPrune(unittest.TestCase):
    """`taste prune` retires what the current rules would not invent."""

    def setUp(self):
        from xtforge.core.taste.store import TasteStore
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="taste-prune-")
        self.store = TasteStore(f"{self.tmp}/taste.db")
        self.addCleanup(self.store.close)

    def test_a_learning_the_rules_reproduce_is_kept(self):
        self.store.ingest(extract("Never hardcode absolute paths.",
                                  source="prompt"))
        self.assertEqual(self.store.prunable(), [])

    def test_a_learning_invented_by_loose_rules_is_prunable(self):
        self.store.ingest(extract("TASK: Use openssl s_client to test TLS 1.",
                                  source="prompt"))
        # Under the old rules this produced a key; simulate that by storing
        # the signal the old pattern would have produced.
        from xtforge.core.taste.schema import Signal
        signal = Signal(kind="explicit", polarity=1, category="security",
                        key="openssl s_client",
                        statement="openssl s_client",
                        quote="TASK: Use openssl s_client to test TLS 1.",
                        source="prompt")
        self.store.ingest([signal])
        prunable = self.store.prunable()
        self.assertEqual([p["key"] for p in prunable], ["openssl s client"])

    def test_manual_learnings_are_never_prunable(self):
        from xtforge.core.taste.extract import extract_one
        self.store.ingest([extract_one("Use tabs, not spaces")])
        self.assertEqual(self.store.prunable(), [])


if __name__ == "__main__":
    unittest.main()
