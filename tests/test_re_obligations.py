"""Tests for the obligation ledger.

This module has no external format to verify against — it is a discipline mechanism, not
a parser. So the tests verify the *semantics* it exists to enforce, and each one asserts
a distinction that would otherwise be lost:

  * `open` and `waived` are different claims. An open obligation is a hole in the
    analysis; a waived one is a conscious decision. Merging them lets a forgotten gap
    masquerade as a judgement call.
  * A waiver needs a reason. An unexplained waiver is indistinguishable from having
    forgotten the item, which is exactly the failure this ledger exists to prevent.
  * Re-recording a resolved obligation reopens it. A new declaration is new information;
    silently keeping it resolved would hide a regression.
  * `clean` is true only when nothing is open — so a caller can gate a conclusion on it
    rather than eyeballing a list.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import obligations


class _LedgerBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.db = root / "overlay.db"
        self.binary = root / "sample.bin"
        self.binary.write_bytes(b"\x7fELF" + bytes(120))
        self.other = root / "other.bin"
        self.other.write_bytes(b"\x7fELF" + bytes(64))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def record(self, topic: str, reason: str = "") -> dict:
        return obligations.record_unknown(self.binary, topic, reason, db_path=self.db)

    def listing(self, **kwargs) -> dict:
        kwargs.setdefault("db_path", self.db)
        return obligations.list_unknowns(self.binary, **kwargs)


class RecordingTest(_LedgerBase):
    def test_record_creates_an_open_obligation(self) -> None:
        result = self.record("import table", "parser returned no entries")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["topic"], "import table")
        self.assertEqual(result["reason"], "parser returned no entries")

    def test_empty_ledger_is_clean(self) -> None:
        report = self.listing()
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["count"], 0)
        self.assertTrue(report["clean"])

    def test_open_obligation_makes_the_ledger_unclean(self) -> None:
        """`clean` is the gate a caller asserts before trusting a conclusion."""
        self.record("symbols")
        report = self.listing()
        self.assertEqual(report["open_count"], 1)
        self.assertFalse(report["clean"])

    def test_re_recording_refreshes_rather_than_duplicates(self) -> None:
        self.record("symbols", "first reason")
        self.record("symbols", "second reason")
        report = self.listing()
        self.assertEqual(report["count"], 1)
        self.assertEqual(report["entries"][0]["reason"], "second reason")

    def test_topic_is_required(self) -> None:
        with self.assertRaises(ValueError):
            obligations.record_unknown(self.binary, "", "", db_path=self.db)

    def test_non_text_reason_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            obligations.record_unknown(self.binary, "topic", 42,  # type: ignore[arg-type]
                                       db_path=self.db)


class StateTransitionTest(_LedgerBase):
    def test_resolve_closes_with_a_finding(self) -> None:
        self.record("swift types")
        result = obligations.resolve_unknown(
            self.binary, "swift types", "mangled names decoded from __swift5",
            db_path=self.db)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["state"], "resolved")
        self.assertEqual(result["resolution"], "mangled names decoded from __swift5")
        self.assertTrue(self.listing()["clean"])

    def test_resolving_an_unrecorded_topic_fails(self) -> None:
        """Resolving nothing must not silently create a resolved entry.

        Otherwise a typo in the topic name produces a ledger that looks clean.
        """
        result = obligations.resolve_unknown(
            self.binary, "never recorded", "some finding", db_path=self.db)
        self.assertFalse(result["ok"])
        self.assertIn("nothing to resolve", result["error"])
        self.assertEqual(self.listing()["count"], 0)

    def test_waive_requires_a_reason(self) -> None:
        """An unexplained waiver is indistinguishable from forgetting.

        This is the single most important rule in the module: waived and open mean
        different things, so a waiver must carry the decision behind it.
        """
        self.record("v8 cache")
        result = obligations.waive_unknown(self.binary, "v8 cache", "", db_path=self.db)
        self.assertFalse(result["ok"])
        self.assertIn("requires a reason", result["error"])
        # And the obligation stays open, not waived.
        self.assertEqual(self.listing()["entries"][0]["state"], "open")

    def test_waive_with_reason_sets_state_and_keeps_reason(self) -> None:
        self.record("v8 cache")
        result = obligations.waive_unknown(
            self.binary, "v8 cache", "not in scope for this question", db_path=self.db)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["state"], "waived")
        self.assertEqual(result["reason"], "not in scope for this question")
        report = self.listing()
        self.assertEqual(report["waived_count"], 1)
        self.assertEqual(report["open_count"], 0)
        # A waived item is not an open hole, so the ledger is clean.
        self.assertTrue(report["clean"])

    def test_open_and_waived_are_counted_separately(self) -> None:
        self.record("a")
        self.record("b")
        obligations.waive_unknown(self.binary, "b", "out of scope", db_path=self.db)
        report = self.listing()
        self.assertEqual(report["counts"], {"open": 1, "waived": 1, "resolved": 0})
        self.assertFalse(report["clean"])

    def test_re_recording_a_resolved_topic_reopens_it(self) -> None:
        """A new declaration is new information.

        Keeping the entry resolved because it was resolved once before would hide a
        regression — the exact failure mode of a ledger that only appends.
        """
        self.record("symbols")
        obligations.resolve_unknown(self.binary, "symbols", "done", db_path=self.db)
        self.assertTrue(self.listing()["clean"])
        self.record("symbols", "stripped again after rebuild")
        report = self.listing()
        self.assertEqual(report["open_count"], 1)
        self.assertFalse(report["clean"])
        self.assertEqual(report["entries"][0]["state"], "open")
        self.assertEqual(report["entries"][0]["resolution"], "")

    def test_waiving_an_unrecorded_topic_fails(self) -> None:
        result = obligations.waive_unknown(
            self.binary, "ghost", "a reason", db_path=self.db)
        self.assertFalse(result["ok"])
        self.assertIn("nothing to waive", result["error"])


class QueryTest(_LedgerBase):
    def _populate(self) -> None:
        self.record("open-one")
        self.record("waived-one")
        obligations.waive_unknown(self.binary, "waived-one", "scope", db_path=self.db)
        self.record("resolved-one")
        obligations.resolve_unknown(self.binary, "resolved-one", "found", db_path=self.db)

    def test_open_entries_sort_first(self) -> None:
        """The reader wants holes first; resolved work is history."""
        self._populate()
        states = [entry["state"] for entry in self.listing()["entries"]]
        self.assertEqual(states[0], "open")
        self.assertEqual(states[-1], "resolved")

    def test_filter_by_state(self) -> None:
        self._populate()
        open_only = self.listing(state="open")
        self.assertEqual(open_only["count"], 1)
        self.assertEqual(open_only["entries"][0]["topic"], "open-one")

    def test_invalid_state_filter_is_an_error_not_an_empty_list(self) -> None:
        """Returning [] for a bad filter would read as "nothing outstanding"."""
        report = self.listing(state="pending")
        self.assertFalse(report["ok"])
        self.assertIn("unknown state", report["error"])

    def test_limit_is_applied(self) -> None:
        for index in range(6):
            self.record(f"topic-{index}")
        report = self.listing(limit=3)
        self.assertEqual(report["count"], 3)
        # ...but the counts describe the whole ledger, not the page.
        self.assertEqual(report["open_count"], 6)

    def test_ledgers_are_per_binary(self) -> None:
        """Entries travel with the artifact's sha256, not with a session."""
        self.record("only-on-first")
        other = obligations.list_unknowns(self.other, db_path=self.db)
        self.assertEqual(other["count"], 0)
        self.assertEqual(self.listing()["count"], 1)

    def test_unknown_binary_is_an_error(self) -> None:
        """A missing binary must not create a ledger keyed on nothing.

        The guard layer raises rather than returning a hash for a file it could not
        read; accepting that would produce entries attributable to no artifact.
        """
        with self.assertRaises(Exception):
            obligations.record_unknown("/nonexistent/binary", "topic", "",
                                       db_path=self.db)

    def test_blank_topic_collides_and_is_refused(self) -> None:
        """An empty topic would collide on (sha256, topic) and silently overwrite.

        Two blank records would leave one row, so an obligation would vanish without
        any error — the worst possible outcome for a ledger whose job is completeness.
        """
        with self.assertRaises(ValueError):
            obligations.record_unknown(self.binary, "   ", "", db_path=self.db)


if __name__ == "__main__":
    unittest.main()
