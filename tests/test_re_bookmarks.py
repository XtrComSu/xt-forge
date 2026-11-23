"""Bookmarks are navigation state for an RE session.

These tests pin the round trip, the address ordering used by next/prev jumps,
the strict ``after`` cursor, idempotent removal, and per-binary isolation —
a mark on one binary must never leak into another.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.bookmarks import (
    list_bookmarks,
    next_bookmark,
    prev_bookmark,
    set_bookmark,
    unset_bookmark,
)


class TestReBookmarks(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "bookmarks.db"
        # Two binaries with deliberately different bytes -> different SHA-256.
        self.bin_a = self.root / "alpha.bin"
        self.bin_b = self.root / "beta.bin"
        self.bin_a.write_bytes(b"\x7fELF" + b"alpha-payload" * 4)
        self.bin_b.write_bytes(b"\x7fELF" + b"beta-payload" * 4)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_set_then_list_roundtrip(self) -> None:
        result = set_bookmark(
            self.bin_a, 0x1200, label="entry", note="start here", db_path=self.db)
        self.assertTrue(result["ok"])
        self.assertEqual(result["rva"], hex(0x1200))
        self.assertEqual(result["label"], "entry")
        self.assertEqual(result["note"], "start here")
        self.assertTrue(result["sha256"])

        listed = list_bookmarks(self.bin_a, db_path=self.db)
        self.assertTrue(listed["ok"])
        self.assertEqual(listed["sha256"], result["sha256"])
        self.assertEqual(listed["count"], 1)
        self.assertFalse(listed["truncated"])
        item = listed["bookmarks"][0]
        self.assertEqual(item["rva"], hex(0x1200))
        self.assertEqual(item["rva_int"], 0x1200)
        self.assertEqual(item["label"], "entry")
        self.assertEqual(item["note"], "start here")
        self.assertIsInstance(item["updated"], int)

    def test_setting_twice_updates_label_without_duplicating(self) -> None:
        set_bookmark(self.bin_a, "0x1200", label="first", note="v1", db_path=self.db)
        set_bookmark(self.bin_a, 0x1200, label="second", note="v2", db_path=self.db)
        listed = list_bookmarks(self.bin_a, db_path=self.db)
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["bookmarks"][0]["label"], "second")
        self.assertEqual(listed["bookmarks"][0]["note"], "v2")

    def test_created_survives_update(self) -> None:
        set_bookmark(self.bin_a, 0x1200, label="original", db_path=self.db)
        with sqlite3.connect(str(self.db)) as conn:
            conn.execute("UPDATE bookmarks SET created=111 WHERE rva=?", (0x1200,))
        set_bookmark(self.bin_a, 0x1200, label="edited", db_path=self.db)
        with sqlite3.connect(str(self.db)) as conn:
            created = conn.execute(
                "SELECT created FROM bookmarks WHERE rva=?", (0x1200,)).fetchone()[0]
        self.assertEqual(created, 111)

    def test_list_is_ordered_by_address(self) -> None:
        for rva in (0x4000, 0x1000, 0x2000):
            set_bookmark(self.bin_a, rva, label=f"m{rva:x}", db_path=self.db)
        listed = list_bookmarks(self.bin_a, db_path=self.db)
        self.assertEqual(
            [b["rva_int"] for b in listed["bookmarks"]], [0x1000, 0x2000, 0x4000])

    def test_after_filters_strictly(self) -> None:
        for rva in (0x1000, 0x2000, 0x3000):
            set_bookmark(self.bin_a, rva, db_path=self.db)
        for after in (0x2000, "0x2000"):
            listed = list_bookmarks(self.bin_a, after=after, db_path=self.db)
            self.assertEqual([b["rva_int"] for b in listed["bookmarks"]], [0x3000])
        empty = list_bookmarks(self.bin_a, after=0x9999, db_path=self.db)
        self.assertEqual(empty["bookmarks"], [])
        self.assertEqual(empty["count"], 0)
        self.assertTrue(empty["ok"])

    def test_next_and_prev_return_none_at_edges(self) -> None:
        for rva in (0x1000, 0x2000, 0x3000):
            set_bookmark(self.bin_a, rva, db_path=self.db)
        nxt = next_bookmark(self.bin_a, 0x1000, db_path=self.db)
        self.assertTrue(nxt["ok"])
        self.assertEqual(nxt["bookmark"]["rva_int"], 0x2000)
        prv = prev_bookmark(self.bin_a, 0x3000, db_path=self.db)
        self.assertTrue(prv["ok"])
        self.assertEqual(prv["bookmark"]["rva_int"], 0x2000)
        self.assertIsNone(next_bookmark(self.bin_a, 0x3000, db_path=self.db)["bookmark"])
        self.assertIsNone(prev_bookmark(self.bin_a, 0x1000, db_path=self.db)["bookmark"])
        self.assertIsNone(next_bookmark(self.bin_b, 0, db_path=self.db)["bookmark"])

    def test_unset_removes_and_is_idempotent(self) -> None:
        set_bookmark(self.bin_a, 0x1200, db_path=self.db)
        first = unset_bookmark(self.bin_a, 0x1200, db_path=self.db)
        self.assertTrue(first["ok"])
        self.assertTrue(first["removed"])
        self.assertEqual(first["rva"], hex(0x1200))
        self.assertEqual(list_bookmarks(self.bin_a, db_path=self.db)["count"], 0)
        second = unset_bookmark(self.bin_a, 0x1200, db_path=self.db)
        self.assertTrue(second["ok"])
        self.assertFalse(second["removed"])

    def test_two_binaries_do_not_share_bookmarks(self) -> None:
        set_bookmark(self.bin_a, 0x1000, label="alpha mark", db_path=self.db)
        set_bookmark(self.bin_b, 0x2000, label="beta mark", db_path=self.db)
        a = list_bookmarks(self.bin_a, db_path=self.db)
        b = list_bookmarks(self.bin_b, db_path=self.db)
        self.assertNotEqual(a["sha256"], b["sha256"])
        self.assertEqual([x["label"] for x in a["bookmarks"]], ["alpha mark"])
        self.assertEqual([x["label"] for x in b["bookmarks"]], ["beta mark"])
        self.assertIsNone(next_bookmark(self.bin_b, 0x4000, db_path=self.db)["bookmark"])

    def test_limit_is_capped_and_truncation_reported(self) -> None:
        for rva in (0x1000, 0x2000, 0x3000, 0x4000, 0x5000):
            set_bookmark(self.bin_a, rva, db_path=self.db)
        page = list_bookmarks(self.bin_a, limit=3, db_path=self.db)
        self.assertEqual(page["count"], 3)
        self.assertTrue(page["truncated"])
        whole = list_bookmarks(self.bin_a, limit=5000, db_path=self.db)
        self.assertEqual(whole["count"], 5)
        self.assertFalse(whole["truncated"])

    def test_bad_input_raises_value_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "rva must be an address"):
            set_bookmark(self.bin_a, "not-an-address", db_path=self.db)
        with self.assertRaisesRegex(ValueError, "after must be an address"):
            list_bookmarks(self.bin_a, after="oops", db_path=self.db)
        with self.assertRaisesRegex(ValueError, "before must be a non-negative"):
            prev_bookmark(self.bin_a, -1, db_path=self.db)
        with self.assertRaisesRegex(ValueError, "limit must be at least 1"):
            list_bookmarks(self.bin_a, limit=0, db_path=self.db)
        with self.assertRaisesRegex(ValueError, "label must be text"):
            set_bookmark(self.bin_a, 0x1200, label=None, db_path=self.db)


if __name__ == "__main__":
    unittest.main()
