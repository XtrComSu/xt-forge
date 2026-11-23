"""Tests for atomic batch renames in the RE overlay.

WHY these tests exist: the batched API must never leave a half-applied merge.
Every failure case below therefore asserts not just that an error is raised but
that the annotation list is still empty afterwards.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.annotate import annotate
from xtforge.core.re.bulk import rename_from_csv, rename_many


class TestRenameMany(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.binary = root / "sample.bin"
        self.binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        self.db_path = root / "overlay.db"

    def _list(self) -> dict:
        return annotate(action="list", binary=self.binary, db_path=self.db_path)

    def test_three_renames_applied_and_listed(self) -> None:
        result = rename_many(
            self.binary,
            {0x1130: "one", "0x1140": "two", 4418: "three"},
            db_path=self.db_path,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["engine"], "python")
        self.assertEqual(result["count"], 3)
        self.assertEqual(len(result["applied"]), 3)
        self.assertEqual(result["sha256"], self._list()["sha256"])

        listing = self._list()
        self.assertEqual(listing["count"], 3)
        names = {row["rva"]: row["new_name"] for row in listing["annotations"]}
        self.assertEqual(names, {"0x1130": "one", "0x1140": "two", hex(4418): "three"})

    def test_duplicate_address_raises_and_writes_nothing(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            rename_many(
                self.binary,
                [(0x1130, "first"), ("0x1130", "second")],
                db_path=self.db_path,
            )
        self.assertIn("0x1130", str(ctx.exception))
        self.assertEqual(self._list()["count"], 0)

    def test_empty_name_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            rename_many(self.binary, [(0x1130, "   ")], db_path=self.db_path)
        self.assertIn("0x1130", str(ctx.exception))
        self.assertEqual(self._list()["count"], 0)

    def test_existing_address_updates_without_duplicating(self) -> None:
        annotate(action="rename", binary=self.binary, rva=0x1130,
                 name="old_name", db_path=self.db_path)
        result = rename_many(self.binary, {0x1130: "new_name"}, db_path=self.db_path)
        self.assertEqual(result["count"], 1)
        listing = self._list()
        self.assertEqual(listing["count"], 1)
        self.assertEqual(listing["annotations"][0]["new_name"], "new_name")

    def test_duplicate_name_raises_and_writes_nothing(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            rename_many(
                self.binary,
                [(0x1130, "same"), (0x1140, "same")],
                db_path=self.db_path,
            )
        self.assertIn("same", str(ctx.exception))
        self.assertEqual(self._list()["count"], 0)

    def test_more_than_5000_renames_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            rename_many(
                self.binary,
                [(i, f"name_{i}") for i in range(5001)],
                db_path=self.db_path,
            )
        self.assertIn("5000", str(ctx.exception))
        self.assertEqual(self._list()["count"], 0)


class TestRenameFromCsv(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.binary = root / "sample.bin"
        self.binary.write_bytes(b"MZ" + b"\x00" * 62)
        self.db_path = root / "overlay.db"

    def _list(self) -> dict:
        return annotate(action="list", binary=self.binary, db_path=self.db_path)

    def test_csv_roundtrip(self) -> None:
        csv_text = "\n".join([
            "# a comment line",
            "",
            "0x1130,alpha",
            "0x1140,beta   # trailing comment",
        ])
        result = rename_from_csv(self.binary, csv_text, db_path=self.db_path)
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            result["applied"],
            [{"rva": "0x1130", "name": "alpha"}, {"rva": "0x1140", "name": "beta"}],
        )
        names = {row["rva"]: row["new_name"] for row in self._list()["annotations"]}
        self.assertEqual(names, {"0x1130": "alpha", "0x1140": "beta"})

    def test_malformed_csv_line_names_its_line_number(self) -> None:
        csv_text = "0x1130,ok\nnot_a_pair\n0x1140,fine\n"
        with self.assertRaises(ValueError) as ctx:
            rename_from_csv(self.binary, csv_text, db_path=self.db_path)
        self.assertIn("line 2", str(ctx.exception))
        self.assertEqual(self._list()["count"], 0)


if __name__ == "__main__":
    unittest.main()
