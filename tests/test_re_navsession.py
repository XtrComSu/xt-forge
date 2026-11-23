"""Navigation state: a cursor, a bounded trail, and named waypoints, keyed by content hash.

Two properties get the most attention here, because they are the ones a naive implementation
gets wrong and the errors are silent:

  * **Content-hash keying.** A cursor stored against a *path* survives a rebuild and then
    points at an address that means something different. Every test that mutates the binary
    asserts the cursor does not follow.
  * **Bounded history.** An unbounded trail is not navigable — you cannot walk back to
    somewhere you cannot find. The cap is asserted, not assumed.

Navigation is also deliberately *permissive*: a cursor is advisory, so a recorded address is
returned as-is rather than validated against the current disassembly. That is a decision, not
an oversight, and `test_address_beyond_the_binary_is_still_returned` records it — refusing to
open a session because the address is stale would make the resume path useless exactly when
the binary has changed underneath.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import navsession

FIXTURE_SOURCE = """
int alpha(int x){return x+1;}
int beta(int y){return y*2;}
int main(void){return alpha(1)+beta(2);}
"""


class SessionCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("gcc"):
            raise unittest.SkipTest("gcc is required")
        import subprocess
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        source = cls.root / "a.c"
        source.write_text(FIXTURE_SOURCE)
        cls.binary = cls.root / "a.bin"
        result = subprocess.run(["gcc", "-O0", "-o", str(cls.binary), str(source)],
                                capture_output=True, timeout=300, check=False)
        if result.returncode != 0:
            raise unittest.SkipTest("fixture did not compile")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        self.db = Path(tempfile.mkdtemp()) / "nav.db"


class CursorTest(SessionCase):
    def test_no_cursor_initially(self) -> None:
        report = navsession.current(self.binary, db_path=self.db)
        self.assertTrue(report["ok"])
        self.assertIsNone(report["address"])
        self.assertIn("note", report)

    def test_goto_moves_the_cursor(self) -> None:
        navsession.goto(self.binary, "0x1000", db_path=self.db)
        self.assertEqual(navsession.current(self.binary, db_path=self.db)["address"], "0x1000")

    def test_goto_records_the_previous_address(self) -> None:
        navsession.goto(self.binary, "0x1000", db_path=self.db)
        report = navsession.goto(self.binary, "0x1020", db_path=self.db)
        self.assertEqual(report["previous"], "0x1000")
        self.assertEqual(report["address"], "0x1020")

    def test_first_goto_has_no_previous(self) -> None:
        self.assertIsNone(navsession.goto(self.binary, "0x1000", db_path=self.db)["previous"])

    def test_bare_number_is_decimal_like_the_rest_of_the_tool(self) -> None:
        """`parse_rva` reads a bare number as decimal and only `0x` as hex.

        That is the convention `re annotate` already uses, so navigation follows it instead of
        inventing a second one. The consequence is worth stating out loud: `1040` means 1040,
        not 0x1040, and a caller who assumes otherwise lands at a different address.
        """
        navsession.goto(self.binary, "1040", db_path=self.db)
        self.assertEqual(navsession.current(self.binary, db_path=self.db)["address"],
                         hex(1040))
        navsession.goto(self.binary, "0x1040", db_path=self.db)
        self.assertEqual(navsession.current(self.binary, db_path=self.db)["address"], "0x1040")
        self.assertNotEqual(hex(1040), "0x1040")

    def test_negative_address_is_rejected(self) -> None:
        report = navsession.goto(self.binary, -1, db_path=self.db)
        self.assertFalse(report["ok"])

    def test_address_past_the_64_bit_range_is_refused_not_raised(self) -> None:
        """Found by adversarial probing: an address past 2**63 raised OverflowError.

        SQLite integers are signed 64-bit, so the value reached the driver. A stored cursor
        makes this worse than a normal bad argument: refusing is required, because a silently
        truncated address would persist and point somewhere unintended.
        """
        report = navsession.goto(self.binary, 2 ** 63, db_path=self.db)
        self.assertFalse(report["ok"])
        self.assertIn("64-bit", report["error"])
        self.assertIsNone(navsession.current(self.binary, db_path=self.db)["address"])

    def test_the_largest_storable_address_works(self) -> None:
        """The boundary itself must be usable, or the guard is off by one."""
        report = navsession.goto(self.binary, 2 ** 63 - 1, db_path=self.db)
        self.assertTrue(report["ok"])
        self.assertEqual(navsession.current(self.binary, db_path=self.db)["address"],
                         hex(2 ** 63 - 1))

    def test_bookmark_address_is_bounded_too(self) -> None:
        for value in (-1, 2 ** 63):
            report = navsession.bookmark(self.binary, "bad", value, db_path=self.db)
            self.assertFalse(report["ok"], f"{value} was accepted as a bookmark address")


class HistoryTest(SessionCase):
    def test_step_back_walks_the_trail(self) -> None:
        for address in ("0x1000", "0x1020", "0x1040"):
            navsession.goto(self.binary, address, db_path=self.db)
        report = navsession.step(self.binary, "prev", db_path=self.db)
        self.assertEqual(report["address"], "0x1020")

    def test_step_back_with_short_history_is_harmless(self) -> None:
        navsession.goto(self.binary, "0x1000", db_path=self.db)
        report = navsession.step(self.binary, "prev", db_path=self.db)
        self.assertTrue(report["ok"])
        self.assertIsNone(report["address"])
        self.assertIn("note", report)

    def test_step_back_twice_reaches_further(self) -> None:
        for address in ("0x1000", "0x1020", "0x1040"):
            navsession.goto(self.binary, address, db_path=self.db)
        navsession.step(self.binary, "prev", db_path=self.db)
        second = navsession.step(self.binary, "prev", db_path=self.db)
        self.assertEqual(second["address"], "0x1000")

    def test_invalid_direction_is_rejected(self) -> None:
        report = navsession.step(self.binary, "sideways", db_path=self.db)
        self.assertFalse(report["ok"])
        self.assertIn("prev", report["error"])

    def test_history_is_bounded(self) -> None:
        """A trail that grows forever is a trail you cannot navigate."""
        for index in range(navsession.MAX_HISTORY + 60):
            navsession.goto(self.binary, f"0x{0x1000 + index * 4:x}", db_path=self.db)
        report = navsession.current(self.binary, db_path=self.db)
        self.assertLessEqual(report["history_depth"], navsession.MAX_HISTORY,
                             "history grew past its cap")

    def test_bounded_history_keeps_the_most_recent(self) -> None:
        """Trimming must drop the oldest entries, not the newest."""
        for index in range(navsession.MAX_HISTORY + 10):
            navsession.goto(self.binary, f"0x{0x1000 + index * 4:x}", db_path=self.db)
        resume = navsession.where_to(self.binary, db_path=self.db)
        newest = f"0x{0x1000 + (navsession.MAX_HISTORY + 9) * 4:x}"
        self.assertEqual(resume["address"], newest)


class BookmarkTest(SessionCase):
    def test_bookmark_round_trips(self) -> None:
        navsession.bookmark(self.binary, "entry", "0x1000", db_path=self.db)
        listing = navsession.bookmark(self.binary, "x", db_path=self.db)
        self.assertEqual(listing["count"], 1)
        self.assertEqual(listing["bookmarks"][0]["name"], "entry")
        self.assertEqual(listing["bookmarks"][0]["address"], "0x1000")

    def test_bookmark_is_updated_in_place(self) -> None:
        navsession.bookmark(self.binary, "hot", "0x1000", db_path=self.db)
        navsession.bookmark(self.binary, "hot", "0x2000", db_path=self.db)
        listing = navsession.bookmark(self.binary, "x", db_path=self.db)
        self.assertEqual(listing["count"], 1, "re-bookmarking created a duplicate")
        self.assertEqual(listing["bookmarks"][0]["address"], "0x2000")

    def test_empty_name_is_rejected(self) -> None:
        report = navsession.bookmark(self.binary, "   ", "0x1000", db_path=self.db)
        self.assertFalse(report["ok"])

    def test_overlong_name_is_rejected(self) -> None:
        report = navsession.bookmark(self.binary, "x" * 129, "0x1000", db_path=self.db)
        self.assertFalse(report["ok"])

    def test_bookmarks_are_sorted_by_address(self) -> None:
        for name, address in (("c", "0x3000"), ("a", "0x1000"), ("b", "0x2000")):
            navsession.bookmark(self.binary, name, address, db_path=self.db)
        listing = navsession.bookmark(self.binary, "x", db_path=self.db)
        addresses = [int(entry["address"], 16) for entry in listing["bookmarks"]]
        self.assertEqual(addresses, sorted(addresses))


class ContentHashKeyingTest(SessionCase):
    """The property that makes this trustworthy: a rebuilt binary starts clean."""

    def test_different_content_does_not_inherit_the_cursor(self) -> None:
        import subprocess
        navsession.goto(self.binary, "0x1040", db_path=self.db)
        other = self.root / "rebuilt.bin"
        source = self.root / "b.c"
        source.write_text("int gamma(int z){return z*3;}\nint main(void){return 0;}\n")
        subprocess.run(["gcc", "-O0", "-o", str(other), str(source)],
                       capture_output=True, timeout=300, check=False)
        if not other.is_file():
            self.skipTest("could not build the second binary")
        report = navsession.current(other, db_path=self.db)
        self.assertIsNone(report["address"],
                          "a different binary inherited another binary's cursor")

    def test_bookmarks_do_not_leak_between_binaries(self) -> None:
        import subprocess
        navsession.bookmark(self.binary, "mine", "0x1000", db_path=self.db)
        other = self.root / "other.bin"
        source = self.root / "c.c"
        source.write_text("int delta(void){return 7;}\nint main(void){return delta();}\n")
        subprocess.run(["gcc", "-O0", "-o", str(other), str(source)],
                       capture_output=True, timeout=300, check=False)
        if not other.is_file():
            self.skipTest("could not build the second binary")
        listing = navsession.bookmark(other, "x", db_path=self.db)
        self.assertEqual(listing["count"], 0)

    def test_same_binary_under_a_new_path_keeps_the_cursor(self) -> None:
        """Keying is by content, so a copy is the same binary."""
        navsession.goto(self.binary, "0x1040", db_path=self.db)
        copy = self.root / "copy.bin"
        shutil.copy(self.binary, copy)
        report = navsession.current(copy, db_path=self.db)
        self.assertEqual(report["address"], "0x1040")


class ResumeTest(SessionCase):
    def test_resume_summarises_everything(self) -> None:
        navsession.goto(self.binary, "0x1000", db_path=self.db)
        navsession.goto(self.binary, "0x1040", db_path=self.db)
        navsession.bookmark(self.binary, "entry", "0x1000", db_path=self.db)
        resume = navsession.where_to(self.binary, db_path=self.db)
        self.assertTrue(resume["ok"])
        self.assertTrue(resume["resumable"])
        self.assertEqual(resume["address"], "0x1040")
        self.assertEqual(len(resume["bookmarks"]), 1)
        self.assertIn("0x1040", resume["trail"])

    def test_fresh_binary_is_not_resumable(self) -> None:
        resume = navsession.where_to(self.binary, db_path=self.db)
        self.assertTrue(resume["ok"])
        self.assertFalse(resume["resumable"])
        self.assertIsNone(resume["address"])

    def test_address_beyond_the_binary_is_still_returned(self) -> None:
        """Navigation state is advisory; validating it would break resume after a rebuild."""
        navsession.goto(self.binary, "0xFFFF0000", db_path=self.db)
        resume = navsession.where_to(self.binary, db_path=self.db)
        self.assertEqual(resume["address"], "0xffff0000")
        self.assertIn("advisory", resume["note"])

    def test_annotation_count_is_reported(self) -> None:
        from xtforge.core.re import annotate
        annotate.annotate(action="comment", binary=self.binary, rva="0x1000",
                          comment="looks like init", db_path=self.db)
        resume = navsession.where_to(self.binary, db_path=self.db)
        self.assertGreaterEqual(resume["annotation_count"], 1,
                                "navigation session did not see existing annotations")


class HonestyTest(unittest.TestCase):
    def test_missing_binary_does_not_silently_succeed(self) -> None:
        """Either it raises or it reports not-ok; what it must not do is record a cursor."""
        db = Path(tempfile.mkdtemp()) / "nav.db"
        from xtforge.core.route import guard
        try:
            report = navsession.goto("/nonexistent/b.bin", "0x1000", db_path=db)
        except (OSError, ValueError, KeyError, guard.Denied):
            # `guard` rejects paths outside its allowlist before the file is even stat'ed,
            # which is a legitimate refusal. The point of the test is that no cursor is
            # recorded, not which exception type says so.
            return
        self.assertFalse(report.get("ok", True),
                         "a missing binary was recorded as a successful navigation")

    def test_advisory_nature_is_stated(self) -> None:
        db = Path(tempfile.mkdtemp()) / "nav.db"
        navsession.goto("/bin/ls", "0x1000", db_path=db)
        resume = navsession.where_to("/bin/ls", db_path=db)
        self.assertIn("advisory", resume["note"].lower())


if __name__ == "__main__":
    unittest.main()
