"""Reconstruction coverage scoring, verified against `nm` and a real ledger.

The value of a coverage number is entirely in whether you can check it. So every claim here
is cross-checked against an independent tool:

  * the **source parse** is checked against the functions actually written in the fixture — a
    parser that misses a definition reports inflated coverage, so the expected set is spelled
    out by hand;
  * **presence in the binary** is checked against `nm`;
  * the **ledger states** come from recording, resolving and waiving real entries through
    `re unknowns`, not from a stub dict.

The distinction the module exists to make is between three states that a single percentage
would blur:

    covered              in the binary AND recorded in the ledger
    present_unrecorded   in the binary, never written down
    absent_expected      `static` in the source, missing from the binary (inlined away)

`absent_expected` is excluded from the denominator. A `static` helper that the optimiser
inlined is not unfinished work, and counting it as a gap is how coverage dashboards become
noise.

One bug is recorded here because it was invisible: the ledger reader guessed at the key name
(`unknowns` instead of the documented `entries`) and silently returned an empty dict. Every
function then reported as `present_unrecorded` — a 0% coverage score against a binary whose
work was fully recorded. `test_resolved_topics_count_as_covered` fails if the key is wrong
again.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import obligations, reccoverage

LIB_C = """
int alpha_init(void){return 1;}
int beta_process(int x){return x*2;}
int gamma_finish(void){return 3;}
void delta_helper(void){}
int epsilon_exported(int y){return y+1;}
"""

UTIL_C = """
static int internal_counter(void){return 5;}
int zeta_util(char* s){ return s ? 1 : 0; }
int eta_unused(void){return 99;}
"""

# Everything the shallow parser is expected to find, spelled out so a regression shows up as a
# name appearing or disappearing rather than as a shifted percentage.
EXPECTED_SOURCE = {"alpha_init", "beta_process", "gamma_finish", "delta_helper",
                   "epsilon_exported", "internal_counter", "zeta_util", "eta_unused"}


def nm_defined(binary: Path) -> set[str]:
    """Ground truth for presence: every defined name `nm` reports."""
    result = subprocess.run(["nm", "--defined-only", str(binary)],
                            capture_output=True, text=True, timeout=120, check=False)
    names: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            names.add(parts[2].split("@")[0].lstrip("_"))
    return names


class CoverageCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not (shutil.which("gcc") and shutil.which("nm")):
            raise unittest.SkipTest("gcc and nm are required")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.src = cls.root / "src"
        cls.src.mkdir()
        (cls.src / "lib.c").write_text(LIB_C)
        (cls.src / "util.c").write_text(UTIL_C)
        cls.db = cls.root / "ledger.db"

        cls.binary = cls.root / "librec.so"
        result = subprocess.run(
            ["gcc", "-shared", "-fPIC", "-o", str(cls.binary),
             str(cls.src / "lib.c"), str(cls.src / "util.c")],
            capture_output=True, timeout=300, check=False)
        if result.returncode != 0:
            raise unittest.SkipTest(f"fixture did not compile: {result.stderr.decode()[:200]}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()


class SourceParseTest(CoverageCase):
    def test_every_definition_is_found(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        self.assertTrue(report["ok"], report.get("error"))
        found = {row["name"] for row in report["rows"]}
        self.assertEqual(found, EXPECTED_SOURCE,
                         f"missing={EXPECTED_SOURCE - found} extra={found - EXPECTED_SOURCE}")

    def test_static_linkage_is_recorded(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        rows = {row["name"]: row for row in report["rows"]}
        self.assertEqual(rows["internal_counter"]["linkage"], "static")
        self.assertEqual(rows["alpha_init"]["linkage"], "external")

    def test_control_flow_keywords_are_not_functions(self) -> None:
        """`if (x) {` has the shape of a definition and must not be counted."""
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        found = {row["name"] for row in report["rows"]}
        for keyword in ("if", "for", "while", "switch", "return"):
            self.assertNotIn(keyword, found)

    def test_comments_do_not_create_functions(self) -> None:
        """The definition regex is anchored to a line start, so a single-line comment is
        already safe. The case that actually needs stripping is a *multi-line* block comment
        where the function begins a line inside it — without stripping, `commented_out` is
        reported as a real function and inflates the source count.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "x.c").write_text(
                "/*\n"
                "int commented_out(void) {\n"
                "  return 1;\n"
                "}\n"
                "*/\n"
                "// int also_commented(void) { return 2; }\n"
                "int real_function(void){return 3;}\n")
            binary = root / "x.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(binary),
                            str(source / "x.c")],
                           capture_output=True, timeout=300, check=False)
            if not binary.is_file():
                self.skipTest("could not build the comment fixture")
            report = reccoverage.evaluate_coverage(binary, source)
        names = {row["name"] for row in report["rows"]}
        self.assertIn("real_function", names)
        self.assertNotIn("commented_out", names,
                         "a function inside a block comment was parsed as real")
        self.assertNotIn("also_commented", names)

    def test_string_literals_do_not_create_functions(self) -> None:
        """A `{` inside a string must not be read as opening a function body."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "x.c").write_text(
                'const char *doc = "not_a_function(void) {";\n'
                "int real_function(void){return 3;}\n")
            binary = root / "x.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(binary),
                            str(source / "x.c")],
                           capture_output=True, timeout=300, check=False)
            if not binary.is_file():
                self.skipTest("could not build the fixture")
            report = reccoverage.evaluate_coverage(binary, source)
        names = {row["name"] for row in report["rows"]}
        self.assertNotIn("not_a_function", names)


class PresenceTest(CoverageCase):
    def test_presence_agrees_with_nm(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        truth = nm_defined(self.binary)
        for row in report["rows"]:
            if row["name"] in truth:
                self.assertTrue(row["in_binary"],
                                f"{row['name']} is in nm but not detected as present")

    def test_unreferenced_static_survives_at_O0(self) -> None:
        """Without optimisation gcc emits an unused `static` function, so it IS present.

        The first version of this test asserted the opposite and failed. The lesson is worth
        keeping: whether a static function reaches the binary is a property of the *build*,
        not of the source, so `absent_expected` has to be judged against what `nm` actually
        reports rather than against an assumption about linkage.
        """
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        truth = nm_defined(self.binary)
        rows = {row["name"]: row for row in report["rows"]}
        if "internal_counter" in truth:
            self.assertTrue(rows["internal_counter"]["in_binary"])
            self.assertEqual(rows["internal_counter"]["status"], "present_unrecorded")
        else:
            self.assertEqual(rows["internal_counter"]["status"], "absent_expected")

    def test_absent_expected_is_excluded_from_the_denominator(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        expected = [r["name"] for r in report["rows"] if r["status"] == "absent_expected"]
        for name in expected:
            self.assertNotIn(name, report["absent"],
                             f"{name} is both expected-absent and a real gap")
        self.assertEqual(report["required"],
                         report["counts"]["covered"]
                         + report["counts"]["present_unrecorded"]
                         + report["counts"]["absent"])

    def test_inlining_is_reported_not_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "s.c").write_text(
                "static int inlined_away(void){return 7;}\n"
                "int uses_static(int x){return inlined_away()+x;}\n")
            binary = root / "s.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-o", str(binary),
                            str(source / "s.c")],
                           capture_output=True, timeout=300, check=False)
            if not binary.is_file():
                self.skipTest("could not build the inlining fixture")
            report = reccoverage.evaluate_coverage(binary, source)
        self.assertIn("inlined_away", report["absent_expected"])


class LedgerTest(CoverageCase):
    def test_resolved_topics_count_as_covered(self) -> None:
        """Guards the bug where the ledger was read under the wrong key and always empty."""
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "ledger.db"
            for topic in ("alpha_init", "beta_process", "gamma_finish"):
                obligations.record_unknown(self.binary, topic, "first pass", db_path=db)
            obligations.resolve_unknown(self.binary, "alpha_init", "identified", db_path=db)
            obligations.waive_unknown(self.binary, "gamma_finish", "not security", db_path=db)
            report = reccoverage.evaluate_coverage(self.binary, self.src, db_path=db)
        self.assertEqual(report["counts"]["covered"], 3,
                         "resolved and waived topics were not counted as covered")
        self.assertGreater(report["coverage_pct"], 0.0)
        self.assertNotIn("alpha_init", report["present_unrecorded"])

    def test_open_topic_counts_as_covered(self) -> None:
        """Having recorded the question is what "accounted for" means, open or not."""
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "ledger.db"
            obligations.record_unknown(self.binary, "beta_process", "still open", db_path=db)
            report = reccoverage.evaluate_coverage(self.binary, self.src, db_path=db)
        rows = {row["name"]: row for row in report["rows"]}
        self.assertEqual(rows["beta_process"]["status"], "covered")
        self.assertEqual(rows["beta_process"]["ledger_state"], "open")

    def test_unmentioned_lists_everything_not_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "ledger.db"
            obligations.record_unknown(self.binary, "alpha_init", "only this", db_path=db)
            report = reccoverage.evaluate_coverage(self.binary, self.src, db_path=db)
        self.assertIn("beta_process", report["unmentioned_in_ledger"])
        self.assertNotIn("alpha_init", report["unmentioned_in_ledger"])

    def test_present_and_coverage_differ_when_work_is_undocumented(self) -> None:
        """The gap between the two percentages is the whole point of the module."""
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "ledger.db"
            obligations.record_unknown(self.binary, "alpha_init", "one of many", db_path=db)
            report = reccoverage.evaluate_coverage(self.binary, self.src, db_path=db)
        self.assertEqual(report["present_pct"], 100.0)
        self.assertLess(report["coverage_pct"], report["present_pct"])
        self.assertTrue(report["present_unrecorded"])


class HonestyTest(CoverageCase):
    def test_missing_binary_is_an_error(self) -> None:
        report = reccoverage.evaluate_coverage("/nonexistent/lib.so", self.src)
        self.assertFalse(report["ok"])

    def test_missing_source_root_is_an_error(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, "/nonexistent/src")
        self.assertFalse(report["ok"])

    def test_no_functions_found_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            (empty / "notes.txt").write_text("nothing here\n")
            report = reccoverage.evaluate_coverage(self.binary, empty)
        self.assertFalse(report["ok"])
        self.assertIn("no function definitions", report["error"])

    def test_limits_are_stated(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        self.assertIn("inlined", report["note"].lower())

    def test_report_is_bounded(self) -> None:
        report = reccoverage.evaluate_coverage(self.binary, self.src)
        self.assertLessEqual(len(report["rows"]), 400)
        self.assertLessEqual(len(report["present_unrecorded"]), 200)


if __name__ == "__main__":
    unittest.main()
