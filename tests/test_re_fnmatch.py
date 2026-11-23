"""Structural function matching, checked against addresses that are known to be correct.

The fixtures are compiled on this host from one source file, so ground truth is not a guess:
`readelf` gives the address of every function in the unstripped build, and a match is correct
or wrong by comparing against those addresses. That matters here more than elsewhere — a
matching heuristic produces a plausible-looking table whether or not it is right, so the only
useful test is one that can name a wrong answer.

The four cases that matter:

  * **same source, two compilers** — `gcc -O2` vs `clang -O2`. Names survive, so this mostly
    checks that structure does not *break* matches that names would have found.
  * **same source, two optimisation levels** — `-O2` vs `-O3`.
  * **across a `strip`** — names gone entirely, addresses recovered from eh_frame/gap-scan.
    This is the case `re diff` cannot do at all: it reported 18% similarity and called
    `.text` an added function.
  * **a function whose shape genuinely diverged** — `compute_sum` at `-O3` is 77 vectorised
    SSE instructions against 17 scalar ones at `-O2`. The matcher must leave it unmatched,
    not pair it with something else.

The last case is the one that caught a real bug. With the guards absent, a low threshold let
`compute_sum` match `0x1110` — a different function — at score 0.33. The score alone was not
enough to prevent it, so there is now an absolute structural check that no threshold can
override.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import fnmatch

SOURCE = """
#include <stdio.h>
int compute_sum(int n){int s=0;for(int i=0;i<n;i++)s+=i*i;return s;}
int classify(int x){if(x<0)return -1;if(x==0)return 0;return 1;}
double scale(double v,double f){return v*f+1.5;}
int main(void){printf("%d %d %f\\n",compute_sum(10),classify(3),scale(2.0,3.0));return 0;}
"""

EXPECTED_FUNCTIONS = {"compute_sum", "classify", "scale", "main"}


def have(*tools: str) -> bool:
    return all(shutil.which(tool) for tool in tools)


def build(directory: Path, compiler: str, level: str, name: str) -> Path | None:
    source = directory / "v.c"
    if not source.exists():
        source.write_text(SOURCE)
    target = directory / name
    result = subprocess.run([compiler, level, "-o", str(target), str(source)],
                            capture_output=True, timeout=300, check=False)
    return target if result.returncode == 0 and target.is_file() else None


def function_addresses(binary: Path) -> dict[str, int]:
    """Ground truth: FUNC symbols and their addresses, straight from readelf."""
    result = subprocess.run(["readelf", "-sW", str(binary)],
                            capture_output=True, text=True, timeout=120, check=False)
    found: dict[str, int] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] != "FUNC":
            continue
        name = parts[7].split("@")[0]
        try:
            address = int(parts[1], 16)
        except ValueError:
            continue
        if address and name in EXPECTED_FUNCTIONS:
            found[name] = address
    return found


class FixtureCase(unittest.TestCase):
    """Compiles the shared fixture once per class."""

    @classmethod
    def setUpClass(cls) -> None:
        if not have("gcc"):
            raise unittest.SkipTest("gcc is not available")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.gcc_o2 = build(cls.root, "gcc", "-O2", "gcc_o2.bin")
        cls.gcc_o3 = build(cls.root, "gcc", "-O3", "gcc_o3.bin")
        if cls.gcc_o2 is None or cls.gcc_o3 is None:
            raise unittest.SkipTest("the fixture did not compile")

        # Stripped copy: no symbol table at all.
        cls.stripped = cls.root / "gcc_o3_stripped.bin"
        shutil.copy(cls.gcc_o3, cls.stripped)
        subprocess.run(["objcopy", "--strip-all", str(cls.stripped)],
                       capture_output=True, timeout=120, check=False)
        if cls.stripped.stat().st_size == 0:
            cls.stripped = None

        cls.clang = (build(cls.root, "clang", "-O2", "clang_o2.bin")
                     if have("clang") else None)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()


class SameCompilerTest(FixtureCase):
    def test_self_match_is_perfect(self) -> None:
        report = fnmatch.compare_functions(self.gcc_o2, self.gcc_o2)
        self.assertTrue(report["ok"], report.get("error"))
        for match in report["matches"]:
            self.assertEqual(match["score"], 1.0,
                             f"{match['function_a']} did not match itself perfectly")
            self.assertFalse(match["renamed"])

    def test_optimisation_levels_match_by_name(self) -> None:
        report = fnmatch.compare_functions(self.gcc_o2, self.gcc_o3)
        matched = {m["function_a"] for m in report["matches"] if not m["renamed"]}
        self.assertTrue(EXPECTED_FUNCTIONS & matched,
                        f"no expected function matched: {matched}")

    def test_evidence_is_reported_for_every_match(self) -> None:
        report = fnmatch.compare_functions(self.gcc_o2, self.gcc_o3)
        for match in report["matches"]:
            evidence = match["evidence"]
            for key in ("block_score", "edge_score", "histogram_score", "size_ratio"):
                self.assertIn(key, evidence)
            self.assertEqual(len(evidence["blocks"]), 2)
            self.assertEqual(len(evidence["instructions"]), 2)


class CrossCompilerTest(FixtureCase):
    def setUp(self) -> None:
        if self.clang is None:
            self.skipTest("clang is not available")

    def test_every_function_is_matched(self) -> None:
        report = fnmatch.compare_functions(self.gcc_o2, self.clang)
        matched = {m["function_a"] for m in report["matches"]}
        missing = EXPECTED_FUNCTIONS - matched
        self.assertFalse(missing, f"unmatched across compilers: {missing}")

    def test_matches_are_not_renamed(self) -> None:
        """Both sides keep their names, so every match should pair equal names."""
        report = fnmatch.compare_functions(self.gcc_o2, self.clang)
        for match in report["matches"]:
            if match["function_a"] in EXPECTED_FUNCTIONS:
                self.assertEqual(match["function_a"], match["function_b"])


class StrippedTest(FixtureCase):
    """The case `re diff` cannot handle: one side has no names at all."""

    def setUp(self) -> None:
        if self.stripped is None:
            self.skipTest("objcopy did not produce a stripped binary")

    def test_mode_reports_recovery(self) -> None:
        report = fnmatch.compare_functions(self.gcc_o2, self.stripped)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["mode_a"], "symbols")
        self.assertEqual(report["mode_b"], "recovered")

    def test_matches_land_on_the_correct_addresses(self) -> None:
        """Ground truth from readelf on the unstripped build; the strips are identical code."""
        truth = function_addresses(self.gcc_o3)
        self.assertTrue(truth, "readelf found no functions to check against")
        report = fnmatch.compare_functions(self.gcc_o2, self.stripped)
        matched = {m["function_a"]: m["function_b"] for m in report["matches"]}
        checked = 0
        for name, address in truth.items():
            if name not in matched:
                continue
            checked += 1
            self.assertEqual(int(matched[name], 16), address,
                             f"{name} matched the wrong address")
        self.assertGreaterEqual(checked, 3,
                                f"too few verifiable matches to be meaningful: {matched}")

    def test_recovered_shapes_have_matching_extents(self) -> None:
        """A clipped extent should give the same instruction count on both sides."""
        report = fnmatch.compare_functions(self.gcc_o2, self.stripped)
        for match in report["matches"]:
            counts = match["evidence"]["instructions"]
            if match["function_a"] in ("classify", "scale"):
                self.assertEqual(counts[0], counts[1],
                                 f"{match['function_a']} extent differs: {counts}")


class DivergedShapeTest(FixtureCase):
    """`compute_sum` is vectorised at -O3, so its shape genuinely differs."""

    def test_diverged_function_is_not_force_matched(self) -> None:
        truth = function_addresses(self.gcc_o3)
        compute = truth.get("compute_sum")
        if compute is None:
            self.skipTest("compute_sum not found in the fixture")
        report = fnmatch.compare_functions(self.gcc_o2, self.stripped, threshold=0.2)
        for match in report["matches"]:
            if match["function_a"] == "compute_sum":
                self.fail(f"compute_sum was matched to {match['function_b']} "
                          f"at score {match['score']} despite a diverged shape")

    def test_structural_guard_rejects_at_any_threshold(self) -> None:
        """Lowering the threshold must not create a pairing the shape forbids."""
        low = fnmatch.compare_functions(self.gcc_o2, self.stripped, threshold=0.05)
        names = {m["function_a"] for m in low["matches"]}
        self.assertNotIn("compute_sum", names)

    def test_guard_explains_itself(self) -> None:
        """A rejection must name which structural property failed, not just say "no"."""
        report = fnmatch.compare_functions(self.gcc_o2, self.stripped, threshold=0.2)
        self.assertGreater(report["rejected_count"], 0)
        for entry in report["rejected_pairs"]:
            self.assertTrue(entry["reason"])
            self.assertTrue(
                any(word in entry["reason"] for word in
                    ("block count", "size", "instruction mix")),
                f"unexplained rejection: {entry['reason']}")


class GuardUnitTest(unittest.TestCase):
    def _shape(self, **overrides: object) -> dict:
        base = {"blocks": 4, "edges": 4, "instructions": 20,
                "histogram": {"mov": 0.5, "arith": 0.5}, "calls": set(), "loops": 0}
        base.update(overrides)
        return base

    def test_identical_shapes_are_plausible(self) -> None:
        self.assertIsNone(fnmatch._structurally_implausible(
            self._shape(), self._shape()))

    def test_block_ratio_rejects(self) -> None:
        reason = fnmatch._structurally_implausible(
            self._shape(blocks=1), self._shape(blocks=8))
        self.assertIsNotNone(reason)
        self.assertIn("block count", reason)

    def test_size_ratio_rejects(self) -> None:
        reason = fnmatch._structurally_implausible(
            self._shape(instructions=5), self._shape(instructions=200))
        self.assertIsNotNone(reason)
        self.assertIn("size", reason)

    def test_incompatible_histograms_reject(self) -> None:
        reason = fnmatch._structurally_implausible(
            self._shape(histogram={"mov": 1.0}),
            self._shape(histogram={"call": 1.0}))
        self.assertIsNotNone(reason)
        self.assertIn("instruction mix", reason)

    def test_size_ratio_is_load_bearing(self) -> None:
        """Two functions with identical *proportions* but 40x the size must not score high.

        Without the sqrt(size_ratio) term this pair scores 1.0 — the histogram and block
        shape agree perfectly — so the term is the only thing separating a 10-instruction
        thunk from a 400-instruction function with the same instruction mix.
        """
        small = {"blocks": 2, "edges": 2, "instructions": 10,
                 "histogram": {"mov": 0.5, "arith": 0.5}, "calls": set(), "loops": 0}
        large = {"blocks": 2, "edges": 2, "instructions": 400,
                 "histogram": {"mov": 0.5, "arith": 0.5}, "calls": set(), "loops": 0}
        score, evidence = fnmatch._similarity(small, large)
        self.assertLess(evidence["size_ratio"], 0.1)
        self.assertLess(score, 0.3,
                        "a 40x size difference barely reduced the score")

    def test_moderate_vectorisation_is_allowed(self) -> None:
        """-O3 turning scalar into SSE is a 4x size change, which must stay matchable."""
        self.assertIsNone(fnmatch._structurally_implausible(
            self._shape(instructions=17),
            self._shape(instructions=74, histogram={"mov": 0.5, "arith": 0.5})))


class HonestyTest(unittest.TestCase):
    def test_missing_file_is_an_error(self) -> None:
        report = fnmatch.compare_functions("/nonexistent/a.bin", "/nonexistent/b.bin")
        self.assertFalse(report["ok"])

    def test_non_binary_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "x.bin"
            blob.write_bytes(b"\x00" * 512)
            report = fnmatch.compare_functions(blob, blob)
        self.assertFalse(report["ok"])

    def test_limits_are_stated(self) -> None:
        report = fnmatch.compare_functions("/bin/ls", "/bin/ls")
        if not report.get("ok"):
            self.skipTest("/bin/ls could not be fingerprinted here")
        self.assertIn("note", report)
        self.assertIn("heuristic", report["note"].lower())

    def test_unmatched_are_reported_not_hidden(self) -> None:
        report = fnmatch.compare_functions("/bin/ls", "/bin/cat")
        if not report.get("ok"):
            self.skipTest("fingerprinting unavailable")
        self.assertIn("unmatched_a", report)
        self.assertIn("unmatched_b", report)


if __name__ == "__main__":
    unittest.main()


class ExtentAssumptionTest(FixtureCase):
    """The matcher relies on the hub's flow walk stopping at a function boundary.

    Clipping at the next recovered entry point was tried and removed: it changed nothing,
    because the walk already stops correctly. That is an assumption about the hub, so it is
    asserted here rather than trusted — a future hub build that follows fall-through into the
    next function would silently corrupt every recovered fingerprint.
    """

    def setUp(self) -> None:
        if self.stripped is None:
            self.skipTest("no stripped fixture")

    def test_recovered_extents_match_the_next_entry_point(self) -> None:
        from xtforge.core.re import sysimage
        report = sysimage.functions(str(self.stripped), limit=2000)
        entry_points = sorted(
            function["address"]
            for image in report.get("images") or []
            for function in image.get("functions") or []
            if isinstance(function.get("address"), int))
        if not entry_points:
            self.skipTest("recovery returned no entry points")

        overruns = []
        for index, address in enumerate(entry_points):
            disassembly = sysimage.disassemble(str(self.stripped), target=hex(address),
                                               count=400, flow=True)
            instructions = disassembly.get("instructions") or []
            if not instructions:
                continue
            highest = max(i["address"] for i in instructions
                          if isinstance(i.get("address"), int))
            boundary = entry_points[index + 1] if index + 1 < len(entry_points) else None
            if boundary is not None and highest >= boundary:
                overruns.append(f"{hex(address)} ended at {hex(highest)} "
                                f"past boundary {hex(boundary)}")
        self.assertFalse(overruns, f"flow walk overran: {overruns}")
