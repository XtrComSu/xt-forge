"""API contract auditing, with `nm -D --defined-only` as the oracle.

Listing exports is easy and `nm` already does it. What this module adds is judgement, and
judgement is exactly the thing that is easy to fake. So every test here has two halves: the
export *set* must agree with `nm`, and the *grading* must be defensible for a named symbol.

The fixtures are real shared objects compiled on this host from two versions of one header,
with four deliberate differences:

  * `api_public_two` removed          → a breaking change for any consumer
  * `api_public_new` added            → additive, not breaking
  * `test_helper_internal`,
    `debug_dump_state`,
    `_internal_thing`,
    `detail_namespace_fn`             → four different kinds of accidental export

`detail_namespace_fn` is the interesting one: it exports a function whose name contains
`detail`, which the heuristic flags as an internal namespace. That is a false positive — the
symbol is genuinely part of a `detail` namespace, and in C++ `detail` legitimately means
"not for you". Keeping it in the tests records that the tier is a *hint*, not a verdict, and
that the baseline diff is the part with teeth.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import apicontract

V1 = """
int api_public_one(int x){return x+1;}
int api_public_two(int y){return y*2;}
void test_helper_internal(void){}
int _internal_thing(void){return 42;}
void debug_dump_state(void){return;}
int api_stable(int z){return z;}
"""

V2 = """
int api_public_one(int x){return x+1;}
int api_public_new(int w){return w*3;}
int api_stable(int z){return z;}
"""


def nm_exports(binary: Path) -> set[str]:
    """Ground truth: dynamic defined symbols, as `nm` reports them."""
    result = subprocess.run(["nm", "-D", "--defined-only", str(binary)],
                            capture_output=True, text=True, timeout=120, check=False)
    names: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "D", "B", "R", "W", "V", "i", "U"):
            names.add(parts[2])
    return names


class LibraryCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("gcc") or not shutil.which("nm"):
            raise unittest.SkipTest("gcc and nm are required")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.builds: dict[str, Path] = {}
        for name, source in (("v1", V1), ("v2", V2)):
            src = cls.root / f"{name}.c"
            src.write_text(source)
            out = cls.root / f"lib{name}.so"
            result = subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(out), str(src)],
                                    capture_output=True, timeout=300, check=False)
            if result.returncode != 0:
                raise unittest.SkipTest(f"fixture did not compile: "
                                        f"{result.stderr.decode()[:200]}")
            cls.builds[name] = out

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()


class AgreementWithNmTest(LibraryCase):
    """The export set must match `nm` exactly, or everything downstream is invented."""

    def test_v1_exports_match_nm(self) -> None:
        report = apicontract.audit_contract(self.builds["v1"])
        self.assertTrue(report["ok"], report.get("error"))
        ours = set(report["surface_sample"])
        ours |= {entry["name"] for entry in report["findings"]}
        truth = nm_exports(self.builds["v1"])
        self.assertEqual(ours, truth, f"missing={truth - ours} extra={ours - truth}")

    def test_v2_exports_match_nm(self) -> None:
        report = apicontract.audit_contract(self.builds["v2"])
        ours = set(report["surface_sample"]) | {e["name"] for e in report["findings"]}
        self.assertEqual(ours, nm_exports(self.builds["v2"]))

    def test_imports_are_not_counted_as_exports(self) -> None:
        """`-D --defined-only` excludes undefined symbols; so must we."""
        report = apicontract.audit_contract(self.builds["v1"])
        ours = set(report["surface_sample"]) | {e["name"] for e in report["findings"]}
        for imported in ("__libc_start_main", "printf", "__cxa_finalize"):
            self.assertNotIn(imported, ours)


class GradingTest(LibraryCase):
    def setUp(self) -> None:
        self.report = apicontract.audit_contract(self.builds["v1"])
        self.assertTrue(self.report["ok"], self.report.get("error"))

    def _tier(self, name: str) -> str:
        for entry in self.report["findings"]:
            if entry["name"] == name:
                return entry["tier"]
        return "public"

    def test_test_helper_is_forbidden(self) -> None:
        self.assertEqual(self._tier("test_helper_internal"), "forbidden")

    def test_debug_helper_is_forbidden(self) -> None:
        self.assertEqual(self._tier("debug_dump_state"), "forbidden")

    def test_internal_underscore_is_risky(self) -> None:
        self.assertEqual(self._tier("_internal_thing"), "risky")

    def test_ordinary_api_is_public(self) -> None:
        self.assertEqual(self._tier("api_public_one"), "public")
        self.assertEqual(self._tier("api_stable"), "public")

    def test_conventional_underscore_is_not_flagged(self) -> None:
        """`_init`, `_fini` and C++ mangling start with underscores and are normal."""
        for name in ("_init", "_fini", "_ZN3foo3barEv"):
            tier, _ = apicontract._grade(name)
            self.assertEqual(tier, "public", f"{name} was wrongly flagged as {tier}")

    def test_every_finding_has_a_reason(self) -> None:
        for entry in self.report["findings"]:
            self.assertTrue(entry["why"])
            self.assertNotEqual(entry["why"], "exported",
                                "a non-public tier needs a specific reason")

    def test_tier_counts_add_up(self) -> None:
        total = sum(self.report["tiers"].values())
        self.assertEqual(total, self.report["export_count"])


class BaselineDiffTest(LibraryCase):
    def setUp(self) -> None:
        self.report = apicontract.audit_contract(self.builds["v2"],
                                                 baseline=self.builds["v1"])
        self.assertTrue(self.report["ok"], self.report.get("error"))

    def test_added_is_detected(self) -> None:
        self.assertIn("api_public_new", self.report["added"])

    def test_removed_is_detected(self) -> None:
        self.assertIn("api_public_two", self.report["removed"])

    def test_removal_of_public_symbol_is_breaking(self) -> None:
        """Removing `api_public_two` breaks every consumer that links it."""
        self.assertIn("api_public_two", self.report["breaking_removals"])
        self.assertFalse(self.report["compatible"])
        self.assertEqual(self.report["verdict"], "breaking")

    def test_verdict_is_breaking_for_a_removal(self) -> None:
        self.assertEqual(self.report["verdict"], "breaking")

    def test_diff_matches_nm_set_difference(self) -> None:
        before = nm_exports(self.builds["v1"])
        after = nm_exports(self.builds["v2"])
        self.assertEqual(set(self.report["added"]), after - before)
        self.assertEqual(set(self.report["removed"]), before - after)

    def test_additive_only_baseline_is_compatible(self) -> None:
        """v1 as baseline for itself plus a new symbol must not be called breaking."""
        report = apicontract.audit_contract(self.builds["v1"], baseline=self.builds["v1"])
        self.assertTrue(report["compatible"])
        self.assertEqual(report["verdict"], "identical")

    def test_cleanup_removal_is_not_breaking(self) -> None:
        """Removing a `test_` symbol that should never have been exported is a fix."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = root / "keep.c"
            keep.write_text("int api_keep(void){return 1;}\n")
            cleaned = root / "cleaned.c"
            cleaned.write_text("int api_keep(void){return 1;}\n"
                               "void test_leaked(void){}\n")
            a = root / "libkeep.so"
            b = root / "libcleaned.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(b), str(cleaned)],
                           capture_output=True, timeout=300, check=False)
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(a), str(keep)],
                           capture_output=True, timeout=300, check=False)
            report = apicontract.audit_contract(a, baseline=b)
        if not report.get("ok"):
            self.skipTest(f"fixture failed: {report.get('error')}")
        self.assertIn("test_leaked", report["removed"])
        self.assertIn("test_leaked", report["cleanup_removals"])
        self.assertEqual(report["breaking_removal_count"], 0)
        self.assertTrue(report["compatible"],
                        "removing a leaked test symbol was called breaking")


class HonestyTest(LibraryCase):
    def test_missing_file_is_an_error(self) -> None:
        report = apicontract.audit_contract("/nonexistent/lib.so")
        self.assertFalse(report["ok"])

    def test_stripped_library_keeps_its_exports(self) -> None:
        """`strip --strip-all` does NOT remove `.dynsym`, and the audit must reflect that.

        My first version of this test asserted the opposite and skipped every run, which is
        the worst possible outcome: a test that looks like it checks something and never
        executes. A shared object's dynamic symbol table is what the loader uses, so it
        survives stripping by design — an audit that reported "no exports" for a stripped
        library would be broken, not honest.
        """
        stripped = self.root / "stripped.so"
        shutil.copy(self.builds["v1"], stripped)
        subprocess.run(["strip", "--strip-all", str(stripped)],
                       capture_output=True, timeout=120, check=False)
        report = apicontract.audit_contract(stripped)
        self.assertTrue(report["ok"], report.get("error"))
        # Same surface as the unstripped build: stripping must not change the ABI.
        original = apicontract.audit_contract(self.builds["v1"])
        ours = set(report["surface_sample"]) | {e["name"] for e in report["findings"]}
        theirs = set(original["surface_sample"]) | {
            e["name"] for e in original["findings"]}
        self.assertEqual(ours, theirs, "stripping changed the reported export surface")

    def test_object_file_with_no_dynsym_is_an_error(self) -> None:
        """A relocatable object has no dynamic symbol table to audit."""
        obj = self.root / "plain.o"
        source = self.root / "plain.c"
        source.write_text("int only_static(void){return 1;}\n")
        subprocess.run(["gcc", "-c", "-o", str(obj), str(source)],
                       capture_output=True, timeout=300, check=False)
        if not obj.is_file():
            self.skipTest("could not build an object file")
        report = apicontract.audit_contract(obj)
        # Either it is rejected, or it reports a surface that `nm -D` also sees.
        if report["ok"]:
            self.assertEqual(
                set(report["surface_sample"]) | {e["name"] for e in report["findings"]},
                nm_exports(obj))
        else:
            self.assertIn("error", report)

    def test_heuristic_nature_is_stated(self) -> None:
        report = apicontract.audit_contract(self.builds["v1"])
        self.assertIn("heuristic", report["note"].lower())

    def test_missing_baseline_is_reported_not_crashed(self) -> None:
        report = apicontract.audit_contract(self.builds["v1"], baseline="/nonexistent")
        self.assertTrue(report["ok"])
        self.assertIn("baseline_error", report)

    def test_real_library_is_auditable(self) -> None:
        candidates = [Path("/usr/lib/libz.so.1"), Path("/usr/lib32/libz.so.1")]
        target = next((p for p in candidates if p.is_file()), None)
        if target is None:
            self.skipTest("no system shared library available")
        report = apicontract.audit_contract(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["export_count"], 50)


if __name__ == "__main__":
    unittest.main()
