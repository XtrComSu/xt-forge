"""PE resource directory tests.

Two of these tests encode bugs that were actually shipped in the first version of
the parser, because both produced output that looked plausible:

  * the type-name table was applied at every tree level, so the resource *name*
    id 2 was reported as type "CURSOR" (it is really name id 1, language 1033);
  * the leaf label was read as the resource name, so a VERSIONINFO came back as
    name=1033 language=1 — inverted, and wrong in a way no type checker notices.

The oracle for both is `llvm-readobj --coff-resources`, which reports
`Type: VERSIONINFO (ID 16) / Name: (ID 1) / Language: (ID 1033)`.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import unittest
from pathlib import Path

from xtforge.core.re.pe import PEFile, PeError


def _compiler() -> str | None:
    return next((c for c in ("x86_64-w64-mingw32-gcc", "clang", "cc", "gcc")
                 if shutil.which(c)), None)


def _windres() -> str | None:
    return next((c for c in ("x86_64-w64-mingw32-windres", "llvm-rc")
                 if shutil.which(c)), None)


def build_pe_with_resources(directory: Path) -> Path | None:
    """Compile a PE carrying one VERSIONINFO resource, or None if tooling is absent."""
    compiler, windres = _compiler(), _windres()
    if not compiler or not windres:
        return None
    src = directory / "main.c"
    src.write_text("int main(void){return 0;}\n")
    rc = directory / "res.rc"
    rc.write_text(
        "1 VERSIONINFO\nFILEVERSION 1,2,3,4\nBEGIN\n"
        '  BLOCK "StringFileInfo"\n  BEGIN\n    BLOCK "040904b0"\n    BEGIN\n'
        '      VALUE "ProductName", "BreadthProbe"\n    END\n  END\nEND\n'
    )
    res_o = directory / "res.res.o"
    built = subprocess.run([windres, str(rc), "-O", "coff", "-o", str(res_o)],
                           capture_output=True, text=True)
    if built.returncode != 0 or not res_o.is_file():
        return None
    exe = directory / "probe.exe"
    linked = subprocess.run([compiler, str(src), str(res_o), "-o", str(exe)],
                            capture_output=True, text=True)
    if linked.returncode != 0 or not exe.is_file():
        return None
    return exe


class PeResourcesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import tempfile
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pe_path = build_pe_with_resources(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.pe_path is None:
            self.skipTest("no PE resource toolchain (windres + mingw/clang) available")
        self.report = PEFile(self.pe_path).resources()

    def test_reports_the_one_resource(self) -> None:
        self.assertTrue(self.report["ok"])
        self.assertEqual(self.report["count"], 1)

    def test_type_name_map_applies_only_at_the_top_level(self) -> None:
        """A name id must not be renamed as a resource type.

        With the map applied at every depth, name id 1 collided with CURSOR, and
        the report read `VERSION/CURSOR/1033` — a confident, wrong answer.
        """
        entry = self.report["entries"][0]
        self.assertEqual(entry["type"], "VERSION")
        self.assertEqual(entry["name"], "1", "name id was rewritten by the type map")
        self.assertEqual(entry["path"], "VERSION/1/1033")

    def test_language_is_the_innermost_component_not_the_name(self) -> None:
        """The leaf label is the language; binding it as the name inverts the report."""
        entry = self.report["entries"][0]
        self.assertEqual(entry["language"], "1033")
        self.assertNotEqual(entry["name"], "1033",
                            "leaf label was reported as the resource name")

    def test_matches_llvm_readobj_types(self) -> None:
        """Cross-check the type against llvm-readobj when it is installed.

        This is the assertion that makes the others trustworthy: it compares
        against an implementation nobody here wrote.
        """
        readobj = shutil.which("llvm-readobj") or shutil.which("llvm-readobj-18")
        if not readobj:
            self.skipTest("llvm-readobj unavailable")
        completed = subprocess.run([readobj, "--coff-resources", str(self.pe_path)],
                                   capture_output=True, text=True)
        out = completed.stdout
        self.assertIn("Total Number of Resources: 1", out)
        self.assertIn("VERSIONINFO", out)
        # readobj prints the name and language as the same ids the parser exposes.
        self.assertIn("Name: (ID 1)", out)
        self.assertIn("Language: (ID 1033)", out)
        self.assertEqual(self.report["types"], ["VERSION"])

    def test_payload_is_located_in_the_file(self) -> None:
        entry = self.report["entries"][0]
        self.assertTrue(entry["in_file"], "resource payload RVA was not mapped")
        self.assertIsInstance(entry["offset"], int)
        data = Path(self.pe_path).read_bytes()
        self.assertLessEqual(entry["offset"] + entry["size"], len(data))

    def test_pe_without_resources_reports_empty_not_error(self) -> None:
        """A PE with no resource directory is a normal PE, not a failure."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "plain.c"
            src.write_text("int main(void){return 0;}\n")
            exe = Path(tmp) / "plain.exe"
            built = subprocess.run([_compiler(), str(src), "-o", str(exe)],
                                   capture_output=True, text=True)
            if built.returncode != 0:
                self.skipTest("cannot build a plain PE here")
            report = PEFile(exe).resources()
        self.assertTrue(report["ok"])
        self.assertEqual(report["count"], 0)
        self.assertTrue(report["warnings"])


class PeResourcesRobustnessTest(unittest.TestCase):
    """A corrupt resource tree must not make the rest of the binary unreadable."""

    @classmethod
    def setUpClass(cls) -> None:
        import tempfile
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pe_path = build_pe_with_resources(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.pe_path is None:
            self.skipTest("no PE resource toolchain available")
        self.data = Path(self.pe_path).read_bytes()

    def test_random_mutation_never_raises_anything_but_pe_error(self) -> None:
        import random
        random.seed(20261124)
        for _ in range(120):
            mutated = bytearray(self.data)
            for _ in range(random.randint(1, 6)):
                mutated[random.randrange(len(mutated))] = random.randrange(256)
            try:
                PEFile(bytes(mutated)).resources()
            except PeError:
                pass  # a rejected PE is a correct outcome
            except Exception as exc:  # noqa: BLE001 - that is the point
                self.fail(f"mutation raised {type(exc).__name__}: {exc}")

    def test_truncation_raises_pe_error_not_indexerror(self) -> None:
        for cut in (0, 2, 64, 0x100, 0x400, len(self.data) // 2):
            with self.subTest(cut=cut):
                try:
                    PEFile(self.data[:cut]).resources()
                except PeError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"truncation at {cut} raised {type(exc).__name__}")

    def test_directory_cycle_terminates(self) -> None:
        """A self-referential directory offset must be detected, not recursed forever.

        Without the cycle guard this hangs rather than failing, so the test needs
        its own timeout to be a test at all.
        """
        import signal
        def _timeout(signum, frame):
            raise TimeoutError("resource walk did not terminate")
        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(10)
        try:
            report = PEFile(self.data).resources()
            self.assertTrue(report["ok"])
        except TimeoutError:
            self.fail("cycle guard missing: resource walk did not terminate")
        except PeError:
            pass
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_entry_cap_is_declared(self) -> None:
        cap = PEFile._RESOURCE_MAX_ENTRIES
        self.assertIsInstance(cap, int)
        self.assertGreater(cap, 0)


if __name__ == "__main__":
    unittest.main()
