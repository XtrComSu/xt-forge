"""Tests for the small self-describing format readers (plist, pyc, desktop, Go, Rust).

These use real files from the host where possible, because the fixtures for these
formats are ubiquitous in the right places: a .desktop entry lives in
/usr/share/applications, a .pyc in __pycache__, a plist in a CMake template, and our
own Go hub binary carries a buildinfo record that `go version -m` can independently
confirm.

Three bugs shipped in the first version, all now tests that fail when restored:

  * `inspect()` sniffed a 4096-byte prefix and then handed that truncated slice to
    the readers, so every real file failed its own size limit — the detector worked
    and the parsers never ran;
  * the .pyc version arithmetic was `low_byte - 10`, reporting 3.14's files as
    "Python 3.33";
  * the Go module-info blob was read as a second string, so the module path, every
    dependency and the VCS revision were all missing from a binary that has them.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import formats

ROOT = Path(__file__).resolve().parents[1]
GO_HUB = ROOT / "native" / "xtforge-go" / "xtforge-hub"


def _first(pattern: str, *roots: str) -> Path | None:
    for root in roots:
        base = Path(root)
        if base.is_dir():
            for candidate in sorted(base.rglob(pattern)):
                if candidate.is_file():
                    return candidate
    return None


class FormatDetectionTest(unittest.TestCase):
    """The detector must pass the whole file through, not its own sniff slice."""

    def test_pyc_is_detected_and_parsed(self) -> None:
        pyc = _first("*.pyc", "/usr/lib/python3.14", "/usr/lib/python3")
        if pyc is None:
            self.skipTest("no .pyc on this host")
        report = formats.inspect(pyc)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIsNotNone(report.get("python_version_guess"))

    def test_desktop_is_detected_and_parsed(self) -> None:
        desktop = _first("*.desktop", "/usr/share/applications")
        if desktop is None:
            self.skipTest("no .desktop entries on this host")
        report = formats.inspect(desktop)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["type"], "Application")

    def test_plist_is_detected_and_parsed(self) -> None:
        plist = _first("*.plist", "/usr/share")
        if plist is None:
            self.skipTest("no plist on this host")
        report = formats.inspect(plist)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn(report["format_detected"], ("xml", "binary", "openstep"))

    def test_large_file_is_not_rejected_by_the_sniffer(self) -> None:
        """The detector reads a prefix; it must not pass that prefix to the reader.

        This is the bug that made every real .pyc, .desktop and Go binary fail with
        "file too large: N bytes (max 4096)" — the size check compared the truncated
        sniff buffer against the reader's own, larger, limit.
        """
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big.desktop"
            big.write_text("[Desktop Entry]\nType=Application\nName=Big\n"
                           "Exec=/bin/true\n"
                           + "# padding\n" * 5000)
            self.assertGreater(big.stat().st_size, 4096)
            report = formats.inspect(big)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["name"], "Big")


class PYCReaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pyc = _first("*.pyc", "/usr/lib/python3.14", "/usr/lib/python3")
        if self.pyc is None:
            self.skipTest("no .pyc on this host")
        self.report = formats.inspect_pyc(self.pyc)

    def test_header_fields(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["magic"], "0x0e2b")
        self.assertEqual(self.report["bytecode_version"], 43)
        self.assertEqual(self.report["header_size"], 16)

    def test_version_mapping_is_minus_29_not_minus_10(self) -> None:
        """Bytecode version 43 is Python 3.14, because minor = low_byte - 29.

        The wrong constant (minus 10) reports 3.33, a version that never existed —
        plausible-looking and completely wrong.
        """
        self.assertEqual(self.report["python_version_guess"], "3.14")

    def test_matches_the_host_interpreter_when_versions_agree(self) -> None:
        import importlib.util
        host_magic = importlib.util.MAGIC_NUMBER[:2]
        if host_magic != bytes([0x2B, 0x0E]):
            self.skipTest(f"host magic {host_magic.hex()} differs from the fixture")
        self.assertEqual(self.report["python_version_guess"],
                         f"{sys.version_info[0]}.{sys.version_info[1]}")

    def test_hash_based_invalidation_is_reported(self) -> None:
        self.assertTrue(self.report["hash_based"])
        self.assertEqual(len(self.report["source_hash"]), 16)

    def test_crlf_marker_identifies_a_pyc(self) -> None:
        """Every .pyc carries a literal CRLF at bytes 2-4, on every platform.

        Detecting on the first byte instead missed modern files, whose magic low
        byte is not 'c'.
        """
        raw = Path(self.pyc).read_bytes()
        self.assertEqual(raw[2:4], b"\r\n")

    def test_non_pyc_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / "x.pyc"
            bogus.write_bytes(b"not a pyc at all, definitely not" * 2)
            report = formats.inspect_pyc(bogus)
        self.assertFalse(report["ok"])
        self.assertIn("magic", report["error"])


class DesktopReaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = _first("*.desktop", "/usr/share/applications")
        if self.entry is None:
            self.skipTest("no .desktop entries on this host")
        self.report = formats.inspect_desktop(self.entry)

    def test_command_is_extracted(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertTrue(self.report["command"])
        self.assertFalse(self.report["command"].startswith("%"))

    def test_field_codes_are_not_treated_as_arguments(self) -> None:
        """%f/%u/%F/%U are placeholders, and must be reported as such."""
        for code in self.report["field_codes"]:
            self.assertNotIn(code, self.report["arguments"])

    def test_missing_desktop_group_is_an_answer_not_a_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.desktop"
            bad.write_text("[Some Other Group]\nKey=Value\n")
            report = formats.inspect_desktop(bad)
        self.assertFalse(report["ok"])
        self.assertIn("Desktop Entry", report["error"])


class GoBinaryTest(unittest.TestCase):
    """Our own hub binary is a Go build, and `go version -m` is the oracle."""

    def setUp(self) -> None:
        if not GO_HUB.is_file():
            self.skipTest("xtforge-hub binary is not built")
        self.report = formats.inspect_go_binary(GO_HUB)

    def test_version_is_read(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertTrue(self.report["version"].startswith("go1."))

    def test_module_info_blob_is_parsed(self) -> None:
        """The 1.18+ record holds one varint blob, not a second string.

        Reading it as a string left module, dependencies and VCS revision all empty
        for a binary that carries every one of them.
        """
        self.assertEqual(self.report["module"], "xtforge-hub")
        self.assertEqual(self.report["goos"], "linux")
        self.assertEqual(self.report["goarch"], "amd64")
        self.assertRegex(self.report["vcs_revision"], r"^[0-9a-f]{40}$")

    def test_matches_go_version_dash_m(self) -> None:
        go = shutil.which("go")
        if not go:
            self.skipTest("go toolchain unavailable")
        completed = subprocess.run([go, "version", "-m", str(GO_HUB)],
                                   capture_output=True, text=True)
        if completed.returncode != 0:
            self.skipTest("go version -m failed")
        out = completed.stdout
        first_line = out.splitlines()[0]
        self.assertIn(self.report["version"], first_line)
        self.assertIn("GOOS=linux", out)
        self.assertIn("GOARCH=amd64", out)
        self.assertIn(self.report["vcs_revision"], out)

    def test_non_go_binary_is_rejected_clearly(self) -> None:
        report = formats.inspect_go_binary("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("not a Go binary", report["error"])


class RustReaderTest(unittest.TestCase):
    def test_reports_evidence_not_a_version(self) -> None:
        """Rust embeds source paths, not a version record.

        The reader is explicit that crate names are inferred, because presenting an
        inferred crate list as if it were read from a header would be a stronger
        claim than the format supports.
        """
        rust = _first("*.so", "/usr/lib/x86_64-linux-gnu") or _first("*", "/usr/bin")
        if rust is None:
            self.skipTest("no binaries to scan")
        report = formats.inspect_rust_binary(rust)
        if not report["ok"]:
            self.assertIn("no Rust markers", report["error"])
            return
        self.assertIn("note", report)
        self.assertIn("inferred", report["note"])


class FormatEdgeCaseTest(unittest.TestCase):
    def test_missing_file_is_reported_not_raised(self) -> None:
        report = formats.inspect("/nonexistent/path/to/nothing")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)

    def test_empty_file_is_reported_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.bin"
            empty.write_bytes(b"")
            report = formats.inspect(empty)
        self.assertFalse(report["ok"])

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(777)
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(20):
                blob = Path(tmp) / f"r{i}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 4096))))
                for reader in (formats.inspect, formats.inspect_plist,
                               formats.inspect_pyc, formats.inspect_desktop):
                    try:
                        reader(blob)
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"{reader.__name__} raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
