"""Release bundles must carry a native executable, and the right one.

The shipped 0.4.6 darwin tarball (541 entries) and windows zip (222 entries) contained no
native executable at all, while Linux had both — recorded as an expected failure in
`test_shipped_packages`. That failure could never be fixed from inside this tree, because
nothing in it built the archives: they were assembled by hand.

`scripts/build_release.py` now does. This test builds real archives and checks the property
that was missing, including the architecture of the binary inside them — a wrong-platform
binary is the same defect wearing a disguise.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVES = ("xtforge-hub", "xtforge-hub.exe", "xtforge-native")


def _build(out: Path, *platforms: str) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(ROOT / "scripts" / "build_release.py"),
            "--version", "0.0.0-test", "--out", str(out)]
    for platform in platforms:
        argv += ["--platform", platform]
    return subprocess.run(argv, capture_output=True, text=True, cwd=str(ROOT), timeout=600)


@unittest.skipUnless(shutil.which("go"), "go toolchain required")
class TestReleaseBuilder(unittest.TestCase):
    def test_linux_archive_carries_launcher_and_native(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            completed = _build(out, "linux-x86_64")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            archive = next(out.glob("*.tar.gz"))
            with tarfile.open(archive) as bundle:
                names = bundle.getnames()
        self.assertTrue(any(n.endswith("bin/xtforge") for n in names),
                        "no POSIX launcher in the Linux bundle")
        self.assertTrue(any(n.endswith("bin/xtforge-hub") for n in names),
                        f"no native executable in {archive.name}")

    def test_darwin_binary_is_actually_darwin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            completed = _build(out, "darwin-arm64")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            archive = next(out.glob("*darwin*.tar.gz"))
            with tarfile.open(archive) as bundle:
                member = next(m for m in bundle.getmembers()
                              if m.name.endswith("bin/xtforge-hub"))
                binary = Path(tmp) / "hub"
                binary.write_bytes(bundle.extractfile(member).read())
            if not shutil.which("file"):
                self.skipTest("file(1) unavailable")
            described = subprocess.run(["file", str(binary)], capture_output=True,
                                       text=True).stdout
        self.assertIn("Mach-O", described,
                      f"the darwin bundle ships a non-Mach-O binary: {described.strip()}")
        self.assertIn("arm64", described)

    def test_windows_archive_uses_the_cmd_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            completed = _build(out, "windows-x86_64")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            archive = next(out.glob("*.zip"))
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
        self.assertTrue(any(n.endswith("bin/xtforge.cmd") for n in names),
                        "no .cmd launcher in the Windows bundle")
        self.assertFalse(any(n.endswith("bin/xtforge") for n in names),
                         "a POSIX launcher in a Windows zip is meaningless")
        self.assertTrue(any(n.endswith("xtforge-hub.exe") for n in names))
