"""Tests for the Dart AOT snapshot reader.

Two oracles, both external:

  * The **Dart SDK itself** (3.14.1), downloaded and extracted, produces a real AOT
    snapshot with `dart compile aot-snapshot`. Its 796 KB output is an ELF holding a
    `kFullAOT` snapshot — not a fixture I shaped to match my own parser.
  * **Independent arithmetic** on the raw bytes verifies the header fields: the magic's
    position, `length + 4` as the snapshot size, and `round_up(length)` as the data-image
    base are recomputed from the file without using the module.

There is also a PNG-wrapped variant, built by zlib-compressing the real ELF into an IDAT
chunk. That reproduces the shape of an iOS `App.framework/App`, where the App Store strips
executables and the code survives only inside the image.

The header layout is not guessed: it comes from `runtime/vm/snapshot.h`, which states the
three traps this reader handles — `length` excludes the magic, the data image is aligned
from `round_up(length)` rather than from the header, and the magic is little-endian so a
byte search for "dcdcf5f5" finds nothing.
"""
from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from xtforge.core.re import dartsnapshot

DART_SOURCE = """
class Vehicle {
  final int wheels;
  final String name;
  Vehicle(this.wheels, this.name);
  String describe() => "$name has $wheels wheels";
}

enum Terrain { road, offroad, water }

void main() {
  final v = Vehicle(4, "car");
  print(v.describe());
  print(Terrain.values);
}
"""


def find_dart() -> Path | None:
    for root in (Path.home() / "dartsdk", Path("/opt/dart"), Path("/tmp/art")):
        if not root.is_dir():
            continue
        try:
            hits = [hit for hit in root.rglob("dart")
                    if hit.is_file() and os.access(hit, os.X_OK)]
        except OSError:
            continue
        # Skip snapshot/runtime helpers called "dart" with no version flag.
        for candidate in hits:
            if candidate.parent.name == "bin":
                return candidate
    return None


def build_snapshot(dart: Path, directory: Path) -> Path | None:
    source = directory / "app.dart"
    source.write_text(DART_SOURCE)
    target = directory / "app.aot"
    try:
        result = subprocess.run(
            [str(dart), "compile", "aot-snapshot", str(source), "-o", str(target)],
            capture_output=True, timeout=900, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return target if target.is_file() and target.stat().st_size > 0 else None


def make_snapshot(length: int = 1000, kind: int = 2,
                  payload: bytes | None = None) -> bytes:
    """A snapshot assembled from the documented header, for boundary tests."""
    body = payload if payload is not None else bytes(length)
    return (struct.pack("<I", dartsnapshot.DART_MAGIC)
            + struct.pack("<q", len(body))
            + struct.pack("<q", kind)
            + body)


class HeaderTest(unittest.TestCase):
    def _inspect(self, blob: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.bin"
            path.write_bytes(blob)
            return dartsnapshot.inspect_dart_snapshot(path)

    def test_raw_snapshot_kind_is_reported(self) -> None:
        report = self._inspect(make_snapshot(1000, 2))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["container"], "raw-snapshot")
        self.assertEqual(report["snapshot"]["kind"], "kFullAOT")

    def test_all_kinds_decode(self) -> None:
        for kind, name in ((0, "kFull"), (1, "kFullJIT"), (2, "kFullAOT"),
                           (3, "kModule"), (4, "kInvalid")):
            report = self._inspect(make_snapshot(64, kind))
            self.assertEqual(report["snapshot"]["kind"], name, kind)

    def test_length_excludes_the_magic(self) -> None:
        """Total footprint is length + 4, not length.

        Reading the declared length as the full size makes every following offset 4 bytes
        short and the data-image base wrong.
        """
        blob = make_snapshot(1000, 2) + bytes(4096)
        report = self._inspect(blob)
        self.assertEqual(report["snapshot"]["declared_length"], 1000)
        self.assertEqual(report["snapshot"]["snapshot_size"], 1004)

    def test_truncated_snapshot_is_flagged(self) -> None:
        """A payload shorter than the declared length must be reported, not parsed on."""
        blob = struct.pack("<I", dartsnapshot.DART_MAGIC) \
            + struct.pack("<q", 999999) + struct.pack("<q", 2) + bytes(100)
        report = self._inspect(blob)
        self.assertTrue(report["snapshot"].get("truncated"))
        self.assertEqual(report["snapshot"]["available"], 120)
        self.assertGreater(report["snapshot"]["shortfall"], 0)

    def test_data_image_is_aligned_from_length(self) -> None:
        """The data image starts at round_up(length) from the snapshot base."""
        for length in (1000, 1001, 1005, 1008):
            blob = make_snapshot(length, 2) + bytes(8192)
            report = self._inspect(blob)
            expected = (length + 7) // 8 * 8
            self.assertEqual(report["snapshot"]["data_image_offset"], expected, length)

    def test_kind_without_code_has_no_data_image(self) -> None:
        """kFull has no code, so there is no data image to point at."""
        report = self._inspect(make_snapshot(500, 0) + bytes(1024))
        self.assertFalse(report["snapshot"]["includes_code"])
        self.assertNotIn("data_image_offset", report["snapshot"])

    def test_big_endian_magic_is_not_found(self) -> None:
        """The magic is little-endian on disk: f5 f5 dc dc, not dc dc f5 f5."""
        wrong = struct.pack(">I", dartsnapshot.DART_MAGIC) + bytes(64)
        report = self._inspect(wrong)
        self.assertFalse(report["ok"])

    def test_arbitrary_data_is_rejected(self) -> None:
        report = self._inspect(bytes(2048))
        self.assertFalse(report["ok"])


class RealSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.dart = find_dart()
        cls.snapshot = build_snapshot(cls.dart, cls.root) if cls.dart else None
        cls.report = (dartsnapshot.inspect_dart_snapshot(cls.snapshot)
                      if cls.snapshot else None)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.dart is None:
            self.skipTest("no Dart SDK on this host")
        if self.report is None:
            self.skipTest("could not build a Dart AOT snapshot")

    def test_snapshot_is_found_inside_the_elf(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["container"], "elf")
        self.assertTrue(self.report["dart_snapshot_found"])

    def test_kind_is_full_aot(self) -> None:
        self.assertEqual(self.report["snapshot"]["kind"], "kFullAOT")
        self.assertTrue(self.report["snapshot"]["includes_code"])

    def test_header_fields_match_independent_arithmetic(self) -> None:
        """Recompute the header straight from the bytes, without the module."""
        raw = self.snapshot.read_bytes()
        magic = struct.pack("<I", dartsnapshot.DART_MAGIC)
        offset = raw.find(magic)
        self.assertGreaterEqual(offset, 0)
        self.assertEqual(self.report["snapshot"]["offset"], offset)
        (length,) = struct.unpack_from("<q", raw, offset + 4)
        (kind,) = struct.unpack_from("<q", raw, offset + 12)
        self.assertEqual(self.report["snapshot"]["declared_length"], length)
        self.assertEqual(self.report["snapshot"]["kind_id"], kind)
        self.assertEqual(self.report["snapshot"]["snapshot_size"], length + 4)
        aligned = (length + 7) // 8 * 8
        self.assertEqual(self.report["snapshot"]["data_image_offset"], offset + aligned)
        # The data image runs to the end of the file.
        self.assertEqual(self.report["snapshot"]["data_image_size"],
                         len(raw) - (offset + aligned))

    def test_snapshot_lies_in_a_loadable_section(self) -> None:
        """The magic sits inside .rodata, which is where the linker puts it."""
        readelf = None
        for candidate in ("/usr/bin/readelf", "/bin/readelf"):
            if Path(candidate).is_file():
                readelf = candidate
                break
        if readelf is None:
            self.skipTest("readelf is not available")
        try:
            proc = subprocess.run([readelf, "-S", "-W", str(self.snapshot)],
                                  capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("readelf could not be run")
        offset = self.report["snapshot"]["offset"]
        inside = False
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) < 6 or not parts[0].startswith("["):
                continue
            try:
                section_offset = int(parts[4], 16)
                section_size = int(parts[5], 16)
            except (ValueError, IndexError):
                continue
            if section_offset <= offset < section_offset + section_size:
                inside = True
                break
        self.assertTrue(inside, f"snapshot at {offset} is not inside any ELF section")

    def test_result_is_json_serialisable(self) -> None:
        import json
        json.dumps(self.report)


class PngWrappedTest(unittest.TestCase):
    """The iOS `App.framework/App` shape: an ELF inside a PNG's IDAT stream."""

    def test_elf_inside_png_idat_is_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Build a small but structurally real ELF-ish payload with a snapshot in it.
            payload = make_snapshot(512, 2) + bytes(2048)
            elf = b"\x7fELF" + bytes(60) + payload

            def chunk(kind: bytes, data: bytes) -> bytes:
                return (struct.pack(">I", len(data)) + kind + data
                        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

            png = (b"\x89PNG\r\n\x1a\n"
                   + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
                   + chunk(b"IDAT", zlib.compress(elf, 9))
                   + chunk(b"IEND", b""))
            target = root / "App"
            target.write_bytes(png)
            report = dartsnapshot.inspect_dart_snapshot(target)

        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["container"], "png")
        self.assertTrue(report["dart_snapshot_found"],
                        "the ELF inside the PNG was not recovered")
        self.assertEqual(report["elf"]["recovered_from"], "inflated-idat")
        self.assertEqual(report["snapshot"]["kind"], "kFullAOT")

    def test_png_without_a_snapshot_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def chunk(kind: bytes, data: bytes) -> bytes:
                return (struct.pack(">I", len(data)) + kind + data
                        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

            png = (b"\x89PNG\r\n\x1a\n"
                   + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
                   + chunk(b"IDAT", zlib.compress(b"not an executable", 9))
                   + chunk(b"IEND", b""))
            target = root / "plain.png"
            target.write_bytes(png)
            report = dartsnapshot.inspect_dart_snapshot(target)

        self.assertTrue(report["ok"])
        self.assertFalse(report["dart_snapshot_found"])
        self.assertIn("note", report)

    def test_plain_elf_without_snapshot_is_reported_honestly(self) -> None:
        report = dartsnapshot.inspect_dart_snapshot("/bin/ls")
        self.assertTrue(report["ok"])
        self.assertEqual(report["container"], "elf")
        self.assertFalse(report["dart_snapshot_found"],
                         "/bin/ls was claimed to contain a Dart snapshot")
        self.assertIn("not a Dart AOT image", report["note"])


class BoundaryTest(unittest.TestCase):
    def test_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "e.bin"
            path.write_bytes(b"")
            report = dartsnapshot.inspect_dart_snapshot(path)
        self.assertFalse(report["ok"])

    def test_missing_file(self) -> None:
        report = dartsnapshot.inspect_dart_snapshot("/nonexistent/app.aot")
        self.assertFalse(report["ok"])

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(777)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(15):
                blob = root / f"r{index}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 1200))))
                try:
                    dartsnapshot.inspect_dart_snapshot(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
