"""Firmware container carving, verified against real filesystems built on this host.

Every format asserted here is produced by the authoritative tool, not hand-written bytes:

  * **squashfs** — `mksquashfs` 4.7.5 (unpacked from the distribution package), compressing
    a real directory. The superblock the reader validates is one the tool wrote.
  * **cramfs** — `mkfs.cramfs` from util-linux.
  * **TRX** — built to OpenWrt's `trx.c` layout, then cross-checked: the CRC it computes over
    `[flag_version:len]` must be the CRC the reader recomputes.
  * **gzip** — Python's own `gzip`, wrapping an ELF.

Building the fixtures exposed four bugs in the reader, all of which produced plausible
output rather than an error:

  * **squashfs superblock miscounted.** The struct has four u32 fields then **six** u16
    fields; reading five shifted `s_major`/`s_minor` into the wrong slots and the version
    came back wrong.
  * **TRX read big-endian.** Every field is little-endian (`STORE32_LE` in trx.c), so a
    big-endian read yields a length near 0xA0000000 and the CRC check never runs.
  * **TRX CRC range was wrong.** The CRC covers `flag_version` (offset 12) to the declared
    length — not the payload after the header.
  * **TRX header size differs by version.** v1 is 28 bytes with three offsets; v2 is 32 with
    four. trx.c starts writing at `sizeof(struct trx_header) - 4` for v1. A reader that
    always reads four offsets consumes four bytes of the payload as a partition offset.

The design point is that a signature match is not evidence. `hsqs` appears by chance inside
compressed data constantly; a squashfs superblock with a power-of-two block size does not.
So every hit is validated, and a hit that fails validation is *reported* under `rejected`
rather than silently dropped — "I saw the magic but the structure was wrong" is itself a
useful finding.
"""
from __future__ import annotations

import gzip
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

from xtforge.core.re import firmwarecarve


def find_tool(name: str) -> Path | None:
    found = shutil.which(name)
    if found:
        return Path(found)
    for root in (Path("/tmp/sq"), Path("/tmp/art"), Path("/usr/bin"), Path("/bin")):
        if not root.is_dir():
            continue
        candidate = root / "usr" / "bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        try:
            hits = [hit for hit in root.rglob(name) if hit.is_file() and os.access(hit, os.X_OK)]
        except OSError:
            continue
        if hits:
            return hits[0]
    return None


def make_tree(directory: Path) -> Path:
    root = directory / "root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "readme.txt").write_text("firmware payload\n")
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (root / "etc" / "shadow").write_bytes(bytes(range(256)) * 4)
    return root


def build_squashfs(directory: Path) -> Path | None:
    tool = find_tool("mksquashfs")
    if tool is None:
        return None
    source = make_tree(directory)
    target = directory / "fs.sqsh"
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/tmp/sq/usr/lib:" + env.get("LD_LIBRARY_PATH", "")
    try:
        result = subprocess.run(
            [str(tool), str(source), str(target), "-comp", "gzip", "-noappend", "-quiet"],
            capture_output=True, timeout=300, check=False, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    return target if target.is_file() and target.stat().st_size else None


def build_cramfs(directory: Path) -> Path | None:
    tool = find_tool("mkfs.cramfs")
    if tool is None:
        return None
    source = make_tree(directory)
    target = directory / "fs.cramfs"
    try:
        result = subprocess.run([str(tool), str(source), str(target)],
                                capture_output=True, timeout=300, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return target if target.is_file() and target.stat().st_size else None


def build_trx(payload: bytes, version: int = 1) -> bytes:
    """TRX as OpenWrt's trx.c writes it: LE fields, CRC over [12:len]."""
    header_size = 32 if version >= 2 else 28
    count = 4 if version >= 2 else 3
    offsets = [header_size] + [0xFFFFFFFF] * (count - 1)
    total = header_size + len(payload)
    body = struct.pack("<" + "I" * count, *offsets) + payload
    head = struct.pack("<4sIII", b"HDR0", total, 0, version << 16)
    blob = head + body
    assert len(blob) == total, (len(blob), total)
    crc = zlib.crc32(blob[12:total]) & 0xFFFFFFFF
    return struct.pack("<4sIII", b"HDR0", total, crc, version << 16) + body


class SquashfsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_squashfs(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("mksquashfs is not available")

    def test_squashfs_is_carved(self) -> None:
        report = firmwarecarve.carve_firmware(self.path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("squashfs", report["formats_found"])

    def test_superblock_fields_are_plausible(self) -> None:
        report = firmwarecarve.carve_firmware(self.path)
        region = next(entry for entry in report["regions"]
                      if entry["format"] == "squashfs")
        self.assertEqual(region["version"], "4.0")
        self.assertGreater(region["inodes"], 0)
        self.assertGreaterEqual(region["block_size"], 4096)
        self.assertEqual(region["block_size"] & (region["block_size"] - 1), 0,
                         "block size must be a power of two")

    def test_squashfs_inside_a_vendor_header_is_found(self) -> None:
        """Carving is the point: the filesystem is not at offset 0."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "firmware.bin"
            target.write_bytes(b"VENDOR-HEADER" * 20 + bytes(400)
                               + self.path.read_bytes() + b"\xff" * 512)
            report = firmwarecarve.carve_firmware(target)
        region = next(entry for entry in report["regions"]
                      if entry["format"] == "squashfs")
        self.assertGreater(region["offset"], 400)


class CramfsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_cramfs(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("mkfs.cramfs is not available")

    def test_cramfs_is_carved(self) -> None:
        report = firmwarecarve.carve_firmware(self.path)
        self.assertIn("cramfs", report["formats_found"])

    def test_declared_size_matches_the_file(self) -> None:
        report = firmwarecarve.carve_firmware(self.path)
        region = next(entry for entry in report["regions"]
                      if entry["format"] == "cramfs")
        self.assertEqual(region["size"], self.path.stat().st_size)


class TrxTest(unittest.TestCase):
    def test_valid_trx_passes_and_crc_verifies(self) -> None:
        blob = build_trx(b"payload bytes here" + bytes(64))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fw.trx"
            target.write_bytes(blob)
            report = firmwarecarve.carve_firmware(target)
        self.assertIn("trx", report["formats_found"])
        region = next(entry for entry in report["regions"] if entry["format"] == "trx")
        self.assertTrue(region["crc_verified"])

    def test_v1_declares_three_partition_offsets(self) -> None:
        """TRXv1 has a 28-byte header and exactly three offset slots.

        Asserting only the header size is too weak: with a plausible payload the fourth
        word read past the header happens to be fill, so a reader that always reads four
        offsets still passes. What distinguishes the versions is how many offsets the header
        is allowed to declare.
        """
        blob = build_trx(bytes(100), version=1)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fw.trx"
            target.write_bytes(blob)
            report = firmwarecarve.carve_firmware(target)
        region = next(entry for entry in report["regions"] if entry["format"] == "trx")
        self.assertEqual(region["version"], 1)
        self.assertEqual(region["header_size"], 28)
        self.assertEqual(region["offset_slots"], 3)

    def test_v2_declares_four_partition_offsets(self) -> None:
        blob = build_trx(bytes(100), version=2)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fw.trx"
            target.write_bytes(blob)
            report = firmwarecarve.carve_firmware(target)
        region = next(entry for entry in report["regions"] if entry["format"] == "trx")
        self.assertEqual(region["offset_slots"], 4)

    def test_v2_header_is_32_bytes(self) -> None:
        blob = build_trx(bytes(100), version=2)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fw.trx"
            target.write_bytes(blob)
            report = firmwarecarve.carve_firmware(target)
        region = next(entry for entry in report["regions"] if entry["format"] == "trx")
        self.assertEqual(region["version"], 2)
        self.assertEqual(region["header_size"], 32)

    def test_corrupted_payload_is_rejected(self) -> None:
        """A flipped byte must fail the CRC and land in `rejected`, not in the regions."""
        blob = bytearray(build_trx(b"payload" + bytes(200)))
        blob[-10] ^= 0xFF
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fw.trx"
            target.write_bytes(bytes(blob))
            report = firmwarecarve.carve_firmware(target)
        self.assertNotIn("trx", report["formats_found"])
        self.assertTrue(report["rejected"])
        self.assertEqual(report["rejected"][0]["format"], "trx")

    def test_trx_must_be_read_little_endian(self) -> None:
        """A big-endian read gives a length near 0xA0000000 that cannot fit the file."""
        blob = build_trx(bytes(64))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fw.trx"
            target.write_bytes(blob)
            report = firmwarecarve.carve_firmware(target)
        region = next(entry for entry in report["regions"] if entry["format"] == "trx")
        self.assertLess(region["length"], len(blob) + 1)


class CompositeImageTest(unittest.TestCase):
    def test_trx_squashfs_and_gzip_together(self) -> None:
        """The realistic shape: vendor header, TRX, squashfs, padding, compressed kernel."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            squash = build_squashfs(root)
            if squash is None:
                self.skipTest("mksquashfs is not available")
            inner = b"opaque vendor bytes" + bytes(16) + squash.read_bytes()
            trx = build_trx(inner)
            kernel = gzip.compress(b"\x7fELF" + bytes(4000))
            image = root / "full.img"
            image.write_bytes(b"VENDORHDR" * 8 + bytes(512) + trx
                              + b"\xff" * 256 + kernel + bytes(128))
            report = firmwarecarve.carve_firmware(image)

        self.assertEqual(report["rejected_count"], 0,
                         f"nothing should be rejected: {report['rejected']}")
        found = report["formats_found"]
        for expected in ("trx", "squashfs", "gzip"):
            self.assertIn(expected, found)

    def test_gzip_wrapping_an_elf_is_described(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "k.gz"
            target.write_bytes(gzip.compress(b"\x7fELF" + bytes(2000)))
            report = firmwarecarve.carve_firmware(target)
        region = next(entry for entry in report["regions"] if entry["format"] == "gzip")
        self.assertEqual(region["contains"], "elf")
        self.assertGreater(region["decompressed_size"], 2000)

    def test_regions_are_sorted_by_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            squash = build_squashfs(root)
            if squash is None:
                self.skipTest("mksquashfs is not available")
            kernel = gzip.compress(b"\x7fELF" + bytes(1000))
            image = root / "mix.img"
            image.write_bytes(squash.read_bytes() + bytes(256) + kernel)
            report = firmwarecarve.carve_firmware(image)
        offsets = [entry["offset"] for entry in report["regions"]]
        self.assertEqual(offsets, sorted(offsets))


class HonestyTest(unittest.TestCase):
    def test_bare_magic_is_not_a_finding(self) -> None:
        """`hsqs` inside random data must not be reported as a squashfs."""
        blob = b"\x00" * 100 + b"hsqs" + bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "noise.bin"
            target.write_bytes(blob)
            report = firmwarecarve.carve_firmware(target)
        self.assertNotIn("squashfs", report["formats_found"])
        self.assertTrue(any(entry["format"] == "squashfs"
                            for entry in report.get("rejected", [])),
                        "the rejected magic should still be reported")

    def test_nothing_found_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "empty.bin"
            target.write_bytes(b"\x00" * 4096)
            report = firmwarecarve.carve_firmware(target)
        self.assertTrue(report["ok"])
        self.assertEqual(report["region_count"], 0)
        self.assertIn("note", report)

    def test_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "e.bin"
            target.write_bytes(b"")
            report = firmwarecarve.carve_firmware(target)
        self.assertFalse(report["ok"])

    def test_missing_file(self) -> None:
        report = firmwarecarve.carve_firmware("/nonexistent/fw.bin")
        self.assertFalse(report["ok"])

    def test_entropy_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "z.bin"
            target.write_bytes(bytes(65536))
            report = firmwarecarve.carve_firmware(target)
        self.assertEqual(report["entropy_head"], 0.0)

    def test_uefi_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x.fd"
            target.write_bytes(b"_FVH" + bytes(512))
            report = firmwarecarve.carve_firmware(target)
        self.assertIn("hint", report)

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(31337)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(15):
                blob = root / f"r{index}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 3000))))
                try:
                    firmwarecarve.carve_firmware(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")

    def test_result_is_json_serialisable(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t.bin"
            target.write_bytes(build_trx(bytes(64)))
            json.dumps(firmwarecarve.carve_firmware(target))


if __name__ == "__main__":
    unittest.main()
