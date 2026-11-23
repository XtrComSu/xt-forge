"""CLI tests for the `re archives` and `re kernelcache` container verbs."""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _tlv(tag: int, value: bytes) -> bytes:
    """One DER-style tag-length-value record as used by Apple Image4."""
    n = len(value)
    if n < 0x80:
        header = bytes((tag, n))
    elif n <= 0xFF:
        header = bytes((tag, 0x81, n))
    elif n <= 0xFFFF:
        header = bytes((tag, 0x82, n >> 8, n & 0xFF))
    else:
        header = bytes((tag, 0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF))
    return header + value


def _ar_member(name: str, data: bytes) -> bytes:
    """A 60-byte classic ar header followed by the member data and padding."""
    header = bytearray(60)
    fields = ((0, 16, name + "/"), (16, 12, "0"), (28, 6, "0"),
              (34, 6, "0"), (40, 8, "100644"), (48, 10, str(len(data))))
    for offset, width, value in fields:
        header[offset:offset + width] = value.ljust(width).encode()
    header[58:60] = b"`\n"
    return bytes(header) + data + (b"\n" if len(data) % 2 else b"")


def _archive_fixture() -> bytes:
    return b"!<arch>\n" + _ar_member("first.o", b"AAAA") + _ar_member("second.o", b"BBBBBB")


def _macho_fixture() -> bytes:
    """A minimal little-endian 64-bit Mach-O with one __TEXT segment and LC_MAIN."""
    data = bytearray(0x110)
    data[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", data, 4, 0x0100000C)   # CPU_TYPE_ARM64
    struct.pack_into("<I", data, 12, 2)           # MH_EXECUTE
    struct.pack_into("<I", data, 16, 2)           # two load commands
    struct.pack_into("<I", data, 20, 96)          # sizeofcmds
    struct.pack_into("<I", data, 32, 0x19)        # LC_SEGMENT_64
    struct.pack_into("<I", data, 36, 72)          # cmdsize
    data[40:47] = b"__TEXT"
    struct.pack_into("<Q", data, 56, 0x100000000)  # vmaddr
    struct.pack_into("<Q", data, 64, 0x1000)       # vmsize
    struct.pack_into("<Q", data, 80, len(data))    # filesize
    struct.pack_into("<I", data, 88, 7)            # maxprot
    struct.pack_into("<I", data, 92, 5)            # initprot
    struct.pack_into("<I", data, 104, 0x80000028)  # LC_MAIN
    struct.pack_into("<I", data, 108, 24)          # cmdsize
    struct.pack_into("<Q", data, 112, 0x100)       # entryoff
    return bytes(data)


def _img4_fixture() -> bytes:
    im4p = (b"".join((
        _tlv(0x16, b"IM4P"), _tlv(0x16, b"krnl"),
        _tlv(0x16, b"kernel"), _tlv(0x04, _macho_fixture()),
    )))
    body = _tlv(0x16, b"IMG4") + _tlv(0x30, im4p) + _tlv(0xA0, b"opaque manifest")
    return b"IMG4" + _tlv(0x30, body)


class TestReContainerVerbs(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _cli(self, verb: str, path: str | Path) -> subprocess.CompletedProcess[str]:
        # The Go hub enforces an allowlist; include both fixture and ELF dirs.
        roots = f"{self.dir},{Path(sys.executable).resolve().parent}"
        env = dict(os.environ, XT_ROOTS=roots)
        return subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "--json", "re", verb, str(path)],
            capture_output=True, text=True, env=env,
        )

    def _write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    @property
    def elf(self) -> str:
        path = Path(sys.executable).resolve()
        if path.read_bytes()[:4] != b"\x7fELF":
            self.skipTest(f"interpreter is not an ELF binary: {path}")
        return str(path)

    def test_archives_lists_ar_members(self):
        path = self._write("two.o.a", _archive_fixture())
        res = self._cli("archives", path)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"), data)
        self.assertEqual(data.get("count"), 2)
        names = [m["name"] for m in data.get("archive", [])]
        self.assertIn("first.o", names)
        self.assertIn("second.o", names)

    def test_archives_rejects_elf(self):
        res = self._cli("archives", self.elf)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertFalse(data.get("ok"), data)
        self.assertTrue(data.get("error"), data)

    def test_kernelcache_rejects_elf(self):
        res = self._cli("kernelcache", self.elf)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertFalse(data.get("ok"), data)
        self.assertTrue(data.get("error"), data)

    def test_kernelcache_reads_img4_fixture(self):
        path = self._write("kernelcache.img4", _img4_fixture())
        res = self._cli("kernelcache", path)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertTrue(data.get("ok"), data)
        self.assertEqual(data.get("format"), "kernelcache")
        self.assertEqual(data.get("arch"), "arm64")
        self.assertEqual(data.get("member"), "img4-kernel")
        self.assertIsInstance(data.get("entry_point"), int)


if __name__ == "__main__":
    unittest.main()
