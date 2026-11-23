"""Tests for the UEFI firmware-volume reader."""
from __future__ import annotations

import random
import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.firmware import COMPRESSION_NOTE, format_guid, inspect

# 78 56 34 12 bc 9a de 0f 00 11 22 33 44 55 66 77
KNOWN_GUID = bytes([
    0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xDE, 0x0F,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
])
KNOWN_GUID_TEXT = "12345678-9abc-0fde-0011-223344556677"

SECOND_GUID = bytes([
    0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
])
SECOND_GUID_TEXT = "89abcdef-4567-0123-1020-304050607080"


def make_ffs(guid: bytes, ftype: int, payload: bytes = b"", *, state: int = 0xF8,
             declared_size: int | None = None) -> bytes:
    """Build an EFI_FFS_FILE_HEADER (24 bytes) plus a padded payload."""
    body = 24 + len(payload)
    size = declared_size if declared_size is not None else (body + 7) // 8 * 8
    header = (
        guid
        + struct.pack("<H", 0)                  # IntegrityCheck
        + bytes([ftype, 0])                     # Type, Attributes
        + size.to_bytes(3, "little")            # Size[3]
        + bytes([state])                        # State
    )
    assert len(header) == 24
    padding = b"\x00" * (size - body) if size > body else b""
    return header + payload + padding


def checksum16(raw: bytes) -> int:
    """Independent word-based UEFI checksum, so the fixture is not circular."""
    total = 0
    for index in range(0, len(raw) - 1, 2):
        total += raw[index] + (raw[index + 1] << 8)
    if len(raw) % 2:
        total += raw[-1]
    return total & 0xFFFF


def make_volume(ffs_bytes: bytes, *, revision: int = 2, attributes: int = 0,
                ext: int = 0, fv_length: int | None = None) -> bytes:
    """Build a 56-byte EFI_FIRMWARE_VOLUME_HEADER with a valid checksum."""
    header = bytearray(0x38)
    header[0x00:0x10] = b"\x00" * 16            # ZeroVector
    header[0x10:0x20] = KNOWN_GUID              # FileSystemGuid
    total = 0x38 + len(ffs_bytes) if fv_length is None else fv_length
    struct.pack_into("<Q", header, 0x20, total)  # FvLength
    header[0x28:0x2C] = b"_FVH"                 # Signature
    struct.pack_into("<I", header, 0x2C, attributes)
    struct.pack_into("<H", header, 0x30, 0x38)  # HeaderLength
    struct.pack_into("<H", header, 0x32, 0)     # Checksum
    struct.pack_into("<H", header, 0x34, ext)   # ExtHeaderOffset
    header[0x36] = 0                            # Reserved
    header[0x37] = revision                     # Revision
    struct.pack_into("<H", header, 0x32, (-checksum16(header)) & 0xFFFF)
    return bytes(header) + ffs_bytes


class TestReFirmware(unittest.TestCase):
    def _write(self, data: bytes) -> str:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "fv.bin"
        path.write_bytes(data)
        return str(path)

    def test_valid_volume_lists_files(self):
        ffs = (
            make_ffs(KNOWN_GUID, 0x02, b"abc")
            + make_ffs(SECOND_GUID, 0x07, b"0123456789abcdef")
        )
        result = inspect(self._write(make_volume(ffs)))

        self.assertTrue(result["ok"])
        self.assertEqual(result["format"], "uefi_fv")
        self.assertEqual(result["volume_offset"], 0)
        self.assertFalse(result["truncated"])
        volume = result["volume"]
        self.assertTrue(volume["checksum_ok"])
        self.assertTrue(volume["reported_length_matches_file"])
        self.assertEqual(volume["fs_guid"], KNOWN_GUID_TEXT)
        self.assertEqual(volume["header_length"], 0x38)
        self.assertEqual(volume["revision"], 2)
        self.assertEqual(volume["attributes"], 0)
        self.assertEqual(volume["ext_header_offset"], 0)

        self.assertEqual(len(result["files"]), 2)
        self.assertEqual([f["guid"] for f in result["files"]],
                         [KNOWN_GUID_TEXT, SECOND_GUID_TEXT])
        self.assertEqual([f["size"] for f in result["files"]], [32, 40])
        self.assertEqual([f["type"] for f in result["files"]], [0x02, 0x07])
        self.assertEqual([f["type_name"] for f in result["files"]],
                         ["FREEFORM", "DRIVER"])
        self.assertEqual([f["index"] for f in result["files"]], [0, 1])
        self.assertTrue(all(f["compressed"] is False for f in result["files"]))
        self.assertIn(COMPRESSION_NOTE, result["notes"])

    def test_checksum_mismatch_still_lists_files(self):
        data = bytearray(make_volume(make_ffs(KNOWN_GUID, 0x02, b"abc")
                                     + make_ffs(SECOND_GUID, 0x07, b"driver")))
        data[0x32] ^= 0x01  # flip one checksum byte
        result = inspect(self._write(bytes(data)))

        self.assertEqual(result["format"], "uefi_fv")
        self.assertFalse(result["volume"]["checksum_ok"])
        self.assertEqual(len(result["files"]), 2)
        self.assertTrue(result["notes"])
        self.assertIn("checksum mismatch", " ".join(result["notes"]))

    def test_file_running_past_volume_is_noted(self):
        bad_ffs = bytearray(make_ffs(KNOWN_GUID, 0x02, b"abc"))
        bad_ffs[20:23] = (4096).to_bytes(3, "little")  # declared, not actual
        result = inspect(self._write(make_volume(bytes(bad_ffs))))

        self.assertEqual(result["format"], "uefi_fv")
        self.assertTrue(any("runs past the volume" in note for note in result["notes"]))

    def test_pad_files_are_counted_not_listed(self):
        ffs = (
            make_ffs(KNOWN_GUID, 0xF0, b"padding")
            + make_ffs(SECOND_GUID, 0x07, b"abc")
        )
        result = inspect(self._write(make_volume(ffs)))

        self.assertEqual([f["guid"] for f in result["files"]], [SECOND_GUID_TEXT])
        self.assertTrue(any("PAD file" in note for note in result["notes"]))

    def test_embedded_volume_offset(self):
        prefix = b"\x00" * 24  # 8-byte aligned, within the 1 MiB window
        result = inspect(self._write(prefix + make_volume(make_ffs(KNOWN_GUID, 0x02, b"abc"))))

        self.assertEqual(result["format"], "uefi_fv")
        self.assertEqual(result["volume_offset"], 24)
        self.assertTrue(result["volume"]["reported_length_matches_file"])

    def test_random_blob_is_unknown_with_hex_note(self):
        blob = random.Random(1234).randbytes(4096)
        result = inspect(self._write(blob))

        self.assertEqual(result["format"], "unknown")
        self.assertEqual(result["files"], [])
        self.assertIn(blob[:16].hex(), " ".join(result["notes"]))

    def test_directory_raises_value_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                inspect(directory)

    def test_format_guid_known_endianness(self):
        self.assertEqual(format_guid(KNOWN_GUID), KNOWN_GUID_TEXT)
        self.assertEqual(format_guid(SECOND_GUID), SECOND_GUID_TEXT)

    def test_format_guid_random(self):
        raw = random.Random(99).randbytes(16)
        expected = (
            f"{int.from_bytes(raw[0:4], 'little'):08x}-"
            f"{int.from_bytes(raw[4:6], 'little'):04x}-"
            f"{int.from_bytes(raw[6:8], 'little'):04x}-"
            f"{raw[8:10].hex()}-{raw[10:16].hex()}"
        )
        self.assertEqual(format_guid(raw), expected)
        self.assertEqual(len(format_guid(raw)), 36)


if __name__ == "__main__":
    unittest.main()
