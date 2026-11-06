"""Tests for minidump and crash dump parser."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.crash import parse_crash


def create_synthetic_minidump(
    exception_code: int = 0xC0000005,
    exception_addr: int = 0x140001050,
    module_name: str = "crash_app.exe",
    module_base: int = 0x140000000,
    module_size: int = 0x10000,
) -> bytes:
    """Build a minimal valid Windows MiniDump byte buffer with Exception and ModuleList streams."""
    # We will assemble:
    # 0x00: Header (32 bytes)
    # 0x20: Stream Directory (2 entries * 12 bytes = 24 bytes) -> [0x20 .. 0x38]
    # 0x38: Exception Stream (168 bytes) -> [0x38 .. 0xE0]
    # 0xE0: Module List Stream:
    #       - num_modules: 4 bytes
    #       - MINIDUMP_MODULE: 108 bytes -> [0xE4 .. 0x150]
    # 0x150: MINIDUMP_STRING for module name:
    #       - Length: 4 bytes
    #       - WCHAR buffer

    encoded_name = module_name.encode("utf-16le") + b"\x00\x00"
    name_rva = 0x150
    name_stream = struct.pack("<I", len(encoded_name) - 2) + encoded_name

    # Exception stream
    # ThreadId(4), alignment(4), ExceptionCode(4), ExceptionFlags(4), ExceptionRecord(8), ExceptionAddress(8), NumberParameters(4), alignment(4), ExceptionInformation(15*8), ThreadContext(8)
    exc_info_zeros = b"\x00" * (15 * 8)
    exc_stream = struct.pack(
        "<IIIIQQII",
        1001,
        0,
        exception_code,
        0,
        0,
        exception_addr,
        0,
        0,
    ) + exc_info_zeros + struct.pack("<II", 0, 0)
    exc_rva = 0x38
    exc_size = len(exc_stream)

    # Module list stream
    mod_rva = exc_rva + exc_size
    mod_entry = struct.pack(
        "<QIIII",
        module_base,
        module_size,
        0,
        1700000000,
        name_rva,
    ) + (b"\x00" * 52) + struct.pack("<IIII", 0, 0, 0, 0)
    mod_stream = struct.pack("<I", 1) + mod_entry
    mod_size = len(mod_stream)

    # Header
    stream_dir_rva = 32
    num_streams = 2
    header = struct.pack(
        "<4sIIIIIQ",
        b"MDMP",
        0x0000A793,
        num_streams,
        stream_dir_rva,
        0,
        1700000000,
        0,
    )

    # Directory entries: Type(4), DataSize(4), Rva(4)
    # StreamType 6 = ExceptionStream, 4 = ModuleListStream
    dir_entries = struct.pack("<III", 6, exc_size, exc_rva) + struct.pack("<III", 4, mod_size, mod_rva)

    blob = bytearray()
    blob.extend(header)
    blob.extend(dir_entries)
    # Pad to exc_rva
    if len(blob) < exc_rva:
        blob.extend(b"\x00" * (exc_rva - len(blob)))
    blob.extend(exc_stream)
    blob.extend(mod_stream)
    if len(blob) < name_rva:
        blob.extend(b"\x00" * (name_rva - len(blob)))
    blob.extend(name_stream)

    return bytes(blob)


class TestCrashParser(unittest.TestCase):
    def test_parse_minidump(self):
        dump_bytes = create_synthetic_minidump(
            exception_code=0xC0000005,
            exception_addr=0x140001050,
            module_name="test_crash.dll",
            module_base=0x140000000,
            module_size=0x20000,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "crash.dmp"
            fpath.write_bytes(dump_bytes)

            res = parse_crash(fpath)
            self.assertTrue(res["ok"])
            self.assertEqual(res["format"], "minidump")
            exc = res.get("exception", {})
            self.assertEqual(exc.get("code"), "0xc0000005")
            self.assertEqual(exc.get("code_name"), "STATUS_ACCESS_VIOLATION")
            self.assertEqual(exc.get("address"), "0x140001050")
            self.assertEqual(exc.get("thread_id"), 1001)

            mod = res.get("crashing_module")
            self.assertIsNotNone(mod)
            self.assertIn("test_crash.dll", mod.get("name", ""))
            self.assertEqual(mod.get("offset"), "0x1050")

    def test_parse_invalid_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "random.bin"
            fpath.write_bytes(b"NOT_A_CRASH_DUMP")

            res = parse_crash(fpath)
            self.assertFalse(res["ok"])
