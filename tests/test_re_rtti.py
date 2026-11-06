"""Tests for C++ RTTI and Vtable extraction."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.rtti import extract_rtti
from tests.test_re_pe import create_minimal_pe


class TestRTTIExtraction(unittest.TestCase):
    def test_extract_msvc_rtti64(self):
        # Synthesize a minimal PE32+ with .rdata containing MSVC RTTI structures
        image_base = 0x140000000
        rdata_rva = 0x2000
        sec_size = 0x1000

        # Layout in .rdata (rva 0x2000, file offset 0x400 + 0x1000 = 0x1400):
        # 0x2000: TypeDescriptor
        #   pVFTable (8 bytes): image_base + 0x5000
        #   spare (8 bytes): 0
        #   name: ".?AVPlayerEntity@@\0"
        type_desc = bytearray(16)
        struct.pack_into("<QQ", type_desc, 0, image_base + 0x5000, 0)
        type_desc.extend(b".?AVPlayerEntity@@\0")
        while len(type_desc) % 8 != 0:
            type_desc.append(0)

        td_rva = rdata_rva  # 0x2000
        td_len = len(type_desc)

        # RTTICompleteObjectLocator (24 bytes) at td_rva + td_len
        col_rva = td_rva + td_len
        # signature=1, offset=0, cdOffset=0, pTypeDescriptor=td_rva, pClassDescriptor=0, pObjectLocator=col_rva
        col = struct.pack("<IIIIII", 1, 0, 0, td_rva, 0, col_rva)

        # Vtable at col_rva + len(col) + 8:
        # Preceding pointer at vtable - 8 is col's Virtual Address!
        vtable_rva = col_rva + len(col) + 8
        col_va = image_base + col_rva

        rdata_buf = bytearray(sec_size)
        rdata_buf[0 : len(type_desc)] = type_desc
        rdata_buf[col_rva - rdata_rva : col_rva - rdata_rva + len(col)] = col
        # vtable - 8 pointer
        struct.pack_into("<Q", rdata_buf, vtable_rva - 8 - rdata_rva, col_va)
        # 3 vtable virtual method pointers
        struct.pack_into("<QQQ", rdata_buf, vtable_rva - rdata_rva, image_base + 0x1010, image_base + 0x1020, image_base + 0x1030)

        code = b"\x90" * 0x1000
        pe_bytes = create_minimal_pe(
            bits=64,
            sections=[
                (".text", 0x1000, 0x1000, code, 0x60000020),
                (".rdata", 0x2000, 0x1000, bytes(rdata_buf), 0x40000040),
            ],
            image_base=image_base,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "game.dll"
            fpath.write_bytes(pe_bytes)

            res = extract_rtti(fpath)
            self.assertTrue(res["ok"])
            classes = res.get("classes", [])
            self.assertEqual(len(classes), 1)
            self.assertIn("PlayerEntity", classes[0]["demangled_name"])
            self.assertEqual(len(classes[0]["methods"]), 3)
