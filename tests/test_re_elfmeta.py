"""Tests for the ELF metadata report (notes, DWARF units, unwind ranges).

The engine consumes .eh_frame for function starts and DWARF for names but never
reports them; ``elfmeta.report`` is the analyst-facing view of that data.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import elfmeta

SOURCE_NAME = "elfmeta_fixture.c"


def _compile_fixture(tmp: Path) -> Path:
    source = tmp / SOURCE_NAME
    source.write_text(
        "int helper(int x) { return x + 1; }\n"
        "int main(void) { return helper(41); }\n"
    )
    binary = tmp / "elfmeta_fixture"
    subprocess.run(
        ["clang", "-g", "-O0", "-Wl,--build-id=sha1", str(source), "-o", str(binary)],
        check=True, capture_output=True,
    )
    return binary


def _elf_image(sections: list[tuple[str, int, bytes]], *, bits: int = 64,
               endian: str = "<") -> bytes:
    """Build a minimal sectioned ELF from (name, sh_type, payload) triples."""
    ehsize = 64 if bits == 64 else 52
    shentsize = 64 if bits == 64 else 40
    ident = (b"\x7fELF" +
             bytes((2 if bits == 64 else 1, 1 if endian == "<" else 2, 1, 0)) +
             b"\x00" * 8)
    names = b"\x00"
    name_off: dict[str, int] = {}
    for name, _typ, _payload in sections:
        name_off[name] = len(names)
        names += name.encode() + b"\x00"
    all_sections = [("NULL", 0, b"")] + list(sections) + [(".shstrtab", 3, names)]
    buf = bytearray(b"\x00" * ehsize)
    placed: list[tuple[str, int, int, int]] = []
    for name, typ, payload in all_sections[1:]:
        while len(buf) % 8:
            buf += b"\x00"
        off = len(buf)
        buf += payload
        placed.append((name, typ, off, len(payload)))
    while len(buf) % 8:
        buf += b"\x00"
    shoff = len(buf)
    shfmt = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    for name, typ, off, size in [("NULL", 0, 0, 0)] + placed:
        buf += struct.pack(shfmt, name_off.get(name, 0), typ, 0, 0, off, size,
                           0, 0, 1, 0)
    count = len(all_sections)
    if bits == 64:
        hfmt = endian + "HHIQQQIHHHHHH"
        args = (1, 62, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize, count, count - 1)
    else:
        hfmt = endian + "HHIIIIIHHHHHH"
        args = (1, 3, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize, count, count - 1)
    buf[:ehsize] = ident + struct.pack(hfmt, *args)
    return bytes(buf)


def _synthetic_elf(debug_info: bytes) -> bytes:
    return _elf_image([(".debug_info", 1, debug_info)])


def _note(ntype: int, desc: bytes, name: bytes = b"GNU") -> bytes:
    out = struct.pack("<III", len(name), len(desc), ntype) + name
    out += b"\x00" * ((-len(out)) % 4)
    out += desc
    return out + b"\x00" * ((-len(out)) % 4)


@unittest.skipUnless(shutil.which("clang"), "clang required")
class TestElfMeta(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.binary = _compile_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_report_exposes_dwarf_unit_unwind_and_build_id(self) -> None:
        result = elfmeta.report(self.binary)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["format"], "elf")
        self.assertIn(result["bits"], (32, 64))
        self.assertIn(result["endian"], ("little", "big"))
        self.assertIsInstance(result["sections_reported"], int)

        dwarf = result["dwarf"]
        self.assertEqual(dwarf["count"], 1, dwarf)
        self.assertEqual(len(dwarf["units"]), 1)
        unit = dwarf["units"][0]
        self.assertIn(SOURCE_NAME, unit["name"] or "", dwarf)
        self.assertIsInstance(unit["producer"], str)
        self.assertIsInstance(unit["low_pc"], int)
        self.assertGreaterEqual(unit["low_pc"], 0)
        self.assertIsInstance(unit["high_pc"], int)

        unwind = result["unwind"]
        self.assertGreaterEqual(unwind["fde_count"], 1, unwind)
        self.assertIsInstance(unwind["cie_count"], int)
        self.assertIsInstance(unwind["truncated"], bool)

        build_id = result["notes"]["build_id"]
        self.assertIsInstance(build_id, str)
        self.assertTrue(build_id)
        self.assertRegex(build_id, r"^[0-9a-f]+$")

    def test_truncated_elf_raises_value_error(self) -> None:
        truncated = Path(self._tmp.name) / "truncated.elf"
        truncated.write_bytes(self.binary.read_bytes()[:64])
        with self.assertRaises(ValueError):
            elfmeta.report(truncated)

    def test_non_elf_bytes_raise_value_error_with_hex_prefix(self) -> None:
        bogus = Path(self._tmp.name) / "bogus.bin"
        raw = b"NOPE-not-an-elf"
        bogus.write_bytes(raw)
        with self.assertRaises(ValueError) as ctx:
            elfmeta.report(bogus)
        self.assertEqual(str(ctx.exception), f"not an ELF file: {raw[:4].hex()}")

    def test_garbage_debug_info_returns_warning_not_exception(self) -> None:
        # PROVES: a structurally valid ELF whose .debug_info contents are garbage
        # still returns a report; the malformed unit becomes a warning instead of
        # an exception. It does NOT prove anything about real compiler output.
        damaged = Path(self._tmp.name) / "garbage.elf"
        damaged.write_bytes(_synthetic_elf(b"\xff" * 32))
        result = elfmeta.report(damaged)
        self.assertTrue(result["ok"])
        self.assertEqual(result["dwarf"]["count"], 0)
        self.assertTrue(result["dwarf"]["warnings"], result["dwarf"])
        self.assertIsNone(result["notes"]["build_id"])
        self.assertEqual(result["unwind"]["fde_count"], 0)

    def test_elf32_big_endian_header_is_reported(self) -> None:
        image = Path(self._tmp.name) / "be32.elf"
        image.write_bytes(_elf_image([], bits=32, endian=">"))
        result = elfmeta.report(image)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["bits"], 32)
        self.assertEqual(result["endian"], "big")

    def test_dwarf4_forms_notes_and_unwind_from_synthetic_elf(self) -> None:
        abbrev = bytes([
            1, 0x11, 0,        # abbrev 1, DW_TAG_compile_unit, no children
            0x03, 0x08,        # DW_AT_name / DW_FORM_string
            0x25, 0x0e,        # DW_AT_producer / DW_FORM_strp
            0x11, 0x01,        # DW_AT_low_pc / DW_FORM_addr
            0x12, 0x06,        # DW_AT_high_pc / DW_FORM_data4
            0, 0,              # end of attributes
            0,                 # end of table
        ])
        payload = (struct.pack("<HI", 4, 0) + bytes([8]) +
                   b"\x01" + b"synthetic.c\x00" +
                   struct.pack("<I", 1) + struct.pack("<Q", 0x1000) +
                   struct.pack("<I", 0x40))
        info = struct.pack("<I", len(payload)) + payload
        cie = struct.pack("<I", 6) + struct.pack("<I", 0) + b"\x01\x00"
        fde = struct.pack("<I", 12) + struct.pack("<I", len(cie)) + b"\x00" * 8
        notes = (_note(3, b"\xde\xad\xbe\xef") + _note(1, b"Linux\x00") +
                 _note(5, b"\x00\x00\x00\x00"))
        image = Path(self._tmp.name) / "synthetic.elf"
        image.write_bytes(_elf_image([
            (".debug_info", 1, info),
            (".debug_abbrev", 1, abbrev),
            (".debug_str", 1, b"\x00synthetic clang\x00"),
            (".eh_frame", 1, cie + fde),
            (".note.test", 7, notes),
        ]))
        result = elfmeta.report(image)
        self.assertEqual(result["dwarf"]["count"], 1, result["dwarf"])
        unit = result["dwarf"]["units"][0]
        self.assertEqual(unit["name"], "synthetic.c")
        self.assertEqual(unit["producer"], "synthetic clang")
        self.assertEqual(unit["low_pc"], 0x1000)
        self.assertEqual(unit["high_pc"], 0x40)
        self.assertEqual(result["unwind"]["cie_count"], 1)
        self.assertEqual(result["unwind"]["fde_count"], 1)
        self.assertFalse(result["unwind"]["truncated"])
        self.assertEqual(result["notes"]["build_id"], "deadbeef")
        self.assertEqual(result["notes"]["abi_tag"], "Linux")
        self.assertTrue(result["notes"]["gnu_property"])

    def test_dwarf64_unit_length_does_not_break_parsing(self) -> None:
        abbrev = bytes([1, 0x11, 0, 0x03, 0x08, 0, 0, 0])
        payload = (struct.pack("<H", 4) + struct.pack("<Q", 0) +
                   b"\x08\x01dwarf64.c\x00")
        info = (struct.pack("<I", 0xFFFFFFFF) +
                struct.pack("<Q", len(payload)) + payload)
        image = Path(self._tmp.name) / "dwarf64.elf"
        image.write_bytes(_elf_image([
            (".debug_info", 1, info), (".debug_abbrev", 1, abbrev),
        ]))
        result = elfmeta.report(image)
        self.assertEqual(result["dwarf"]["count"], 1, result["dwarf"])
        self.assertEqual(result["dwarf"]["units"][0]["name"], "dwarf64.c")
        self.assertFalse(result["dwarf"]["warnings"], result["dwarf"])

    def test_bounds_cap_units_and_fdes(self) -> None:
        unit = struct.pack("<I", 8) + struct.pack("<HI", 4, 0) + b"\x08\x00"
        fde = struct.pack("<I", 4) + struct.pack("<I", 1)
        image = Path(self._tmp.name) / "capped.elf"
        image.write_bytes(_elf_image([
            (".debug_info", 1, unit * 201),
            (".debug_abbrev", 1, b"\x00"),
            (".eh_frame", 1, fde * 5001),
        ]))
        result = elfmeta.report(image)
        self.assertEqual(result["dwarf"]["count"], 200)
        self.assertTrue(result["dwarf"]["warnings"])
        self.assertEqual(result["unwind"]["fde_count"], 5000)
        self.assertTrue(result["unwind"]["truncated"])


if __name__ == "__main__":
    unittest.main()
