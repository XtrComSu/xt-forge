"""Identification and inventory tests for the WebAssembly module reader.

Fixtures are assembled from byte literals here; nothing is downloaded and no
external tool is needed. The module is an inventory layer, not a disassembler.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import wasm

MAGIC = b"\x00asm"
VERSION = b"\x01\x00\x00\x00"
HEADER = MAGIC + VERSION
EMPTY_COUNTS = {"types": 0, "imports": 0, "functions": 0,
                "exports": 0, "code": 0, "data": 0}


def _u32(value: int) -> bytes:
    """Unsigned LEB128, assembled from byte literals."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _u32(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _u32(len(body)) + body


class WasmInventoryTests(unittest.TestCase):
    def _inspect(self, data: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.wasm"
            path.write_bytes(data)
            return wasm.inspect(str(path))

    def test_minimal_module_has_no_sections_or_counts(self) -> None:
        result = self._inspect(HEADER)
        self.assertTrue(result["ok"])
        self.assertEqual(result["format"], "wasm")
        self.assertEqual(result["version"], 1)
        self.assertTrue(result["magic_ok"])
        self.assertEqual(result["size"], 8)
        self.assertTrue(result["path"].endswith("sample.wasm"))
        self.assertEqual(result["sections"], [])
        self.assertEqual(result["counts"], EMPTY_COUNTS)
        self.assertEqual(result["imports"], [])
        self.assertEqual(result["exports"], [])

    def test_type_import_export_are_inventoried(self) -> None:
        type_section = _section(1, b"\x01\x60\x00\x00")
        import_section = _section(2, b"\x01" + _name("env") + _name("log") + b"\x00\x00")
        export_section = _section(7, b"\x01" + _name("run") + b"\x00" + _u32(0))
        result = self._inspect(HEADER + type_section + import_section + export_section)

        self.assertEqual(result["counts"], {"types": 1, "imports": 1, "functions": 0,
                                            "exports": 1, "code": 0, "data": 0})
        self.assertEqual(result["imports"],
                         [{"module": "env", "name": "log", "kind": "func"}])
        self.assertEqual(result["exports"],
                         [{"name": "run", "kind": "func", "index": 0}])
        import_offset = 8 + len(type_section)
        export_offset = import_offset + len(import_section)
        self.assertEqual(result["sections"], [
            {"id": 1, "name": "type", "offset": 8, "size": len(type_section) - 2},
            {"id": 2, "name": "import", "offset": import_offset,
             "size": len(import_section) - 2},
            {"id": 7, "name": "export", "offset": export_offset,
             "size": len(export_section) - 2},
        ])

    def test_custom_section_is_named_custom(self) -> None:
        body = _name("name")
        result = self._inspect(HEADER + _section(0, body))
        self.assertEqual(result["sections"],
                         [{"id": 0, "name": "custom", "offset": 8, "size": len(body)}])
        self.assertEqual(result["counts"], EMPTY_COUNTS)

    def test_non_wasm_bytes_name_the_magic(self) -> None:
        with self.assertRaises(ValueError) as caught:
            self._inspect(b"NOTWASM\x00\x01")
        message = str(caught.exception)
        self.assertIn("0061736d", message)
        self.assertIn("4e4f5457", message)

    def test_section_size_past_end_of_file_raises_value_error(self) -> None:
        # Section id 1 at offset 8 declares 100 body bytes; only 2 are present.
        data = HEADER + b"\x01" + _u32(100) + b"\x60\x00"
        with self.assertRaises(ValueError) as caught:
            self._inspect(data)
        self.assertIn("offset 8", str(caught.exception))

    def test_truncated_and_oversized_leb_raise_value_error(self) -> None:
        with self.assertRaises(ValueError) as caught:
            self._inspect(HEADER + b"\x01\x80")
        self.assertIn("LEB", str(caught.exception))

        with self.assertRaises(ValueError) as caught:
            self._inspect(HEADER + b"\x01" + b"\x80" * 5)
        self.assertIn("5 bytes", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
