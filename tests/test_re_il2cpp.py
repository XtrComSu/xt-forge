"""Tests for the il2cpp global-metadata reader.

**These tests are weaker than the rest of the RE suite, and the reason matters.**

Every other format in `xtforge/core/re/` is verified against a real artifact produced by the
authoritative tool: OVMF for firmware, Swift 6.0.3 for Swift, Dart 3.14.1 for Dart, a real
`Assets.car` for BOM, `mkntfs` for NTFS. No real `global-metadata.dat` was reachable from
this host — Unity does not distribute one, and the public il2cpp tools do not ship fixtures.

So what is asserted here is what can be asserted without a real file:

  * The header layout is **74 fields, 296 bytes**, taken from Il2CppDumper's reference
    implementation rather than invented. That count is pinned: if someone miscounts the
    field table, the header size changes and the test fails.
  * The sanity magic and its little-endian byte order.
  * The region-pairing logic: `*Offset` with its `*Size`/`*Count` sibling, including the
    cases that matter — a region inside the header, a region past EOF, a declared size with
    a zero offset, and a truncated region.
  * Graceful handling of non-metadata and malformed input.

What is NOT asserted, because it cannot be: that these regions match Unity's output. That
gap is why the coverage row is `partial`. If a real `global-metadata.dat` becomes available,
the first thing to add is a region-boundary comparison against Il2CppDumper's own output.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import il2cpp

SANITY = 0xFAB11BAF
HEADER_SIZE = 296


def build_header(**overrides: int) -> bytearray:
    """A 296-byte header with the sanity magic and caller-set fields."""
    header = bytearray(HEADER_SIZE)
    struct.pack_into("<I", header, 0, SANITY)
    struct.pack_into("<i", header, 4, 24)
    field_offsets = {name: offset for offset, name, _kind in il2cpp.HEADER_FIELDS}
    for name, value in overrides.items():
        if name not in field_offsets:
            raise KeyError(f"unknown header field {name!r}")
        struct.pack_into("<I", header, field_offsets[name], value)
    return header


def _decode(blob: bytes) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "global-metadata.dat"
        path.write_bytes(blob)
        return il2cpp.inspect_il2cpp_metadata(path)


class HeaderLayoutTest(unittest.TestCase):
    def test_header_is_74_fields_and_296_bytes(self) -> None:
        """The size is derived from the field table, so a miscount changes it."""
        self.assertEqual(len(il2cpp.HEADER_FIELDS), 74)
        self.assertEqual(il2cpp.HEADER_SIZE, HEADER_SIZE)

    def test_offsets_are_contiguous_u32_slots(self) -> None:
        for index, (offset, _name, _kind) in enumerate(il2cpp.HEADER_FIELDS):
            self.assertEqual(offset, index * 4)

    def test_sanity_and_version_are_the_first_two_fields(self) -> None:
        self.assertEqual(il2cpp.HEADER_FIELDS[0][1], "sanity")
        self.assertEqual(il2cpp.HEADER_FIELDS[1][1], "version")

    def test_field_names_are_unique(self) -> None:
        names = [name for _o, name, _k in il2cpp.HEADER_FIELDS]
        self.assertEqual(len(names), len(set(names)))


class ParseTest(unittest.TestCase):
    def test_minimal_header_parses(self) -> None:
        report = _decode(bytes(build_header()))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["sanity"], "0xfab11baf")
        self.assertEqual(report["version"], 24)
        self.assertEqual(report["header_size"], HEADER_SIZE)

    def test_version_is_read_little_endian(self) -> None:
        header = build_header()
        struct.pack_into("<i", header, 4, 31)
        report = _decode(bytes(header))
        self.assertEqual(report["version"], 31)

    def test_wrong_sanity_is_rejected(self) -> None:
        header = build_header()
        struct.pack_into("<I", header, 0, 0xDEADBEEF)
        report = _decode(bytes(header))
        self.assertFalse(report["ok"])
        self.assertIn("not il2cpp global-metadata", report["error"])
        self.assertIn("hint", report)

    def test_truncated_header_is_rejected(self) -> None:
        report = _decode(struct.pack("<I", SANITY) + bytes(64))
        self.assertFalse(report["ok"])
        self.assertIn("shorter than", report["error"])

    def test_tiny_file_is_rejected(self) -> None:
        report = _decode(b"\xaf")
        self.assertFalse(report["ok"])

    def test_empty_file_is_rejected(self) -> None:
        report = _decode(b"")
        self.assertFalse(report["ok"])

    def test_missing_file_reports_error(self) -> None:
        report = il2cpp.inspect_il2cpp_metadata("/nonexistent/global-metadata.dat")
        self.assertFalse(report["ok"])


class RegionTest(unittest.TestCase):
    """The region table is the part that can be verified without a real artifact."""

    def test_populated_region_is_reported(self) -> None:
        header = build_header(stringOffset=HEADER_SIZE, stringSize=64)
        report = _decode(bytes(header) + bytes(64))
        self.assertTrue(report["ok"], report.get("error"))
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertFalse(string.get("empty"))
        self.assertEqual(string["offset"], HEADER_SIZE)
        self.assertEqual(string["size"], 64)

    def test_zero_pairs_are_marked_empty(self) -> None:
        report = _decode(bytes(build_header()))
        self.assertTrue(all(entry.get("empty") for entry in report["regions"]))
        self.assertEqual(report["populated_region_count"], 0)

    def test_region_inside_the_header_is_inconsistent(self) -> None:
        """An offset below 296 would read the header as payload."""
        header = build_header(stringOffset=16, stringSize=32)
        report = _decode(bytes(header) + bytes(64))
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertIn("inconsistent", string)
        self.assertIn("header", string["inconsistent"])
        self.assertIn("inconsistent_regions", report)

    def test_region_starting_past_eof_is_inconsistent(self) -> None:
        """An offset beyond the file cannot be payload."""
        header = build_header(stringOffset=100000, stringSize=10)
        report = _decode(bytes(header) + bytes(16))
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertIn("inconsistent", string)
        self.assertIn("past the end", string["inconsistent"])

    def test_region_ending_past_eof_is_truncated(self) -> None:
        """An offset inside the file with a size that overruns it is truncated, not valid.

        These are different faults and a reader must not conflate them: a bad offset means
        the header is not what we think, while a truncated extent means the file was cut
        short. Start 300 size 10 with a 312-byte file fits, so the size here must overrun.
        """
        header = build_header(stringOffset=300, stringSize=64)
        report = _decode(bytes(header) + bytes(12))  # 308 bytes total
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertNotIn("inconsistent", string)
        self.assertIn("truncated", string)
        self.assertEqual(string["truncated"], 300 + 64 - 308)

    def test_region_that_exactly_fits_is_not_truncated(self) -> None:
        """Boundary: start + size == file_size is a complete region."""
        header = build_header(stringOffset=300, stringSize=12)
        report = _decode(bytes(header) + bytes(16))  # 312 bytes total: 300 + 12 == 312
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertNotIn("truncated", string)
        self.assertNotIn("inconsistent", string)

    def test_size_without_offset_is_inconsistent(self) -> None:
        header = build_header(stringSize=64)
        report = _decode(bytes(header) + bytes(128))
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertIn("inconsistent", string)

    def test_truncated_region_is_flagged(self) -> None:
        """A region that starts in the file but runs past its end must be flagged."""
        header = build_header(stringOffset=300, stringSize=1000)
        report = _decode(bytes(header) + bytes(100))
        string = next(entry for entry in report["regions"]
                      if entry["region"] == "string")
        self.assertIn("truncated", string)
        self.assertGreater(string["truncated"], 0)
        self.assertIn("warning", report)

    def test_region_count_matches_the_offset_fields(self) -> None:
        report = _decode(bytes(build_header()))
        declared = sum(1 for _o, _n, kind in il2cpp.HEADER_FIELDS if kind == "offset")
        self.assertEqual(report["region_count"], declared)

    def test_count_suffixed_sibling_is_found(self) -> None:
        """Some regions pair Offset with Count, not Size (rgctxEntries, usage lists)."""
        names = [name for _o, name, kind in il2cpp.HEADER_FIELDS if kind == "offset"]
        self.assertIn("rgctxEntries", [n[:-len("Offset")] for n in names])
        report = _decode(bytes(build_header(rgctxEntriesOffset=300,
                                            rgctxEntriesCount=40)) + bytes(200))
        region = next(entry for entry in report["regions"]
                      if entry["region"] == "rgctxEntries")
        self.assertEqual(region["size"], 40)
        self.assertEqual(region["size_field"], "rgctxEntriesCount")


class HonestyTest(unittest.TestCase):
    def test_schema_note_states_what_is_not_decoded(self) -> None:
        """The result must say it did not decode type records.

        A caller who reads "region table present, 4000 types" without this note could
        reasonably think the type names were recovered.
        """
        report = _decode(bytes(build_header()))
        self.assertIn("schema_note", report)
        self.assertIn("NOT decoded", report["schema_note"])

    def test_result_is_json_serialisable(self) -> None:
        import json
        json.dumps(_decode(bytes(build_header(stringOffset=296, stringSize=8)) + bytes(8)))

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(24601)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(15):
                blob = root / f"r{index}.dat"
                payload = bytearray(bytes(random.randrange(256)
                                          for _ in range(random.randint(0, 700))))
                # Half get the correct magic, so the truncation paths are exercised.
                if payload[:4] and index % 2 == 0:
                    payload[0:4] = struct.pack("<I", SANITY)
                blob.write_bytes(bytes(payload))
                try:
                    il2cpp.inspect_il2cpp_metadata(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()


class StringTableTest(unittest.TestCase):
    """The global string table: the one part of the file decodable without a per-version schema.

    Type and method records were correctly left undecoded — their layouts change between Unity
    releases, and a decoder without the right schema returns plausible garbage. The string table
    is different: it is a flat sequence of NUL-terminated UTF-8 and has never varied, so decoding
    it is sound. It is also where the names are, and reporting only the header left an analyst
    with a region table and nothing readable.
    """

    NAMES = ["Object", "ValueType", "Attribute", "Enum", "String", "IEnumerable",
             "UnityEngine", "MonoBehaviour", "GameObject", "Update", "PlayerController",
             "A fairly long prose string that is a literal rather than a type name"]

    def _metadata(self, names: list[str] | None = None, *, declare: int | None = None) -> bytes:
        import struct as _struct
        blob = b"".join(name.encode() + b"\x00" for name in (names or self.NAMES))
        header = 296
        raw = bytearray(header + len(blob))
        _struct.pack_into("<I", raw, 0x000, 0xFAB11BAF)
        _struct.pack_into("<I", raw, 0x004, 29)
        _struct.pack_into("<I", raw, 0x018, header)
        _struct.pack_into("<I", raw, 0x01C, len(blob) if declare is None else declare)
        raw[header:header + len(blob)] = blob
        return bytes(raw)

    def _inspect(self, raw: bytes) -> dict:
        import tempfile
        from pathlib import Path
        from xtforge.core.re import il2cpp
        directory = Path(tempfile.mkdtemp(prefix="xtil2cpp-"))
        try:
            target = directory / "global-metadata.dat"
            target.write_bytes(raw)
            return il2cpp.inspect_il2cpp_metadata(target)
        finally:
            import shutil
            shutil.rmtree(directory, ignore_errors=True)

    def test_the_table_decodes_in_order(self) -> None:
        report = self._inspect(self._metadata())
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["strings"]["string_count"], len(self.NAMES))
        self.assertEqual(report["strings"]["head"][:4],
                         ["Object", "ValueType", "Attribute", "Enum"])

    def test_the_head_is_the_real_unity_fingerprint(self) -> None:
        """A located table starts with the primitives, so this distinguishes located from lucky."""
        report = self._inspect(self._metadata())
        self.assertIn("Object", report["strings"]["head"])
        self.assertIn("IEnumerable", report["strings"]["head"])

    def test_names_exclude_prose_literals(self) -> None:
        report = self._inspect(self._metadata())
        names = report["names"]
        self.assertIn("PlayerController", names)
        self.assertNotIn("A fairly long prose string that is a literal rather than a type name",
                         names,
                         "a prose literal was reported as a type name")

    def test_a_truncated_table_is_reported_not_refused(self) -> None:
        """The other regions may still be intact, so refusing the whole file would lose them."""
        full = self._metadata()
        report = self._inspect(full[:296 + 20])
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(report["strings"].get("truncated"), report["strings"])
        self.assertIn("only", report["strings"].get("note", ""))

    def test_an_offset_past_the_end_is_an_error_not_a_crash(self) -> None:
        import struct as _struct
        raw = bytearray(self._metadata())
        _struct.pack_into("<I", raw, 0x018, len(raw) + 5000)
        report = self._inspect(bytes(raw))
        self.assertTrue(report["ok"], "the header is still readable")
        self.assertIn("error", report["strings"])

    def test_a_missing_table_is_reported_as_absent(self) -> None:
        import struct as _struct
        raw = bytearray(self._metadata())
        _struct.pack_into("<I", raw, 0x018, 0)
        _struct.pack_into("<I", raw, 0x01C, 0)
        report = self._inspect(bytes(raw))
        self.assertEqual(report["strings"]["string_count"], 0)
        self.assertIn("no global string table", report["strings"]["note"])

    def test_a_bad_byte_does_not_discard_the_neighbours(self) -> None:
        """One invalid sequence must not throw away the other ten thousand strings."""
        blob = b"Good\x00Bad\xff\xfeName\x00AlsoGood\x00"
        import struct as _struct
        raws = bytearray(296 + len(blob))
        _struct.pack_into("<I", raws, 0x000, 0xFAB11BAF)
        _struct.pack_into("<I", raws, 0x018, 296)
        _struct.pack_into("<I", raws, 0x01C, len(blob))
        raws[296:] = blob
        report = self._inspect(bytes(raws))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("Good", report["strings"]["strings"])
        self.assertIn("AlsoGood", report["strings"]["strings"])

    def test_a_single_huge_string_is_not_mistaken_for_a_type_name(self) -> None:
        report = self._inspect(self._metadata(["A" * 500, "RealType"]))
        self.assertNotIn("A" * 500, report["names"])
        self.assertIn("RealType", report["names"])
