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


class RecordDecodeTest(unittest.TestCase):
    """Type and method records, decoded from the leader only.

    Type/method records were correctly left undecoded for a long time, because their layouts change
    between Unity releases: `customAttributeIndex` disappears at 24.1, `byrefTypeIndex` at 24.5,
    `ccwFunctionIndex` exists only 21..22. A full decode without a version table returns plausible
    garbage.

    But the *leader* is stable — `nameIndex` is the first word of both records in every version —
    and the record stride is derivable from the file itself rather than from a table. So names and
    namespaces can be reported for any version, which is the part an analyst greps for.

    **`nameIndex` is a byte offset, not an ordinal.** The reference implementation is explicit:

        public string GetStringFromIndex(uint index)
            => ReadStringToNull(header.stringOffset + index);

    My first version of this test built the fixture with ordinals, and the first version of the
    decoder read them as ordinals, so the two agreed and both were wrong. It surfaced only because
    the fixture's name/namespace pairs came back swapped — `Object.UnityEngine` for a type I had
    written as Object-in-System. A decoder and its test written from the same misunderstanding
    confirm each other; the fixture here is built from byte offsets so it cannot.

    Layouts are built at three real strides (v24.5 88/52, v27 104/44, v29 120/56) so the
    derivations are exercised rather than one hard-coded case passing by luck.
    """

    STRINGS = ["System", "Object", "UnityEngine", "MonoBehaviour", "PlayerController",
               "Update", "String", "Collections", "List`1", "Start", "Awake"]
    # (name, namespace) as *strings*, converted to byte offsets when the fixture is built.
    TYPES = [("Object", "System"), ("MonoBehaviour", "UnityEngine"),
             ("List`1", "Collections"), ("PlayerController", "UnityEngine")]
    METHODS = ["Update", "Start", "Awake", "Update", "Start", "Awake"]

    def _blob_and_offsets(self) -> tuple[bytes, dict[str, int]]:
        """Build the string table the way real metadata lays it out.

        The table begins with a NUL byte, so byte offset 0 resolves to the empty string. That is
        not a convention I invented: `GetStringFromIndex(index)` is
        `ReadStringToNull(header.stringOffset + index)` with no sentinel for zero, so offset 0 has
        to be a real string and the empty one is what sits there. A fixture that put a real name at
        offset 0 made offset 0 ambiguous and produced a decoder that special-cased it wrongly.
        """
        blob = b"\x00"
        offsets: dict[str, int] = {"": 0}
        for text in self.STRINGS:
            offsets[text] = len(blob)
            blob += text.encode() + b"\x00"
        return blob, offsets

    def _metadata(self, type_stride: int, method_stride: int, version: int = 24) -> bytes:
        import struct as _struct
        blob, offsets = self._blob_and_offsets()
        type_blob = b"".join(
            _struct.pack("<II", offsets[name], offsets.get(namespace, 0))
            + b"\x00" * (type_stride - 8) for name, namespace in self.TYPES)
        method_blob = b"".join(
            _struct.pack("<I", offsets[name]) + b"\x00" * (method_stride - 4)
            for name in self.METHODS)
        header = 296
        string_at = header
        type_at = string_at + len(blob)
        method_at = type_at + len(type_blob)
        raw = bytearray(method_at + len(method_blob))
        _struct.pack_into("<I", raw, 0x000, 0xFAB11BAF)
        _struct.pack_into("<I", raw, 0x004, version)
        _struct.pack_into("<I", raw, 0x018, string_at)
        _struct.pack_into("<I", raw, 0x01C, len(blob))
        _struct.pack_into("<I", raw, 0x030, method_at)
        _struct.pack_into("<I", raw, 0x034, len(method_blob))
        _struct.pack_into("<I", raw, 0x0A0, type_at)
        _struct.pack_into("<I", raw, 0x0A4, len(type_blob))
        raw[string_at:string_at + len(blob)] = blob
        raw[type_at:type_at + len(type_blob)] = type_blob
        raw[method_at:method_at + len(method_blob)] = method_blob
        return bytes(raw)

    def _inspect(self, raw: bytes) -> dict:
        import tempfile
        from pathlib import Path
        from xtforge.core.re import il2cpp
        directory = Path(tempfile.mkdtemp(prefix="xtil2rec-"))
        try:
            target = directory / "global-metadata.dat"
            target.write_bytes(raw)
            return il2cpp.inspect_il2cpp_metadata(target)
        finally:
            import shutil
            shutil.rmtree(directory, ignore_errors=True)

    def test_the_stride_is_derived_from_the_file_not_assumed(self) -> None:
        """Three real layouts, three derived strides.

        "First stride that divides the table evenly" picked the 8-byte leader and reported 44
        records of which 40 were noise; ranking by resolution *rate* picked a multiple of the real
        stride that sampled one record and scored 100%. Ranking by the *count* of records that land
        on a real string start is what makes all three land on the truth.
        """
        for type_stride, method_stride, version in ((88, 52, 24), (104, 44, 27), (120, 56, 29)):
            with self.subTest(type_stride=type_stride, method_stride=method_stride):
                report = self._inspect(self._metadata(type_stride, method_stride, version))
                self.assertEqual(report["type_records"]["record_stride"], type_stride)
                self.assertEqual(report["method_records"]["record_stride"], method_stride)

    def test_every_type_record_is_decoded_with_the_right_name(self) -> None:
        report = self._inspect(self._metadata(88, 52))
        names = [entry["full_name"] for entry in report["type_records"]["types"]]
        self.assertEqual(len(names), 4, names)
        # Namespace before name, as .NET renders a full type name. The record itself is
        # name-first: `nameIndex` is the leading word and `namespaceIndex` the second one.
        self.assertEqual(names, ["System.Object", "UnityEngine.MonoBehaviour",
                                 "Collections.List`1", "UnityEngine.PlayerController"])

    def test_name_and_namespace_are_not_swapped(self) -> None:
        """The exact symptom of reading a byte offset as an ordinal."""
        report = self._inspect(self._metadata(88, 52))
        first = report["type_records"]["types"][0]
        self.assertEqual(first["name"], "Object")
        self.assertEqual(first["namespace"], "System")

    def test_a_type_with_no_namespace_is_not_given_one(self) -> None:
        """Index 0 means 'none'; returning the blob's first string would invent a namespace."""
        import struct as _struct
        blob, offsets = self._blob_and_offsets()
        type_blob = _struct.pack("<II", offsets["Object"], 0) + b"\x00" * 80
        header = 296
        raw = bytearray(header + len(blob) + len(type_blob))
        _struct.pack_into("<I", raw, 0x000, 0xFAB11BAF)
        _struct.pack_into("<I", raw, 0x018, header)
        _struct.pack_into("<I", raw, 0x01C, len(blob))
        _struct.pack_into("<I", raw, 0x0A0, header + len(blob))
        _struct.pack_into("<I", raw, 0x0A4, len(type_blob))
        raw[header:header + len(blob)] = blob
        raw[header + len(blob):] = type_blob
        report = self._inspect(bytes(raw))
        types = report["type_records"]["types"]
        self.assertEqual(types[0]["namespace"], "")
        self.assertEqual(types[0]["full_name"], "Object",
                         "a type with no namespace must not gain a leading dot")

    def test_method_names_are_recovered_in_order(self) -> None:
        report = self._inspect(self._metadata(88, 52))
        names = [entry["name"] for entry in report["method_records"]["methods"]]
        self.assertEqual(names, self.METHODS)

    def test_a_garbage_stride_is_flagged_rather_than_reported_as_types(self) -> None:
        """When nothing lands on a string start, the output must not present it as a type list."""
        import struct as _struct
        header = 296
        junk = bytes((index * 37 + 11) % 251 + 1 for index in range(1024))
        raw = bytearray(header + 16 + len(junk))
        _struct.pack_into("<I", raw, 0x000, 0xFAB11BAF)
        _struct.pack_into("<I", raw, 0x018, header)
        _struct.pack_into("<I", raw, 0x01C, 16)
        _struct.pack_into("<I", raw, 0x0A0, header + 16)
        _struct.pack_into("<I", raw, 0x0A4, len(junk))
        raw[header:header + 16] = b"aaa\x00bbb\x00ccc\x00ddd\x00"
        raw[header + 16:] = junk
        report = self._inspect(bytes(raw))
        records = report["type_records"]
        self.assertTrue(records.get("warning") or records["type_count"] <= 1,
                       f"decoded {records['type_count']} types from noise without warning")

    def test_a_table_past_the_end_is_an_error_not_a_crash(self) -> None:
        import struct as _struct
        raw = bytearray(self._metadata(88, 52))
        _struct.pack_into("<I", raw, 0x0A0, len(raw) + 99999)
        report = self._inspect(bytes(raw))
        self.assertTrue(report["ok"])
        self.assertIn("error", report["type_records"])

    def test_a_file_with_no_type_table_says_so(self) -> None:
        import struct as _struct
        raw = bytearray(self._metadata(88, 52))
        _struct.pack_into("<I", raw, 0x0A0, 0)
        _struct.pack_into("<I", raw, 0x0A4, 0)
        report = self._inspect(bytes(raw))
        self.assertEqual(report["type_records"]["type_count"], 0)
        self.assertIn("no type definition table", report["type_records"]["note"])

    def test_a_nonzero_ordinal_is_not_treated_as_an_offset(self) -> None:
        """A record naming the 3rd string must resolve to it by its byte offset, and a bare
        ordinal of 2 must not silently mean the 3rd string."""
        import struct as _struct
        blob, offsets = self._blob_and_offsets()
        self.assertNotEqual(offsets["UnityEngine"], 2,
                            "the fixture must have a namespace whose offset is not its ordinal, "
                            "or this test cannot distinguish the two readings")
        type_blob = _struct.pack("<II", offsets["Object"], offsets["UnityEngine"]) + b"\x00" * 80
        header = 296
        raw = bytearray(header + len(blob) + len(type_blob))
        _struct.pack_into("<I", raw, 0x000, 0xFAB11BAF)
        _struct.pack_into("<I", raw, 0x018, header)
        _struct.pack_into("<I", raw, 0x01C, len(blob))
        _struct.pack_into("<I", raw, 0x0A0, header + len(blob))
        _struct.pack_into("<I", raw, 0x0A4, len(type_blob))
        raw[header:header + len(blob)] = blob
        raw[header + len(blob):] = type_blob
        report = self._inspect(bytes(raw))
        entry = report["type_records"]["types"][0]
        self.assertEqual(entry["namespace"], "UnityEngine")
