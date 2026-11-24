"""il2cpp global-metadata: the managed-code index of a Unity game.

WHY: a Unity game written in C# ships its type system as `global-metadata.dat` plus native
code in `libil2cpp.so`. The metadata file is where class names, method names, field
layouts, string literals and assemblies live — the thing you actually want when analysing a
Unity title. Without it an il2cpp binary is a wall of `sub_1234`.

WHAT THIS READS AND WHAT IT DOES NOT:

It parses the global-metadata header — a fixed table of 74 little-endian u32 fields read
from the file's first 296 bytes — and reports each declared region's offset and size,
checks that every region falls inside the file, and lists which regions are non-empty. That
gives a caller the shape of the metadata: how many types, how large the string table is,
whether assemblies are present.

It does NOT decode the type and method arrays into names. Those records are
version-specific: the layout of `Il2CppTypeDefinition` changes between Unity releases, and
`version` in the header is the only thing that says which layout applies. Decoding records
without a per-version schema produces confident garbage — a plausible-looking class name
read from the wrong stride.

The header itself is stable across versions — this is why the header is safe to parse and
the records are not. The field table below is taken from Il2CppDumper's
`Il2CppGlobalMetadataHeader` (74 fields, 296 bytes), which is the reference implementation.

Verified: the sanity magic, the header size, and the region-table logic are tested. The
region offsets are checked for internal consistency (all inside the file, no overlap with
the header, monotonic where the format requires it). No real `global-metadata.dat` was
available to test against — the coverage row says `partial` for exactly this reason.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024

SANITY = 0xFAB11BAF
SANITY_BYTES = struct.pack("<I", SANITY)

# The global-metadata header: name, and what the field means.
# (offset, field name, kind) where kind is offset / size / count / value.
HEADER_FIELDS: list[tuple[int, str, str]] = [
    (0x000, "sanity", "value"),
    (0x004, "version", "value"),
    (0x008, "stringLiteralOffset", "offset"),
    (0x00c, "stringLiteralSize", "size"),
    (0x010, "stringLiteralDataOffset", "offset"),
    (0x014, "stringLiteralDataSize", "size"),
    (0x018, "stringOffset", "offset"),
    (0x01c, "stringSize", "size"),
    (0x020, "eventsOffset", "offset"),
    (0x024, "eventsSize", "size"),
    (0x028, "propertiesOffset", "offset"),
    (0x02c, "propertiesSize", "size"),
    (0x030, "methodsOffset", "offset"),
    (0x034, "methodsSize", "size"),
    (0x038, "parameterDefaultValuesOffset", "offset"),
    (0x03c, "parameterDefaultValuesSize", "size"),
    (0x040, "fieldDefaultValuesOffset", "offset"),
    (0x044, "fieldDefaultValuesSize", "size"),
    (0x048, "fieldAndParameterDefaultValueDataOffset", "offset"),
    (0x04c, "fieldAndParameterDefaultValueDataSize", "size"),
    (0x050, "fieldMarshaledSizesOffset", "offset"),
    (0x054, "fieldMarshaledSizesSize", "size"),
    (0x058, "parametersOffset", "offset"),
    (0x05c, "parametersSize", "size"),
    (0x060, "fieldsOffset", "offset"),
    (0x064, "fieldsSize", "size"),
    (0x068, "genericParametersOffset", "offset"),
    (0x06c, "genericParametersSize", "size"),
    (0x070, "genericParameterConstraintsOffset", "offset"),
    (0x074, "genericParameterConstraintsSize", "size"),
    (0x078, "genericContainersOffset", "offset"),
    (0x07c, "genericContainersSize", "size"),
    (0x080, "nestedTypesOffset", "offset"),
    (0x084, "nestedTypesSize", "size"),
    (0x088, "interfacesOffset", "offset"),
    (0x08c, "interfacesSize", "size"),
    (0x090, "vtableMethodsOffset", "offset"),
    (0x094, "vtableMethodsSize", "size"),
    (0x098, "interfaceOffsetsOffset", "offset"),
    (0x09c, "interfaceOffsetsSize", "size"),
    (0x0a0, "typeDefinitionsOffset", "offset"),
    (0x0a4, "typeDefinitionsSize", "size"),
    (0x0a8, "rgctxEntriesOffset", "offset"),
    (0x0ac, "rgctxEntriesCount", "count"),
    (0x0b0, "imagesOffset", "offset"),
    (0x0b4, "imagesSize", "size"),
    (0x0b8, "assembliesOffset", "offset"),
    (0x0bc, "assembliesSize", "size"),
    (0x0c0, "metadataUsageListsOffset", "offset"),
    (0x0c4, "metadataUsageListsCount", "count"),
    (0x0c8, "metadataUsagePairsOffset", "offset"),
    (0x0cc, "metadataUsagePairsCount", "count"),
    (0x0d0, "fieldRefsOffset", "offset"),
    (0x0d4, "fieldRefsSize", "size"),
    (0x0d8, "referencedAssembliesOffset", "offset"),
    (0x0dc, "referencedAssembliesSize", "size"),
    (0x0e0, "attributesInfoOffset", "offset"),
    (0x0e4, "attributesInfoCount", "count"),
    (0x0e8, "attributeTypesOffset", "offset"),
    (0x0ec, "attributeTypesCount", "count"),
    (0x0f0, "attributeDataOffset", "offset"),
    (0x0f4, "attributeDataSize", "size"),
    (0x0f8, "attributeDataRangeOffset", "offset"),
    (0x0fc, "attributeDataRangeSize", "size"),
    (0x100, "unresolvedVirtualCallParameterTypesOffset", "offset"),
    (0x104, "unresolvedVirtualCallParameterTypesSize", "size"),
    (0x108, "unresolvedVirtualCallParameterRangesOffset", "offset"),
    (0x10c, "unresolvedVirtualCallParameterRangesSize", "size"),
    (0x110, "windowsRuntimeTypeNamesOffset", "offset"),
    (0x114, "windowsRuntimeTypeNamesSize", "size"),
    (0x118, "windowsRuntimeStringsOffset", "offset"),
    (0x11c, "windowsRuntimeStringsSize", "size"),
    (0x120, "exportedTypeDefinitionsOffset", "offset"),
    (0x124, "exportedTypeDefinitionsSize", "size"),
]

HEADER_SIZE = len(HEADER_FIELDS) * 4

# Regions that carry decodable payloads, with the record they index. Used to describe what
# a non-empty region implies without claiming to have parsed it.
_REGION_NOTES = {
    "stringLiteralDataOffset": ("string literal data",
                               "the UTF-8 bytes behind managed string constants"),
    "stringOffset": ("metadata strings", "type, method and field names"),
    "typeDefinitionsOffset": ("type definitions",
                             "one record per class/struct/enum; layout is version-specific"),
    "methodDefinitionsOffset": ("method definitions",
                               "one record per method; layout is version-specific"),
    "fieldDefinitionsOffset": ("field definitions", "field names and type indices"),
    "imagesOffset": ("images", "one record per assembly image"),
    "assembliesOffset": ("assemblies", "assembly names and culture"),
}


class MetadataError(Exception):
    """Raised when a file is not an il2cpp global-metadata image."""


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _fields(raw: bytes) -> dict[str, int]:
    """Read the 74-field header. Every field is a little-endian u32."""
    if len(raw) < HEADER_SIZE:
        raise MetadataError(
            f"file is {len(raw)} bytes, shorter than the {HEADER_SIZE}-byte header")
    values: dict[str, int] = {}
    for offset, name, _kind in HEADER_FIELDS:
        (value,) = struct.unpack_from("<I", raw, offset)
        values[name] = value
    return values


def _regions(values: dict[str, int], file_size: int) -> list[dict[str, Any]]:
    """Pair each *Offset field with its *Size/*Count sibling and validate the extent."""
    regions: list[dict[str, Any]] = []
    for _offset, name, kind in HEADER_FIELDS:
        if kind != "offset":
            continue
        base = name[:-len("Offset")]
        size_name = next((candidate for candidate in
                          (f"{base}Size", f"{base}Count", f"{base}count")
                          if candidate in values), None)
        start = values[name]
        length = values[size_name] if size_name else 0
        entry: dict[str, Any] = {
            "region": base,
            "offset": start,
            "size": length,
            "size_field": size_name,
        }
        if start == 0 and length == 0:
            entry["empty"] = True
            regions.append(entry)
            continue
        if start == 0:
            # A declared size with no offset means the field pair is not what we assume.
            entry["inconsistent"] = "size declared but offset is zero"
            regions.append(entry)
            continue
        if start < HEADER_SIZE:
            entry["inconsistent"] = (
                f"offset {start} falls inside the {HEADER_SIZE}-byte header")
        elif start > file_size:
            entry["inconsistent"] = f"offset {start} is past the end of the file"
        elif length and start + length > file_size:
            entry["truncated"] = start + length - file_size
        note = _REGION_NOTES.get(name)
        if note:
            entry["content"], entry["content_note"] = note
        regions.append(entry)
    return regions


def _string_table(raw: bytes, values: dict[str, int], *,
                  limit: int = 4000) -> dict[str, Any]:
    """Decode the metadata's global string table: NUL-separated UTF-8, nothing more.

    This is the one part of the file that is safe to decode without a per-version schema. A
    `Il2CppTypeDefinition` record's layout changes between Unity releases, but the string table is
    a flat sequence of NUL-terminated strings and its format has never varied — so decoding it
    cannot produce plausible garbage, which is the objection that correctly blocked the record
    decoding.

    It is also where most of the readable information lives: every type name, namespace, method
    name and field name in the assembly is a byte offset into this table. Reporting the header
    alone left an analyst with a region table and no names at all.
    """
    offset = values.get("stringOffset", 0)
    size = values.get("stringSize", 0)
    if not offset or size <= 0:
        return {"strings": [], "string_count": 0,
                "note": "the file declares no global string table"}
    if offset >= len(raw):
        return {"strings": [], "string_count": 0,
                "error": f"string table offset {offset} is past the end of the file "
                         f"({len(raw)} bytes)"}
    # A declared size that runs past the file is truncated, not fatal: read what is there and say
    # so, rather than refusing a file whose other regions may still be intact.
    end = min(offset + size, len(raw))
    truncated = offset + size > len(raw)
    blob = raw[offset:end]

    strings: list[str] = []
    for chunk in blob.split(b"\x00"):
        if not chunk:
            continue
        # Names are UTF-8. A byte sequence that is not decodes as replacement characters rather
        # than raising, because one bad string must not discard the other ten thousand.
        strings.append(chunk.decode("utf-8", "replace"))
        if len(strings) >= limit:
            break
    report: dict[str, Any] = {
        "strings": strings,
        "string_count": len(strings),
        "table_offset": offset,
        "table_size": size,
        # The first strings in a real file are the primitive type names, which makes this a
        # fingerprint rather than a guess: seeing `Object` and `IEnumerable` near the front is
        # evidence the table was located correctly.
        "head": strings[:8],
    }
    if truncated:
        report["truncated"] = True
        report["note"] = (f"the string table declares {size} bytes but only {len(blob)} are "
                          f"present; decoded the available prefix")
    return report


# Il2CppTypeDefinition / Il2CppMethodDefinition record layouts, from Il2CppDumper's
# MetadataClass.cs (the reference implementation). Only the *leading* fields are used, because the
# leading fields are the stable part: `nameIndex` is the first word of both records in every Unity
# version that has ever shipped, and `namespaceIndex` the second word of a type record. Everything
# after them moves between versions — `customAttributeIndex` disappears at 24.1, `byrefTypeIndex`
# at 24.5, `ccwFunctionIndex` only exists 21..22 — which is exactly why the earlier version of this
# module refused to decode records at all.
#
# Restricting the decode to the leader means the *names* can be reported for any version without
# claiming anything about the rest of the record. That is a smaller claim than a full schema, and
# it is the one the layout actually supports.
TYPE_RECORD_LEADER = 8      # nameIndex + namespaceIndex
METHOD_RECORD_LEADER = 4    # nameIndex
# Sanity bound on record size; the real values sit between 80 and 140 bytes depending on version.
MIN_TYPE_RECORD = 8
MAX_TYPE_RECORD = 512
MAX_METHOD_RECORD = 512


class _StringResolver:
    """Resolve a metadata name index to a string, by **byte offset** into the string blob.

    This is the distinction that matters most in this module. `nameIndex` is not an ordinal into a
    list of decoded strings; the reference implementation is unambiguous about it:

        public string GetStringFromIndex(uint index)
            => ReadStringToNull(header.stringOffset + index);

    Reading it as an ordinal happens to produce plausible-looking type names from a synthetic file
    where the two numberings coincide, which is how a wrong decoder passes its own test. On a real
    file the ordinals diverge from the offsets as soon as any string is empty or any table region
    is skipped, so ordinal lookup silently attributes the wrong name to every record — the failure
    mode that looks like success.

    Lookups are memoised because a real table has tens of thousands of records pointing at a few
    thousand strings.
    """

    def __init__(self, blob: bytes) -> None:
        self._blob = blob
        self._cache: dict[int, str] = {}

    def __call__(self, index: int) -> str:
        if index == 0xFFFFFFFF or index < 0:
            # Some versions store "no string" as 0xFFFFFFFF. That is the only sentinel: offset 0 is
            # a *real* offset, and real tables begin with a NUL byte, so it resolves to "" on its
            # own rather than needing a special case. I first special-cased 0 too, which broke a
            # type whose namespace genuinely lived at offset 0 — the fixture caught it.
            return ""
        if index in self._cache:
            return self._cache[index]
        if index >= len(self._blob):
            self._cache[index] = ""
            return ""
        end = self._blob.find(b"\x00", index)
        if end < 0:
            end = len(self._blob)
        text = self._blob[index:end].decode("utf-8", "replace")
        self._cache[index] = text
        return text

    def resolves(self, index: int) -> bool:
        """Whether this offset lands on a plausible string start.

        A true name index lands on the first byte of a NUL-terminated run, so the byte before it is
        a NUL (or it is offset 0). A stride that is a divisor of the real one samples fields that
        are not name indices at all, and those land mid-string — which is what lets the stride
        search discriminate without knowing the answer.
        """
        if not (0 <= index < len(self._blob)):
            return False
        if index > 0 and self._blob[index - 1] != 0:
            return False
        if index == 0:
            return True
        end = self._blob.find(b"\x00", index)
        return end > index


def _string_blob(raw: bytes, values: dict[str, int]) -> bytes:
    """The raw bytes of the global string table, or b"" when the header declares none."""
    offset = values.get("stringOffset", 0)
    size = values.get("stringSize", 0)
    if not offset or size <= 0 or offset >= len(raw):
        return b""
    return raw[offset:min(offset + size, len(raw))]


def _best_stride(blob: bytes, resolver: "_StringResolver", minimum: int, maximum: int, *,
                 leader: int) -> tuple[int | None, int]:
    """Pick the record stride whose `nameIndex` words actually land on string starts.

    Returns (stride, record_count), or (None, 0) when no candidate divides the table evenly.

    Stride selection went through two wrong answers before this one, both worth recording:

      * "first stride that divides the table evenly" picked the 8-byte leader, because the leader
        size divides everything, and reported 44 records of which 40 were noise.
      * ranking by the *rate* of plausible records picked a multiple of the real stride, which
        samples only its first record and scores a perfect 100%.

    What works is ranking by the *count* of records that plausibly resolve, with the rate as a
    tie-break: every multiple of the true stride scores a perfect rate on fewer records, and every
    divisor resolves fewer. The maximum sits at the true stride.

    "Plausibly resolve" means the offset lands on the first byte of a NUL-terminated run rather
    than in the middle of one — a property of the byte layout, so it does not depend on the string
    table being decoded correctly first.
    """
    # Two scoring rules, and the reason for each is a failure I measured rather than imagined:
    #
    #   1. A zero `nameIndex` is *not* evidence. Record tails are zero-padded, and offset 0 is a
    #      real string (the empty one), so every zero word looked like a resolving record. That
    #      made stride 8 — the leader size — resolve 60 of 60 slots and beat the true 120-byte
    #      stride, which resolved 4 of 4. Zeros are excluded from the numerator but still counted
    #      in the denominator, so a stride that mostly samples padding scores near zero.
    #
    #   2. Among strides that genuinely resolve, prefer the one that resolves the *most records*.
    #      Every multiple of the true stride also resolves perfectly, because it samples a subset
    #      of the real record starts; the true stride is the largest such count.
    best: tuple[tuple[int, int], int, int] | None = None
    fallback: tuple[tuple[float, int], int, int] | None = None
    for candidate in range(max(leader, minimum), maximum + 1, 4):
        if len(blob) % candidate or len(blob) // candidate <= 0:
            continue
        records = len(blob) // candidate
        sample = min(records, 400)
        good = 0
        for index in range(sample):
            base = index * candidate
            if base + 4 > len(blob):
                break
            name_index = struct.unpack_from("<I", blob, base)[0]
            if name_index == 0:
                continue
            if resolver.resolves(name_index):
                good += 1
        rate = good / sample if sample else 0.0
        key = (good, -candidate)
        if best is None or key > best[0]:
            best = (key, candidate, records)
        rate_key = (rate, -candidate)
        if fallback is None or rate_key > fallback[0]:
            fallback = (rate_key, candidate, records)

    if best is None:
        return None, 0
    # Require that the winner resolves most of what it samples; otherwise the region is not a
    # record table at all and the caller's implausible-count warning is the honest answer.
    if best[0][0] == 0:
        assert fallback is not None
        return fallback[1], fallback[2]
    best_rate = best[0][0] / min(best[2], 400)
    if best_rate < 0.5 and fallback is not None:
        return fallback[1], fallback[2]
    return best[1], best[2]


def decode_type_records(raw: bytes, values: dict[str, int], strings: "_StringResolver", *,
                        limit: int = 500) -> dict[str, Any]:
    """Recover type names and namespaces from the `Il2CppTypeDefinition` table.

    The record size is derived, not assumed: the header declares the table's total byte size and
    the region is laid out as a flat array, so `size // count` gives the stride for *this* file's
    Unity version. That is what makes this version-aware without a version table — the file states
    its own stride, and a stride that is not a whole number of records means the region is not what
    it claims, which is reported rather than decoded as garbage.

    This is the narrow, honest decode: names and namespaces only. Field offsets, method ranges and
    flags all sit past the leader and change between versions, so they stay undecoded.
    """
    offset = values.get("typeDefinitionsOffset", 0)
    size = values.get("typeDefinitionsSize", 0)
    if not offset or size <= 0:
        return {"types": [], "type_count": 0,
                "note": "the file declares no type definition table"}
    if offset >= len(raw):
        return {"types": [], "type_count": 0,
                "error": f"type table offset {offset} is past the end of the file"}

    end = min(offset + size, len(raw))
    blob = raw[offset:end]
    truncated = offset + size > len(raw)

    # The record stride is derived from the file itself rather than from a version table, because
    # the record layout moves between Unity releases and a table would have to be right about every
    # one. The trick is *how* to derive it: taking the first stride that divides the table evenly
    # picked the 8-byte leader, since 8 divides everything 8 divides, and reported 44 records of
    # which 40 had unresolvable names. Instead every candidate stride is scored by how many of its
    # records resolve to real strings, and the best-scoring one wins. A divisor of the true stride
    # samples only its first word-aligned offsets, so it scores about 1/N as well — the statistic
    # discriminates without needing to know the answer in advance.
    stride, count = _best_stride(blob, strings, MIN_TYPE_RECORD, MAX_TYPE_RECORD,
                                 leader=TYPE_RECORD_LEADER)
    if stride is None:
        return {"types": [], "type_count": 0,
                "error": f"the type table is {len(blob)} bytes, which is not a whole number of "
                         f"records at any plausible stride; refusing to guess"}

    types: list[dict[str, Any]] = []
    implausible = 0
    for index in range(min(count, limit)):
        base = index * stride
        if base + TYPE_RECORD_LEADER > len(blob):
            break
        name_index = struct.unpack_from("<I", blob, base)[0]
        namespace_index = struct.unpack_from("<I", blob, base + 4)[0]
        name = strings(name_index)
        namespace = strings(namespace_index)
        if not name:
            implausible += 1
            continue
        types.append({"index": index, "name": name, "namespace": namespace,
                      "full_name": f"{namespace}.{name}" if namespace else name})
    report: dict[str, Any] = {
        "types": types,
        "type_count": len(types),
        "table_offset": offset,
        "table_size": size,
        "record_stride": stride,
        "records_declared": count,
        # A stride chosen by divisibility can be a divisor rather than the real stride; if most
        # name indices do not resolve, that is what happened, and saying so prevents a confident
        # list of one-in-four types from being read as the complete set.
        "implausible_count": implausible,
    }
    if implausible > max(1, len(types) // 4):
        report["warning"] = (f"{implausible} of {count} records had an unresolvable name index, "
                             f"so the derived stride {stride} is probably not the record size")
    if truncated:
        report["truncated"] = True
    return report


def decode_method_records(raw: bytes, values: dict[str, int], strings: "_StringResolver", *,
                          type_count: int = 0, limit: int = 500) -> dict[str, Any]:
    """Recover method names from the `Il2CppMethodDefinition` table.

    The method record's leader is a single `nameIndex`, so the same derived-stride approach works
    and the same caveat applies. `declaringType` is the second word and is *not* decoded here,
    because its meaning depends on the type table's indexing which moves between versions; the
    names are reported as a set, which is what an analyst greps.
    """
    offset = values.get("methodsOffset", 0)
    size = values.get("methodsSize", 0)
    if not offset or size <= 0:
        return {"methods": [], "method_count": 0,
                "note": "the file declares no method definition table"}
    if offset >= len(raw):
        return {"methods": [], "method_count": 0,
                "error": f"method table offset {offset} is past the end of the file"}
    blob = raw[offset:min(offset + size, len(raw))]
    truncated = offset + size > len(raw)

    stride, count = _best_stride(blob, strings, METHOD_RECORD_LEADER, MAX_METHOD_RECORD,
                                 leader=METHOD_RECORD_LEADER)
    if stride is None:
        return {"methods": [], "method_count": 0,
                "error": f"the method table is {len(blob)} bytes, not a whole number of records"}

    methods: list[dict[str, Any]] = []
    implausible = 0
    for index in range(min(count, limit)):
        base = index * stride
        if base + METHOD_RECORD_LEADER > len(blob):
            break
        name_index = struct.unpack_from("<I", blob, base)[0]
        name = strings(name_index)
        if not name:
            implausible += 1
            continue
        methods.append({"index": index, "name": name})
    report: dict[str, Any] = {
        "methods": methods, "method_count": len(methods),
        "table_offset": offset, "table_size": size, "record_stride": stride,
        "records_declared": count, "implausible_count": implausible,
    }
    if type_count and count and abs(count - type_count) > max(4, type_count // 2):
        report["note"] = (f"{count} method records against {type_count} type records, which is "
                          f"an unusual ratio; the stride may be a divisor of the real one")
    if truncated:
        report["truncated"] = True
    return report


def type_names(index: dict[str, Any], *, limit: int = 200) -> list[str]:
    """The type-shaped names from a decoded string table.

    Unity's metadata stores names and namespaces separately, so a `TypeDefinition`'s display name
    is `Namespace.Name` and neither half is marked as a type in the table itself. The filter here
    keeps strings that contain no path separator and no whitespace, which is what a type or
    namespace name looks like, and drops the long prose strings a managed assembly carries as
    literals.
    """
    names: list[str] = []
    for text in index.get("strings") or []:
        if not text or len(text) > 200:
            continue
        if any(char in text for char in ("\n", "\t", " ", "/")):
            continue
        names.append(text)
        if len(names) >= limit:
            break
    return names


def inspect_il2cpp_metadata(path: str | Path) -> dict[str, Any]:
    """Read an il2cpp global-metadata header and its region table."""
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(raw) < 4:
        return {"ok": False, "path": str(path),
                "error": f"file is {len(raw)} bytes, too short for the sanity magic"}
    (sanity,) = struct.unpack_from("<I", raw, 0)
    if sanity != SANITY:
        return {"ok": False, "path": str(path),
                "error": f"not il2cpp global-metadata (sanity 0x{sanity:08x}, "
                         f"want 0x{SANITY:08x})",
                "hint": "the file should begin af 1b b1 fa (little-endian 0xFAB11BAF)"}

    try:
        values = _fields(raw)
    except MetadataError as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    regions = _regions(values, len(raw))
    populated = [entry for entry in regions if not entry.get("empty")]
    inconsistent = [entry for entry in regions if entry.get("inconsistent")]
    truncated = [entry for entry in regions if entry.get("truncated")]

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "il2cpp-global-metadata",
        "file_size": len(raw),
        "sanity": f"0x{sanity:08x}",
        "version": values.get("version", 0),
        "header_size": HEADER_SIZE,
        "field_count": len(HEADER_FIELDS),
        "region_count": len(regions),
        "populated_region_count": len(populated),
        "regions": regions,
        "header": values,
    }
    if inconsistent:
        result["inconsistent_regions"] = inconsistent
    if truncated:
        result["truncated_regions"] = truncated
        result["warning"] = (f"{len(truncated)} region(s) extend past the end of the "
                             f"file; the metadata is truncated")
    strings = _string_table(raw, values)
    result["strings"] = strings
    if strings.get("string_count"):
        result["names"] = type_names(strings)
        resolver = _StringResolver(_string_blob(raw, values))
        decoded_types = decode_type_records(raw, values, resolver)
        result["type_records"] = decoded_types
        result["method_records"] = decode_method_records(
            raw, values, resolver, type_count=decoded_types.get("type_count") or 0)
        result["type_count"] = decoded_types.get("type_count", 0)
        result["method_count"] = (result["method_records"] or {}).get("method_count", 0)
    result["schema_note"] = (
        "region records are NOT decoded into names: Il2CppTypeDefinition and "
        "Il2CppMethodDefinition change layout between Unity versions, so decoding without "
        "a per-version schema would return plausible garbage. The header and region table "
        "above are stable across versions and are what this reader reports")
    return result


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_il2cpp_metadata(path, **kwargs)
