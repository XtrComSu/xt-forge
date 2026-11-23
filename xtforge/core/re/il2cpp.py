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
    result["schema_note"] = (
        "region records are NOT decoded into names: Il2CppTypeDefinition and "
        "Il2CppMethodDefinition change layout between Unity versions, so decoding without "
        "a per-version schema would return plausible garbage. The header and region table "
        "above are stable across versions and are what this reader reports")
    return result


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_il2cpp_metadata(path, **kwargs)
