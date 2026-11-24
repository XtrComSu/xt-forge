"""Android binary XML (AXML) decoding.

A manifest inside an APK is not text. It is a compressed chunk format: an XML header, a string
pool, a resource-id map, and a flat stream of start/end-element events whose attribute values are
either string-pool indices or *typed* values. The typed part is what makes the format awkward and
what a byte scan cannot do:

  * `versionCode="42"` is stored as an integer, not the text "42" — the text does not exist in the
    file at all.
  * `exported="true"` is stored as a boolean with the payload 0xFFFFFFFF for true and 0 for false.
  * `label="@string/app_name"` is a *resource reference* — an id like 0x7F040001 with no string
    attached. Resolving it needs `resources.arsc`, which this module also reads.

The previous implementation scanned the raw bytes for `android.permission.[A-Z0-9_]+`. That finds
permission strings only because they happen to appear verbatim in the pool, and it can never find
a component name, an exported flag, or a single attribute value typed as anything but a string.
It also silently invented permissions from any matching byte run anywhere in the file.

Everything here is bounds-checked. A malformed manifest is common in the wild — deliberately, in
packed malware — and a decoder that trusts the declared offsets will read past its buffer.
"""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any

# Chunk types, from the platform's ResourceTypes.h.
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202

# Res_value data types.
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

NO_INDEX = 0xFFFFFFFF
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_STRINGS = 200_000
MAX_DEPTH = 256
MAX_ELEMENTS = 100_000

# Android framework attribute resource ids, for manifests that carry no resource map. The map is
# usually present, but a hand-built or stripped manifest may omit it, and then the only way to
# know that attribute 0x0101021b is `versionCode` is this table.
_ATTR_IDS = {
    0x01010003: "name", 0x01010006: "permission", 0x01010010: "exported",
    0x0101001D: "enabled", 0x01010020: "icon", 0x01010024: "value",
    0x01010025: "resource", 0x01010026: "debuggable", 0x01010027: "process",
    0x01010028: "authorities", 0x01010029: "scheme", 0x0101002A: "host",
    0x0101002B: "port", 0x0101002C: "path", 0x0101002D: "pathPrefix",
    0x0101002E: "pathPattern", 0x0101002F: "mimeType", 0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode", 0x0101021C: "versionName", 0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion", 0x01010280: "allowBackup", 0x01010393: "supportsRtl",
    0x010103B1: "compileSdkVersion", 0x01010572: "compileSdkVersionCodename",
    0x01010574: "platformBuildVersionCode", 0x01010575: "platformBuildVersionName",
    0x0101021E: "protectionLevel", 0x01010000: "theme", 0x01010001: "label",
    0x01010002: "screenOrientation", 0x010102D9: "roundIcon", 0x0101057E: "appComponentFactory",
}


class AxmlError(ValueError):
    """A manifest that cannot be decoded, with the offset where decoding stopped."""


class _Reader:
    """Bounds-checked big-endian reads over one buffer.

    The real format is little-endian throughout, but every offset in it is attacker-controlled in
    a hostile sample, so each read is checked against the buffer rather than trusted.
    """

    __slots__ = ("data", "size")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    def need(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise AxmlError(f"read of {length} byte(s) at {offset} runs past the "
                            f"{self.size}-byte buffer")

    def u8(self, offset: int) -> int:
        self.need(offset, 1)
        return self.data[offset]

    def u16(self, offset: int) -> int:
        self.need(offset, 2)
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        self.need(offset, 4)
        return struct.unpack_from("<I", self.data, offset)[0]

    def i32(self, offset: int) -> int:
        self.need(offset, 4)
        return struct.unpack_from("<i", self.data, offset)[0]

    def f32(self, offset: int) -> float:
        self.need(offset, 4)
        return struct.unpack_from("<f", self.data, offset)[0]

    def raw(self, offset: int, length: int) -> bytes:
        self.need(offset, length)
        return self.data[offset:offset + length]


def parse_string_pool(reader: _Reader, offset: int, limit: int) -> list[str]:
    """Decode a RES_STRING_POOL chunk into a list of strings.

    Two encodings exist and both appear in real APKs: UTF-16LE (flags bit 0x100 clear) and a
    length-prefixed UTF-8 form. The UTF-8 form uses one or two bytes for the character count and
    again for the byte count, which is where naive readers fall over.
    """
    header_size = reader.u16(offset + 2)
    chunk_size = reader.u32(offset + 4)
    if header_size < 28 or chunk_size < header_size:
        raise AxmlError(f"string pool at {offset} has an impossible header "
                        f"(header {header_size}, chunk {chunk_size})")
    end = offset + min(chunk_size, limit)
    count = reader.u32(offset + 8)
    flags = reader.u32(offset + 16)
    strings_start = reader.u32(offset + 20)
    if count > MAX_STRINGS:
        raise AxmlError(f"string pool claims {count} strings, over the {MAX_STRINGS} limit")
    utf8 = bool(flags & 0x100)
    base = offset + strings_start
    if base > end:
        raise AxmlError(f"string pool data starts at {base}, past the chunk end {end}")

    offsets_at = offset + header_size
    reader.need(offsets_at, count * 4)
    strings: list[str] = []
    for index in range(count):
        cursor = base + reader.u32(offsets_at + index * 4)
        try:
            if utf8:
                cursor = _skip_utf8_length(reader, cursor)[1]
                byte_length, cursor = _skip_utf8_length(reader, cursor)
                strings.append(reader.raw(cursor, byte_length).decode("utf-8", "replace"))
            else:
                characters = reader.u16(cursor)
                cursor += 2
                if characters & 0x8000:  # high-bit form: two 16-bit words
                    characters = ((characters & 0x7FFF) << 16) | reader.u16(cursor)
                    cursor += 2
                strings.append(reader.raw(cursor, characters * 2).decode("utf-16-le", "replace"))
        except AxmlError:
            # One bad offset must not lose the whole pool: the strings before it are still good,
            # and a partially readable pool is more useful than none.
            strings.append("")
    return strings


def _skip_utf8_length(reader: _Reader, cursor: int) -> tuple[int, int]:
    """Read a UTF-8 pool length prefix (1 or 2 bytes) and return (value, next offset)."""
    first = reader.u8(cursor)
    if first & 0x80:
        return ((first & 0x7F) << 8) | reader.u8(cursor + 1), cursor + 2
    return first, cursor + 1


def parse_resource_map(reader: _Reader, offset: int) -> list[int]:
    """Decode RES_XML_RESOURCE_MAP: the attribute-name-to-resource-id table."""
    header_size = reader.u16(offset + 2)
    chunk_size = reader.u32(offset + 4)
    if chunk_size < header_size:
        raise AxmlError(f"resource map at {offset} declares {chunk_size} < header {header_size}")
    count = (chunk_size - header_size) // 4
    return [reader.u32(offset + header_size + index * 4) for index in range(count)]


def decode_value(reader: _Reader, data_type: int, data: int,
                 strings: list[str], resources: Any = None) -> Any:
    """Turn a typed Res_value into a Python value.

    The type byte is the whole point of the format: the same 4-byte field is an integer, a
    boolean, a colour, or an index into the string pool depending on it. Treating it as a string
    index unconditionally is what produces nonsense like `versionCode='Baklava'`.
    """
    if data_type == TYPE_STRING:
        return strings[data] if 0 <= data < len(strings) else None
    if data_type == TYPE_INT_BOOLEAN:
        return data != 0
    if data_type == TYPE_INT_DEC:
        return struct.unpack("<i", struct.pack("<I", data & 0xFFFFFFFF))[0]
    if data_type == TYPE_INT_HEX:
        return f"0x{data:08x}"
    if data_type == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0]
    if data_type in (TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE, TYPE_ATTRIBUTE,
                     TYPE_DYNAMIC_ATTRIBUTE):
        resolved = resources.get(data) if resources is not None else None
        return resolved if resolved is not None else f"@{data:#010x}"
    if data_type == TYPE_NULL:
        return None
    if data_type in (TYPE_INT_COLOR_ARGB8, TYPE_INT_COLOR_RGB8,
                     TYPE_INT_COLOR_ARGB4, TYPE_INT_COLOR_RGB4):
        return f"#{data:08x}"
    if data_type in (TYPE_DIMENSION, TYPE_FRACTION):
        return f"0x{data:08x}"
    return f"type 0x{data_type:02x} value 0x{data:08x}"


def parse_manifest(raw: bytes, resources: Any = None) -> dict[str, Any]:
    """Parse a binary AndroidManifest.xml into a tree plus a component summary."""
    if len(raw) > MAX_MANIFEST_BYTES:
        raise AxmlError(f"manifest is {len(raw)} bytes, over the {MAX_MANIFEST_BYTES} limit")
    reader = _Reader(raw)
    if reader.u16(0) != RES_XML_TYPE:
        raise AxmlError(f"not a binary XML file: first chunk type is "
                        f"0x{reader.u16(0):04x}, expected 0x{RES_XML_TYPE:04x}")

    strings: list[str] = []
    resource_ids: list[int] = []
    elements: list[dict[str, Any]] = []
    stack: list[dict[str, Any]] = []

    offset = reader.u16(2)  # the XML header's own size
    if offset < 8:
        offset = 8
    while offset + 8 <= reader.size:
        chunk_type = reader.u16(offset)
        header_size = reader.u16(offset + 2)
        chunk_size = reader.u32(offset + 4)
        if chunk_size < 8 or header_size < 8 or header_size > chunk_size:
            # A zero size would loop forever; a header larger than its own chunk is nonsense.
            raise AxmlError(f"chunk at {offset} has an impossible size "
                            f"(header {header_size}, chunk {chunk_size})")
        if chunk_type == RES_STRING_POOL_TYPE and not strings:
            strings = parse_string_pool(reader, offset, reader.size - offset)
        elif chunk_type == RES_XML_RESOURCE_MAP:
            resource_ids = parse_resource_map(reader, offset)
        elif chunk_type == RES_XML_START_ELEMENT:
            if len(elements) >= MAX_ELEMENTS:
                raise AxmlError(f"more than {MAX_ELEMENTS} elements")
            if len(stack) >= MAX_DEPTH:
                raise AxmlError(f"element nesting deeper than {MAX_DEPTH}")
            element = _parse_start_element(reader, offset, strings, resource_ids, resources)
            if stack:
                stack[-1]["children"].append(element)
            elements.append(element)
            stack.append(element)
        elif chunk_type == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        offset += chunk_size

    return {
        "elements": len(elements),
        "tree": elements[0] if elements else None,
        "strings": len(strings),
        "resource_ids": len(resource_ids),
    }


def _parse_start_element(reader: _Reader, offset: int, strings: list[str],
                         resource_ids: list[int], resources: Any) -> dict[str, Any]:
    name_index = reader.u32(offset + 20)
    attribute_start = reader.u16(offset + 24)
    attribute_size = reader.u16(offset + 26)
    attribute_count = reader.u16(offset + 28)
    tag = strings[name_index] if 0 <= name_index < len(strings) else f"#{name_index}"

    attributes: dict[str, Any] = {}
    raw_attributes: list[dict[str, Any]] = []
    # `attribute_size` is declared per file and some writers use a larger record than the 20 bytes
    # the platform defines; honouring it is what keeps such a file readable.
    step = attribute_size if attribute_size >= 20 else 20
    for index in range(attribute_count):
        base = offset + 16 + attribute_start + index * step
        try:
            name_idx = reader.u32(base + 4)
            raw_value = reader.u32(base + 8)
            data_type = reader.u8(base + 15)
            data = reader.u32(base + 16)
        except AxmlError:
            break
        key = strings[name_idx] if 0 <= name_idx < len(strings) else f"#{name_idx}"
        if key.startswith("#") and name_idx < len(resource_ids):
            # No name in the pool: the resource map gives the framework attribute id.
            key = _ATTR_IDS.get(resource_ids[name_idx], key)
        if raw_value != NO_INDEX and 0 <= raw_value < len(strings):
            value: Any = strings[raw_value]
        else:
            value = decode_value(reader, data_type, data, strings, resources)
        attributes[key] = value
        raw_attributes.append({"name": key, "value": value, "type": data_type,
                               "resource_id": (resource_ids[name_idx]
                                               if name_idx < len(resource_ids) else None)})

    return {"tag": tag, "attributes": attributes, "raw_attributes": raw_attributes,
            "children": []}


# ---------------------------------------------------------------- components


COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def components(tree: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """Collect declared components, with their intent filters and exported defaults.

    The `android:exported` default is not trivia: on API 31+ a component with an intent filter
    must declare it explicitly or the install fails, and before that an intent-filtered component
    defaulted to exported. Reporting only the literal attribute hides that, so the resolved value
    is reported alongside it and the reason is recorded.
    """
    found: dict[str, list[dict[str, Any]]] = {tag: [] for tag in COMPONENT_TAGS}
    if not tree:
        return found

    def walk(node: dict[str, Any], sdk: int | None) -> None:
        if node.get("tag") == "uses-sdk":
            value = node["attributes"].get("targetSdkVersion")
            if isinstance(value, int):
                sdk = value
        if node.get("tag") == "application":
            for child in node["children"]:
                tag = child.get("tag")
                if tag not in found:
                    walk(child, sdk)
                    continue
                attributes = child.get("attributes") or {}
                filters = [grand for grand in child["children"] if grand.get("tag") == "intent-filter"]
                declared = attributes.get("exported")
                if isinstance(declared, bool):
                    exported, why = declared, "declared"
                elif filters:
                    exported, why = True, "implicit: has an intent-filter and no exported attribute"
                else:
                    exported, why = False, "implicit: no intent-filter and no exported attribute"
                found[tag].append({
                    "name": attributes.get("name"),
                    "exported": exported,
                    "exported_source": why,
                    "permission": attributes.get("permission"),
                    "label": attributes.get("label"),
                    "process": attributes.get("process"),
                    "authorities": attributes.get("authorities"),
                    "actions": [grand["attributes"].get("name")
                                for child2 in filters for grand in child2["children"]
                                if grand.get("tag") == "action"],
                    "categories": [grand["attributes"].get("name")
                                   for child2 in filters for grand in child2["children"]
                                   if grand.get("tag") == "category"],
                    "intent_filters": len(filters),
                })
                walk(child, sdk)
        for child in node.get("children") or []:
            walk(child, sdk)

    walk(tree, None)
    return {tag: items for tag, items in found.items() if items}


def inspect_manifest(path: str | Path, *, entry: str = "AndroidManifest.xml",
                     resources: Any = None) -> dict[str, Any]:
    """Parse the manifest inside an APK (or a bare AndroidManifest.xml).

    Typed values are rendered the way the Go hub renders them — `versionCode` as the text "3" —
    so the two implementations answer identically. They disagreed once: Python returned the
    integer 3 and Go the string "3", which made a cross-check between them report a mismatch
    while both displayed the same number.
    """
    """Parse the manifest inside an APK (or a bare AndroidManifest.xml)."""
    target = Path(path)
    try:
        if zipfile.is_zipfile(target):
            with zipfile.ZipFile(target) as archive:
                if entry not in archive.namelist():
                    return {"ok": False, "path": str(target),
                            "error": f"no {entry} in the archive",
                            "entries": archive.namelist()[:40]}
                raw = archive.read(entry)
        else:
            raw = target.read_bytes()
    except (OSError, zipfile.BadZipFile) as exc:
        return {"ok": False, "path": str(target), "error": str(exc)}

    try:
        parsed = parse_manifest(raw, resources)
    except AxmlError as exc:
        return {"ok": False, "path": str(target), "error": str(exc)}

    tree = parsed["tree"]
    attributes = (tree or {}).get("attributes", {})
    return {
        "ok": True,
        "path": str(target),
        "package": attributes.get("package"),
        "version_code": _as_text(attributes.get("versionCode")),
        "version_name": _as_text(attributes.get("versionName")),
        "compile_sdk": _as_text(attributes.get("compileSdkVersion")),
        "elements": parsed["elements"],
        "string_count": parsed["strings"],
        "components": components(tree),
        "permissions": [node["attributes"].get("name")
                        for node in _walk_tags(tree, "uses-permission")
                        if node["attributes"].get("name")],
        "features": [node["attributes"].get("name")
                     for node in _walk_tags(tree, "uses-feature")
                     if node["attributes"].get("name")],
        "uses_sdk": {key: _as_text(value) for key, value in
                     next((node["attributes"] for node in _walk_tags(tree, "uses-sdk")),
                          {}).items()},
        "application": next((node["attributes"] for node in _walk_tags(tree, "application")), {}),
    }


def _as_text(value: Any) -> str | None:
    """Render a typed attribute as text, matching the Go hub's representation."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _walk_tags(node: dict[str, Any] | None, tag: str):
    if not node:
        return
    if node.get("tag") == tag:
        yield node
    for child in node.get("children") or []:
        yield from _walk_tags(child, tag)


# ---------------------------------------------------------------- resources.arsc


def parse_arsc(raw: bytes) -> dict[int, str]:
    """Map resource id -> default-configuration value from resources.arsc.

    A manifest attribute like `label="@string/app_name"` holds only an id (0x7F040001). Resolving
    it means walking the resource table: the table's own string pool (which is where the *values*
    live), then package chunks, type chunks and per-entry records.

    Only the default configuration is read. Locale variants are real, but a manifest reference is
    answered by the value a device with no matching locale would use, and reporting a random
    locale would be worse than reporting the default.
    """
    values: dict[int, str] = {}
    if len(raw) < 12:
        return values
    reader = _Reader(raw)
    try:
        if reader.u16(0) != RES_TABLE_TYPE:
            return values
        header_size = reader.u16(2)
        total = min(reader.u32(4), reader.size)
        package_count = reader.u32(8)
    except AxmlError:
        return values

    # The value strings are in the table's top-level pool, not the package's key pool.
    global_strings: list[str] = []
    offset = header_size
    while offset + 8 <= total:
        try:
            chunk_type = reader.u16(offset)
            chunk_size = reader.u32(offset + 4)
        except AxmlError:
            break
        if chunk_size < 8:
            break
        if chunk_type == RES_STRING_POOL_TYPE and not global_strings:
            try:
                global_strings = parse_string_pool(reader, offset, reader.size - offset)
            except AxmlError:
                global_strings = []
        offset += chunk_size

    # Then the package chunks, bounded so a lying package count cannot spin here.
    packages: list[int] = []
    offset = header_size
    budget = max(package_count, 1) * 8
    while offset + 8 <= total and len(packages) < budget:
        try:
            chunk_type = reader.u16(offset)
            chunk_size = reader.u32(offset + 4)
        except AxmlError:
            break
        if chunk_size < 8:
            break
        if chunk_type == RES_TABLE_PACKAGE_TYPE:
            packages.append(offset)
        offset += chunk_size

    for package_at in packages:
        try:
            values.update(_parse_package(reader, package_at, total, global_strings))
        except AxmlError:
            continue
    return values


def _parse_package(reader: _Reader, package_at: int, end: int,
                   global_strings: list[str]) -> dict[int, str]:
    package_id = reader.u32(package_at + 8)
    type_strings_offset = reader.u32(package_at + 268)
    key_strings_offset = reader.u32(package_at + 276)
    header_size = reader.u16(package_at + 2)

    try:
        type_names = parse_string_pool(reader, package_at + type_strings_offset,
                                       reader.size - (package_at + type_strings_offset))
        key_names = parse_string_pool(reader, package_at + key_strings_offset,
                                      reader.size - (package_at + key_strings_offset))
    except AxmlError:
        return {}

    values: dict[int, str] = {}
    offset = package_at + header_size
    while offset + 8 <= end:
        try:
            chunk_type = reader.u16(offset)
            chunk_size = reader.u32(offset + 4)
        except AxmlError:
            break
        if chunk_size < 8:
            break
        if chunk_type == RES_TABLE_TYPE_TYPE:
            try:
                values.update(_parse_type(reader, offset, package_id, type_names,
                                          key_names, global_strings))
            except AxmlError:
                pass
        offset += chunk_size
    return values


def _parse_type(reader: _Reader, offset: int, package_id: int, type_names: list[str],
                key_names: list[str], global_strings: list[str]) -> dict[int, str]:
    type_id = reader.u8(offset + 8)
    flags = reader.u8(offset + 9)
    entry_count = reader.u32(offset + 12)
    entries_start = reader.u32(offset + 16)
    header_size = reader.u16(offset + 2)
    if entry_count > 100_000:
        return {}
    type_name = type_names[type_id - 1] if 0 < type_id <= len(type_names) else f"type{type_id}"

    # Sparse and 16-bit-offset tables index differently. Both are real formats; neither appears in
    # a small package, so they are skipped rather than misread into plausible wrong values.
    if flags & 0x03:
        return {}

    values: dict[int, str] = {}
    for index in range(entry_count):
        try:
            entry_offset = reader.u32(offset + header_size + index * 4)
        except AxmlError:
            break
        if entry_offset == NO_INDEX:
            continue
        entry_at = offset + entries_start + entry_offset
        try:
            entry_size = reader.u16(entry_at)
            entry_flags = reader.u16(entry_at + 2)
            if entry_flags & 0x0001:  # FLAG_COMPLEX: a bag (style/array), not a plain value
                continue
            key_index = reader.u32(entry_at + 4)
            if entry_size >= 16:  # the wide record carries the Res_value inline
                data_type = reader.u8(entry_at + 15)
                data = reader.u32(entry_at + 16)
            else:
                value_at = entry_at + entry_size
                data_type = reader.u8(value_at + 3)
                data = reader.u32(value_at + 4)
        except AxmlError:
            continue
        if data_type != TYPE_STRING or data >= len(global_strings):
            continue
        key = key_names[key_index] if key_index < len(key_names) else str(key_index)
        resource_id = (package_id << 24) | (type_id << 16) | index
        values[resource_id] = f"{type_name}/{key}={global_strings[data]}"
    return values
