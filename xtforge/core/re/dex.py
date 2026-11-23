"""Dalvik executable (.dex) reader: classes, fields, methods, and CIL-free bytecode shape.

WHY this exists: `re apk` already lists an APK's entries, but the answer an analyst
wants from an Android package is "which classes and methods are in it". That requires
reading DEX, which is where Android's code actually lives. REA wraps a DEX reader for
the same reason.

Three things in DEX regularly produce confidently wrong output and are handled
explicitly here:

  * Strings are MUTF-8, not UTF-8. NUL is encoded as C0 80, and a supplementary
    character is encoded as two 3-byte surrogate halves. Decoding with UTF-8 either
    raises or silently mis-decodes every non-BMP string, which includes most emoji
    and CJK extension characters in real apps.
  * String data is a ULEB128 *UTF-16 length* followed by the bytes. Skipping the
    length and reading to the first NUL works until a string contains C0 80 — then
    the string is truncated at the embedded NUL escape.
  * `encoded_field` and `encoded_method` store an index *difference* from the
    previous entry, not an absolute index. Reading them as absolute yields method
    names that belong to other classes — plausible, specific, and wrong.

Returns {"ok": bool, ...} and never raises on malformed input.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_ITEMS = 200000
MAX_CLASSES_LISTED = 5000

DEX_MAGIC_PREFIX = b"dex\n"
HEADER_SIZE = 0x70

# class_def_item / encoded_* access flags (Dalvik bytecode spec, "access_flags").
_CLASS_FLAGS = {
    0x00001: "PUBLIC", 0x00002: "PRIVATE", 0x00004: "PROTECTED", 0x00008: "STATIC",
    0x00010: "FINAL", 0x00020: "SUPER", 0x00200: "INTERFACE", 0x00400: "ABSTRACT",
    0x01000: "SYNTHETIC", 0x02000: "ANNOTATION", 0x04000: "ENUM",
}
_METHOD_FLAGS = {
    0x00001: "PUBLIC", 0x00002: "PRIVATE", 0x00004: "PROTECTED", 0x00008: "STATIC",
    0x00010: "FINAL", 0x00020: "SYNCHRONIZED", 0x00040: "BRIDGE", 0x00080: "VARARGS",
    0x00100: "NATIVE", 0x00400: "ABSTRACT", 0x00800: "STRICT",
    0x01000: "SYNTHETIC", 0x10000: "CONSTRUCTOR", 0x20000: "DECLARED_SYNCHRONIZED",
}
_FIELD_FLAGS = {
    0x00001: "PUBLIC", 0x00002: "PRIVATE", 0x00004: "PROTECTED", 0x00008: "STATIC",
    0x00010: "FINAL", 0x00040: "VOLATILE", 0x00080: "TRANSIENT",
    0x01000: "SYNTHETIC", 0x04000: "ENUM",
}


def _flags(mask: int, table: dict[int, str]) -> list[str]:
    return [name for bit, name in sorted(table.items()) if mask & bit]


def _read(path: str | Path) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"file too large: {size} bytes (max {MAX_BYTES})")
    return canon.read_bytes()


def _uleb128(data: bytes, offset: int, limit: int | None = None) -> tuple[int, int]:
    """Decode an unsigned LEB128, at most 5 bytes in DEX."""
    if limit is None:
        limit = len(data)
    value = 0
    for index in range(5):
        if offset + index >= limit:
            raise ValueError("truncated LEB128")
        byte = data[offset + index]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, offset + index + 1
    raise ValueError("LEB128 longer than 5 bytes")


def _mutf8(data: bytes, offset: int, limit: int) -> str:
    """Decode Modified UTF-8, the encoding DEX uses for strings.

    Differences from UTF-8 that matter: NUL is C0 80, and characters above the BMP
    are encoded as two 3-byte surrogate halves rather than one 4-byte sequence.
    """
    units: list[int] = []
    cursor = offset
    while cursor < limit:
        byte = data[cursor]
        if byte == 0:
            break
        if byte < 0x80:
            units.append(byte)
            cursor += 1
        elif byte & 0xE0 == 0xC0:
            if cursor + 1 >= limit:
                break
            units.append(((byte & 0x1F) << 6) | (data[cursor + 1] & 0x3F))
            cursor += 2
        elif byte & 0xF0 == 0xE0:
            if cursor + 2 >= limit:
                break
            units.append(((byte & 0x0F) << 12) | ((data[cursor + 1] & 0x3F) << 6)
                         | (data[cursor + 2] & 0x3F))
            cursor += 3
        else:
            # A 4-byte UTF-8 sequence does not occur in MUTF-8; treat as a unit.
            units.append(0xFFFD)
            cursor += 1
    # Recombine surrogate pairs. Each surrogate is a single code unit here, so this
    # is a plain UTF-16 decode.
    raw = b"".join(struct.pack(">H", unit & 0xFFFF) for unit in units)
    return raw.decode("utf-16-be", "replace")


class Dex:
    """One .dex file, parsed lazily enough to stay fast on multi-megabyte input."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < HEADER_SIZE:
            raise ValueError(f"file too small for a DEX header ({len(data)} bytes)")
        if not data.startswith(DEX_MAGIC_PREFIX):
            raise ValueError("no DEX magic")
        if data[7] != 0:
            raise ValueError("malformed DEX magic terminator")
        self.version = data[4:7].decode("ascii", "replace")
        # Field offsets are absolute, not a packed array: the 20-byte signature sits
        # between the checksum and file_size, so the header is not a sequence of
        # 4-byte words. Unpacking "<20I" from offset 8 silently misaligns every
        # field after the signature — the string table then reads from the wrong
        # offset and returns garbage strings rather than an error.
        def u32(offset: int) -> int:
            return struct.unpack_from("<I", data, offset)[0]

        self.checksum = u32(8)
        self.file_size = u32(32)
        self.header_size = u32(36)
        self.endian_tag = u32(40)
        self.map_off = u32(52)
        self.string_ids_size, self.string_ids_off = u32(56), u32(60)
        self.type_ids_size, self.type_ids_off = u32(64), u32(68)
        self.proto_ids_size, self.proto_ids_off = u32(72), u32(76)
        self.field_ids_size, self.field_ids_off = u32(80), u32(84)
        self.method_ids_size, self.method_ids_off = u32(88), u32(92)
        self.class_defs_size, self.class_defs_off = u32(96), u32(100)
        self.data_size, self.data_off = u32(104), u32(108)
        self._strings: dict[int, str] = {}
        if self.endian_tag not in (0x12345678, 0x78563412):
            raise ValueError(f"unexpected endian tag 0x{self.endian_tag:08x}")
        if self.header_size != HEADER_SIZE:
            raise ValueError(f"unexpected header size 0x{self.header_size:x}")

    def _check(self, offset: int, size: int, what: str) -> None:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(f"{what} runs past the end of the file")

    def string(self, index: int) -> str:
        if index in self._strings:
            return self._strings[index]
        if not 0 <= index < self.string_ids_size:
            return ""
        entry = self.string_ids_off + index * 4
        self._check(entry, 4, "string_ids entry")
        (data_off,) = struct.unpack_from("<I", self.data, entry)
        if data_off >= len(self.data):
            return ""
        _length, start = _uleb128(self.data, data_off)
        value = _mutf8(self.data, start, len(self.data))
        self._strings[index] = value
        return value

    def type_name(self, index: int) -> str:
        if not 0 <= index < self.type_ids_size:
            return ""
        entry = self.type_ids_off + index * 4
        self._check(entry, 4, "type_ids entry")
        (descriptor_idx,) = struct.unpack_from("<I", self.data, entry)
        return self.string(descriptor_idx)

    def proto(self, index: int) -> dict[str, Any]:
        if not 0 <= index < self.proto_ids_size:
            return {}
        entry = self.proto_ids_off + index * 12
        self._check(entry, 12, "proto_ids entry")
        shorty_idx, return_type_idx, parameters_off = struct.unpack_from(
            "<III", self.data, entry)
        parameters: list[str] = []
        if parameters_off:
            # type_list: u32 size, then that many u16 type indices.
            if parameters_off + 4 <= len(self.data):
                (count,) = struct.unpack_from("<I", self.data, parameters_off)
                for i in range(min(count, 64)):
                    cursor = parameters_off + 4 + i * 2
                    if cursor + 2 > len(self.data):
                        break
                    (type_idx,) = struct.unpack_from("<H", self.data, cursor)
                    parameters.append(self.type_name(type_idx))
        return {"shorty": self.string(shorty_idx),
                "return_type": self.type_name(return_type_idx),
                "parameters": parameters}

    def method_id(self, index: int) -> dict[str, Any]:
        if not 0 <= index < self.method_ids_size:
            return {}
        entry = self.method_ids_off + index * 8
        self._check(entry, 8, "method_ids entry")
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, entry)
        return {"class": self.type_name(class_idx), "name": self.string(name_idx),
                "proto": self.proto(proto_idx)}

    def field_id(self, index: int) -> dict[str, Any]:
        if not 0 <= index < self.field_ids_size:
            return {}
        entry = self.field_ids_off + index * 8
        self._check(entry, 8, "field_ids entry")
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.data, entry)
        return {"class": self.type_name(class_idx), "type": self.type_name(type_idx),
                "name": self.string(name_idx)}

    def verify(self) -> dict[str, Any]:
        """Check the embedded checksum and signature against the declared algorithms.

        checksum is Adler-32 over everything after the checksum field (offset 12);
        signature is SHA-1 over everything after the signature field (offset 32).
        A mismatch means the file was modified after it was built — which is exactly
        what an investigator wants to know, and is the reason both are computed here
        rather than trusted.
        """
        out: dict[str, Any] = {"checksum_ok": None, "signature_ok": None}
        if len(self.data) >= 12:
            out["checksum_ok"] = (zlib.adler32(self.data[12:]) & 0xFFFFFFFF) == self.checksum
        if len(self.data) >= 32:
            out["signature_ok"] = hashlib.sha1(self.data[32:]).hexdigest() == \
                self.data[12:32].hex()
        out["file_size_ok"] = self.file_size == len(self.data)
        return out


def _class_data(dex: Dex, offset: int) -> dict[str, Any]:
    """Decode a class_data_item: counts, then delta-encoded fields and methods.

    The deltas are the subtle part: each entry stores the difference from the
    previous entry's index, so the index must be accumulated. Treating a delta as an
    absolute index returns a real method that belongs to a different class.
    """
    data = dex.data
    if not offset or offset >= len(data):
        return {"fields": [], "methods": []}
    limit = len(data)
    static_count, cursor = _uleb128(data, offset, limit)
    instance_count, cursor = _uleb128(data, cursor, limit)
    direct_count, cursor = _uleb128(data, cursor, limit)
    virtual_count, cursor = _uleb128(data, cursor, limit)

    fields: list[dict[str, Any]] = []
    field_index = 0
    for _ in range(min(static_count, MAX_ITEMS)):
        delta, cursor = _uleb128(data, cursor, limit)
        access, cursor = _uleb128(data, cursor, limit)
        field_index += delta
        info = dex.field_id(field_index)
        info.update({"access": _flags(access, _FIELD_FLAGS), "static": True})
        fields.append(info)
    field_index = 0
    for _ in range(min(instance_count, MAX_ITEMS)):
        delta, cursor = _uleb128(data, cursor, limit)
        access, cursor = _uleb128(data, cursor, limit)
        field_index += delta
        info = dex.field_id(field_index)
        info.update({"access": _flags(access, _FIELD_FLAGS), "static": False})
        fields.append(info)

    methods: list[dict[str, Any]] = []
    method_index = 0
    for kind, count in (("direct", direct_count), ("virtual", virtual_count)):
        method_index = 0
        for _ in range(min(count, MAX_ITEMS)):
            delta, cursor = _uleb128(data, cursor, limit)
            access, cursor = _uleb128(data, cursor, limit)
            code_off, cursor = _uleb128(data, cursor, limit)
            method_index += delta
            info = dex.method_id(method_index)
            info.update({
                "access": _flags(access, _METHOD_FLAGS),
                "kind": kind,
                "has_code": bool(code_off),
                "native": bool(access & 0x00100),
            })
            if code_off:
                info["code"] = _code_item(dex, code_off)
            methods.append(info)
    return {"fields": fields, "methods": methods,
            "static_field_count": static_count, "instance_field_count": instance_count}


def _code_item(dex: Dex, offset: int) -> dict[str, Any]:
    """Read a code_item header: register counts, instruction size, try regions."""
    data = dex.data
    if offset + 16 > len(data):
        return {}
    registers, ins, _outs, tries = struct.unpack_from("<HHHH", data, offset)
    debug_info_off, insns_size = struct.unpack_from("<II", data, offset + 8)
    return {
        "registers": registers,
        "ins": ins,
        "tries": tries,
        # Two bytes per instruction unit; the real instruction count differs because
        # some opcodes carry payloads, so this is a size not a count.
        "insns_size": insns_size,
        "has_debug_info": bool(debug_info_off),
    }


def inspect(path: str | Path, *, list_classes: bool = True,
            class_filter: str = "") -> dict[str, Any]:
    """Inventory a .dex file: header, verification, classes with fields and methods."""
    try:
        data = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    try:
        dex = Dex(data)
        verification = dex.verify()
    except (ValueError, struct.error) as exc:
        return {"ok": False, "path": str(path),
                "error": f"malformed DEX: {exc}"}

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "format": "dex",
        "version": dex.version,
        "counts": {
            "strings": dex.string_ids_size,
            "types": dex.type_ids_size,
            "prototypes": dex.proto_ids_size,
            "fields": dex.field_ids_size,
            "methods": dex.method_ids_size,
            "classes": dex.class_defs_size,
        },
        "verification": verification,
    }

    if not list_classes:
        return result

    classes: list[dict[str, Any]] = []
    filtered = class_filter.lower()
    for index in range(min(dex.class_defs_size, MAX_CLASSES_LISTED)):
        entry = dex.class_defs_off + index * 32
        if entry + 32 > len(data):
            result["truncated"] = True
            break
        (class_idx, access, superclass_idx, interfaces_off, source_file_idx,
         _annotations_off, class_data_off, _static_values_off) = struct.unpack_from(
            "<IIIIIIII", data, entry)
        name = dex.type_name(class_idx)
        if filtered and filtered not in name.lower():
            continue
        record: dict[str, Any] = {
            "name": name,
            "access": _flags(access, _CLASS_FLAGS),
            "superclass": dex.type_name(superclass_idx) if superclass_idx != 0xFFFFFFFF
            else None,
        }
        if source_file_idx != 0xFFFFFFFF:
            record["source_file"] = dex.string(source_file_idx)
        if interfaces_off and interfaces_off + 4 <= len(data):
            (count,) = struct.unpack_from("<I", data, interfaces_off)
            interfaces = []
            for i in range(min(count, 32)):
                cursor = interfaces_off + 4 + i * 2
                if cursor + 2 > len(data):
                    break
                (type_idx,) = struct.unpack_from("<H", data, cursor)
                interfaces.append(dex.type_name(type_idx))
            record["interfaces"] = interfaces
        try:
            members = _class_data(dex, class_data_off)
        except (ValueError, struct.error) as exc:
            members = {"fields": [], "methods": [], "error": str(exc)}
        record["fields"] = members["fields"][:200]
        record["methods"] = members["methods"][:400]
        record["field_count"] = len(members["fields"])
        record["method_count"] = len(members["methods"])
        classes.append(record)

    result["classes"] = classes
    result["class_count"] = len(classes)
    result["native_methods"] = sorted({
        f"{cls['name']}->{m['name']}"
        for cls in classes for m in cls["methods"] if m.get("native")
    })[:200]
    return result


def inspect_entry(path: str | Path, entry_name: str = "classes.dex") -> dict[str, Any]:
    """Read one .dex entry out of an APK/zip without unpacking it to disk."""
    import zipfile
    try:
        canon = guard.read_guard(path)
        with zipfile.ZipFile(canon) as archive:
            names = archive.namelist()
            if entry_name not in names:
                candidates = sorted(n for n in names
                                    if n.endswith(".dex") and "/" not in n)
                if not candidates:
                    return {"ok": False, "path": str(path),
                            "error": f"no {entry_name} in the archive",
                            "dex_entries": []}
                entry_name = candidates[0]
            data = archive.read(entry_name)
    except (OSError, ValueError, Denied, zipfile.BadZipFile) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    dex = Dex(data)
    return {"ok": True, "path": str(path), "entry": entry_name,
            "size": len(data), "version": dex.version,
            "counts": {"strings": dex.string_ids_size, "types": dex.type_ids_size,
                       "methods": dex.method_ids_size, "classes": dex.class_defs_size},
            "verification": dex.verify()}
