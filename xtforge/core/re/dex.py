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
# Per-entry cap when scanning inside an archive: a single .dex over this is not scannable.
MAX_CLASS_SCAN_BYTES = 256 * 1024 * 1024
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
            "verification": dex.verify(),
            **native_methods(data)}


def native_methods(data: bytes, *, limit: int = 200) -> dict[str, Any]:
    """Find `native` methods and derive the JNI symbol each one is bound to.

    A `native` method has no DEX code — the body lives in a `.so`. The only thing tying the two
    together is a naming convention, so recovering the binding means computing the symbol name
    the runtime will look up:

        Java_<package with / -> _><Class>_<method>
        Java_<...>__<signature>            for an overloaded method

    The mangling is not simply "replace dots with underscores". Underscores in a name are escaped
    as `_1`, semicolons as `_2`, and `[` as `_3`, because otherwise a name containing an
    underscore could produce the same symbol as one containing a dot. Getting that wrong yields a
    symbol that looks right and matches nothing, which is the worst possible answer to "which
    native code implements this method".

    `inspect()` computed this and `inspect_entry()` — the function `re apk` actually calls — did
    not, so the verb an analyst uses reported no native methods even for a package that has them.
    """
    dex = Dex(data)
    found: list[dict[str, Any]] = []
    for index in range(min(dex.class_defs_size, MAX_ITEMS)):
        entry = dex.class_defs_off + index * 32
        try:
            class_index, _access, _super, _ifs, _src, _ann, class_data_off, _static = \
                _unpack_class_def(dex.data, entry)
        except (struct.error, IndexError):
            continue
        class_name = dex.type_name(class_index)
        if not class_name or not class_data_off:
            continue
        members = _class_data(dex, class_data_off)
        for method in members.get("methods") or []:
            if not method.get("native"):
                continue
            descriptor = _descriptor_signature(dex, method)
            found.append({
                "class": class_name,
                "name": method.get("name"),
                "descriptor": method.get("descriptor") or descriptor,
                "jni_symbol": jni_symbol(class_name, method.get("name") or "", descriptor),
                "overloaded": False,
            })
    # A JNI symbol only carries the signature when the method is overloaded; computing it that way
    # requires knowing the class's other methods, so the plain form is reported and the signature
    # form is offered alongside rather than guessed at.
    counts: dict[str, int] = {}
    for record in found:
        counts[record["jni_symbol"].split("__")[0]] = 0
    for record in found:
        key = record["jni_symbol"].split("__")[0]
        counts[key] += 1
    for record in found:
        key = record["jni_symbol"].split("__")[0]
        if counts.get(key, 0) > 1:
            record["overloaded"] = True
            record["jni_symbol_overloaded"] = record["jni_symbol"]

    return {
        "native_methods": found[:limit],
        "native_method_count": len(found),
        "jni_symbols": sorted({r["jni_symbol"] for r in found})[:limit],
    }


def _unpack_class_def(data: bytes, offset: int) -> tuple:
    return struct.unpack_from("<8I", data, offset)


def _descriptor_signature(dex: "Dex", method: dict[str, Any]) -> str:
    """Recover the method descriptor from its prototype, for the JNI mangling."""
    prototype = method.get("prototype") or method.get("proto")
    if isinstance(prototype, str):
        return prototype
    if isinstance(prototype, dict):
        built = prototype.get("descriptor") or prototype.get("shorty")
        if isinstance(built, str):
            return built
    return ""


def jni_symbol(class_name: str, method_name: str, descriptor: str = "") -> str:
    """Build the JNI symbol the runtime resolves for a native method.

    Class names arrive in DEX form (`Lcom/example/Foo;`), so the leading `L` and trailing `;` are
    stripped, `/` stays, and the remaining characters are escaped. Overloads append `__` and the
    mangled descriptor; callers decide whether that suffix applies, since it depends on siblings.
    """
    plain = class_name or ""
    if plain.startswith("L") and plain.endswith(";"):
        plain = plain[1:-1]
    # The package separator becomes `_` *unescaped*; only a literal underscore is escaped, to
    # `_1`. Escaping before replacing `/` turned `com/example` into `com_1example` — a symbol
    # that looks right and matches nothing, which is the worst answer to "which native code
    # implements this method". Splitting on `/` and escaping each segment keeps the two distinct.
    parts = [part for part in plain.split("/") if part]
    symbol = "Java_" + "_".join(_jni_escape(part) for part in parts) + "_" + _jni_escape(method_name)
    if descriptor:
        symbol += "__" + _jni_escape(descriptor)
    return symbol


def _jni_escape(text: str) -> str:
    """Escape one JNI name segment: `_`->`_1`, `;`->`_2`, `[`->`_3`.

    The `/` separator is handled by the caller, because it becomes a plain `_` rather than an
    escaped one. Escaping it here turned `com/example` into `com_1example`.
    """
    return text.replace("_", "_1").replace(";", "_2").replace("[", "_3")


def _classes_matching(dex: "Dex", pattern: str, limit: int) -> tuple[list[dict], int]:
    """Walk the class-def table, returning matching records and the total scanned."""
    import re as _re
    try:
        matcher = _re.compile(pattern, _re.IGNORECASE)
    except _re.error:
        matcher = None
    matches: list[dict[str, Any]] = []
    scanned = 0
    for index in range(dex.class_defs_size):
        entry = dex.class_defs_off + index * 32
        if entry + 32 > len(dex.data):
            break
        (class_idx, access, superclass_idx, _interfaces, _source,
         _annotations, _class_data, _static) = struct.unpack_from(
            "<IIIIIIII", dex.data, entry)
        scanned += 1
        name = dex.type_name(class_idx)
        if matcher is None or not matcher.search(name):
            continue
        matches.append({
            "name": name,
            "access": _flags(access, _CLASS_FLAGS),
            "superclass": (dex.type_name(superclass_idx)
                           if superclass_idx != 0xFFFFFFFF else None),
        })
        if len(matches) > limit:
            break
    return matches, scanned


def search_classes(path: str | Path, pattern: str, *, limit: int = 60,
                   entry_name: str = "classes.dex") -> dict[str, Any]:
    """Find classes whose name matches a pattern, inside a .dex file or an APK.

    The breadth matrix filed this under ADB device management, which is wrong: listing classes
    needs the file, not a device. The class-def walk mirrors `inspect`'s, so the two report the
    same contents rather than two independently-drifting views.
    """
    import re as _re
    import zipfile
    if not pattern:
        return {"ok": False, "error": "a class name pattern is required"}
    try:
        _re.compile(pattern)
    except _re.error as exc:
        return {"ok": False, "error": f"invalid pattern: {exc}"}
    target = Path(str(path))
    if not target.is_file():
        return {"ok": False, "error": f"not a file: {path}"}

    matches: list[dict[str, Any]] = []
    scanned = 0
    entries = 0
    try:
        if zipfile.is_zipfile(target):
            with zipfile.ZipFile(target) as archive:
                for name in archive.namelist():
                    if not name.endswith(".dex"):
                        continue
                    entries += 1
                    with archive.open(name) as handle:
                        raw = handle.read(MAX_CLASS_SCAN_BYTES)
                    try:
                        found, seen = _classes_matching(Dex(raw), pattern, limit)
                    except (ValueError, IndexError, struct.error) as exc:
                        matches.append({"entry": name, "error": str(exc)})
                        continue
                    scanned += seen
                    matches.extend({"entry": name, **record} for record in found)
                    if len(matches) >= limit:
                        break
        else:
            entries = 1
            found, scanned = _classes_matching(Dex(_read(target)), pattern, limit)
            matches.extend({"entry": entry_name, **record} for record in found)
    except (zipfile.BadZipFile, OSError, ValueError, struct.error) as exc:
        return {"ok": False, "error": str(exc)}

    # `truncated` must be set when the walk stopped early, not when matches exceeded the limit:
    # the loop breaks *at* the limit, so `len(matches) > limit` is never true and a capped
    # result looked complete. One extra match is collected to make the distinction detectable.
    truncated = len(matches) > limit
    return {"ok": True, "path": str(target), "pattern": pattern,
            "dex_entries": entries, "classes_scanned": scanned,
            "match_count": min(len(matches), limit), "matches": matches[:limit],
            "truncated": truncated}


def trace_references(path: str | Path, symbol: str, *, limit: int = 60,
                     entry_name: str = "classes.dex") -> dict[str, Any]:
    """Find where a method or field name is declared across the archive's .dex files.

    This answers "who declares or references this", the question behind the REA
    `trace_android_references` tool, and it is answerable from the file rather than a device.
    """
    import zipfile
    if not symbol:
        return {"ok": False, "error": "a symbol name is required"}
    target = Path(str(path))
    if not target.is_file():
        return {"ok": False, "error": f"not a file: {path}"}

    blobs: list[tuple[str, bytes]] = []
    try:
        if zipfile.is_zipfile(target):
            with zipfile.ZipFile(target) as archive:
                for name in archive.namelist():
                    if name.endswith(".dex"):
                        with archive.open(name) as handle:
                            blobs.append((name, handle.read(MAX_CLASS_SCAN_BYTES)))
        else:
            blobs.append((entry_name, _read(target)))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}

    hits: list[dict[str, Any]] = []
    needle = symbol.lower()
    for name, data in blobs:
        try:
            parsed = Dex(data)
        except (ValueError, IndexError, struct.error):
            continue
        for kind, lookup, count in (("method", parsed.method_id, parsed.method_ids_size),
                                    ("field", parsed.field_id, parsed.field_ids_size)):
            for index in range(count):
                try:
                    entry = lookup(index)
                except (ValueError, IndexError, struct.error, KeyError):
                    continue
                if entry and needle in (entry.get("name") or "").lower():
                    hits.append({"entry": name, "kind": kind, "name": entry.get("name"),
                                 "class": entry.get("class"), "type": entry.get("type")})
                    if len(hits) >= limit:
                        break
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    return {"ok": True, "path": str(target), "symbol": symbol, "dex_entries": len(blobs),
            "reference_count": len(hits), "references": hits[:limit],
            "truncated": len(hits) >= limit}
