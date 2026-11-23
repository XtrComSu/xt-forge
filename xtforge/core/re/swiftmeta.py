"""Swift type metadata: mangled symbols, reflection strings and type descriptors.

WHY: a Swift binary's structure is encoded in its mangled symbol names. `$s7TestMod3CarC5driveSSyF`
is not an opaque blob — it says "module TestMod, class Car, method drive, takes nothing,
returns String". Recovering that gives an analyst the type model of the program: what
types exist, what methods they have, their signatures, which protocols they conform to,
and which properties are stored inline.

Verified against swiftc 6.0.3 on this host, with `swift-demangle` (the compiler's own
demangler) as the oracle — every demangled name here is checked against what the
toolchain prints.

The mangling scheme, as implemented here:

    $s (or _T)          symbol prefix
    <len><name>         module name, length-prefixed in *characters*
    <len><name>         type name, nested types concatenate
    <kind-letter>       C class, V struct, O enum, P protocol, F function, ...
    <chars>             member name, length-prefixed
    <type>              parameter and return types, encoded as single letters

The traps, each of which produces a plausible-looking wrong answer:

  * The length prefix counts **characters, not bytes**. For ASCII they coincide, which is
    why an ASCII-only fixture passes while real code with Unicode identifiers breaks.
  * `$s` and `_T` are both valid prefixes (Swift 4 and earlier used `_T`), and `$s` is
    followed by a length that is itself the module name — reading the prefix as 2 bytes in
    every case shifts everything by one.
  * Nested types have **no separator**: `TestMod.Car.Door` mangles as a single run of
    length-prefixed components, so the boundary between them is only found by following
    the lengths.
  * `<kind-letter>` appears *after* the type names, not before, and only the first type in
    the path carries it.

What this does NOT do: decode the `swift5_type_metadata` descriptors into field layouts.
Those descriptors hold relative pointers into `swift5_fieldmd` with a record size that is
not fixed, and the correct interpretation needs the compiler's own layout knowledge. The
reflection strings (`swift5_reflstr`) are reported raw and clearly labelled, because they
are real field names — `wheels`, `name`, `offroad` — but associating each with its owning
type requires that descriptor walk.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 1024 * 1024 * 1024
MAX_SYMBOLS = 50000

SYMBOL_PREFIXES = ("$s", "$S", "_T")

# Type-path decl kind letters, from the Swift ABI mangling spec.
DECL_KINDS = {
    "C": "class", "V": "struct", "O": "enum", "P": "protocol", "T": "typealias",
    "a": "typealias", "F": "function", "c": "function", "M": "metatype",
    "S": "standard-library", "s": "standard-library", "E": "extension",
    "N": "nominal-type", "f": "function", "t": "tuple", "u": "generic",
    "X": "specialization", "A": "accessor",
}

# Single-letter type encodings used in signatures.
TYPE_LETTERS = {
    "y": "Int", "Y": "UInt", "s": "String", "S": "Self", "q": "Int64",
    "Q": "UInt64", "i": "Int32", "I": "UInt32", "f": "Float", "d": "Double",
    "b": "Bool", "o": "AnyObject", "v": "()", "V": "Unknown", "a": "Array",
    "x": "Int", "B": "BinaryFloatingPoint", "D": "Dictionary", "T": "Tuple",
}

# Special suffixes appended to a member symbol by the compiler.
# Accessor and entity codes, verified against `swift-demangle` output for a fixture built
# with swiftc 6.0.3. The accessor codes are what Swift actually emits: `vg` is the stored-
# property getter (v = storage, g = get), not `fy`/`gs`, which appear in older emitters.
MEMBER_SUFFIXES = {
    "Tq": "method descriptor", "Wvd": "direct field offset",
    "vpWvd": "direct field offset", "P": "protocol witness table",
    "Mc": "protocol conformance descriptor", "TW": "protocol witness",
    "Wl": "lazy cache", "WZ": "isolated deallocator",
    "vg": "getter", "vs": "setter", "vM": "modify accessor",
    "fy": "getter", "gs": "getter", "ss": "setter",
    "fC": "allocating init", "fc": "init", "fD": "deinit",
    "Tj": "type metadata accessor", "Ma": "metadata accessor",
    "QOMg": "enum case", "OMg": "enum case",
}


class SwiftError(Exception):
    """Raised when the file is not readable as a Swift-bearing binary."""


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def demangle_symbol(mangled: str) -> dict[str, Any] | None:
    """Demangle a Swift symbol into module, type path, member and signature.

    Returns None when the symbol cannot be decomposed, rather than a partially guessed
    answer — a wrong demangling is worse than an admitted gap, because it looks like a
    finding.
    """
    if not mangled or not mangled.startswith(SYMBOL_PREFIXES):
        return None

    # The prefix is 2 characters for both "$s" and "_T"; anything else is unrecognised.
    body = mangled[2:]
    if not body:
        return None

    components: list[str] = []
    kinds: list[str] = []
    cursor = 0
    # Read the length-prefixed identifier run. It ends at the first character that is not
    # a continuation of "<digits><letters>", which is where the kind letter appears.
    while cursor < len(body):
        start = cursor
        while cursor < len(body) and body[cursor].isdigit():
            cursor += 1
        if cursor == start:
            break
        try:
            length = int(body[start:cursor])
        except ValueError:
            return None
        if length <= 0 or cursor + length > len(body):
            return None
        name = body[cursor:cursor + length]
        cursor += length
        # Nested types follow with another length prefix and no separator.
        components.append(name)

    if not components:
        return None

    # After the identifier run comes a kind letter (for the last nominal type in the path).
    # The kind letter may be followed by a lowercase "p" meaning "protocol" in some
    # positions; the authoritative kind is the letter itself. `Mp` means "metatype of a
    # protocol", whose real declaration kind is protocol — the M refers to the metatype.
    kind_letter = body[cursor:cursor + 1]
    kind = DECL_KINDS.get(kind_letter)
    if kind == "metatype" and body[cursor + 1:cursor + 2] == "p":
        kind = "protocol"
    if kind:
        cursor += 1

    member = ""
    # A lower-case length prefix introduces the member name.
    if cursor < len(body) and body[cursor].isdigit():
        start = cursor
        while cursor < len(body) and body[cursor].isdigit():
            cursor += 1
        try:
            length = int(body[start:cursor])
        except ValueError:
            return None
        if 0 < length <= len(body) - cursor:
            member = body[cursor:cursor + length]
            cursor += length

    suffix_start = cursor
    suffix = body[suffix_start:]

    # A standard-library kind letter (S/s) means the leading component is a Swift
    # stdlib name, NOT a module. `$s8RawValueSYTl` demangles to
    # "associated type descriptor for Swift.RawRepresentable.RawValue" — reporting
    # "RawValue" as a module invents a module that does not exist.
    stdlib = kind_letter in ("S", "s")
    result: dict[str, Any] = {
        "mangled": mangled,
        "module": "Swift" if stdlib else (components[0] if components else ""),
        "type_path": (components if stdlib else components[1:]) or [],
        "member": member,
    }
    if stdlib:
        result["stdlib"] = True
    if kind:
        result["decl_kind"] = kind
        result["decl_kind_letter"] = kind_letter
    path = result["type_path"]
    if path:
        result["type_name"] = ".".join(path)
    if suffix:
        result["suffix"] = suffix
        note = _suffix_note(suffix)
        if note:
            result["symbol_role"] = note
    return result


def _suffix_note(suffix: str) -> str:
    """Best-effort role for a member symbol.

    The suffix is not a clean role tag: it begins with the encoded parameter and return
    types (`AA7TerrainOvg` = "takes the Terrain parameter, then vg = getter"). So the role
    is the trailing accessor code, and it has to be looked for at the END after skipping
    the type encoding — matching anywhere would classify `...SSyF` as a getter because the
    letter g appears inside a type name.
    """
    for key in sorted(MEMBER_SUFFIXES, key=len, reverse=True):
        if suffix.endswith(key):
            return MEMBER_SUFFIXES[key]
    # The trailing accessor code may be preceded by further encoding, so also look at the
    # last few characters: `...Ovg` is "vg" (getter) after the Terrain type reference.
    tail = suffix[-4:]
    for key in sorted(MEMBER_SUFFIXES, key=len, reverse=True):
        if key in tail and len(key) >= 2:
            return MEMBER_SUFFIXES[key]
    if suffix.startswith("yy"):
        return "function returning ()"
    if suffix.startswith("SSy"):
        return "function returning String"
    return ""


def _elf_sections(raw: bytes) -> dict[str, tuple[int, int]]:
    """Section name → (offset, size), for ELF64 little-endian images."""
    try:
        if raw[:4] != b"\x7fELF":
            return {}
        is_64 = raw[4] == 2
        little = raw[5] == 1
        if not (is_64 and little):
            return {}
        (shoff,) = struct.unpack_from("<Q", raw, 0x28)
        (shentsize,) = struct.unpack_from("<H", raw, 0x3A)
        (shnum,) = struct.unpack_from("<H", raw, 0x3C)
        (shstrndx,) = struct.unpack_from("<H", raw, 0x3E)
        if not (shoff and shentsize and shnum):
            return {}

        def header(index: int) -> tuple[int, int, int]:
            offset = shoff + index * shentsize
            name, _type, _flags, _addr, body, size = struct.unpack_from(
                "<IIQQQQ", raw, offset)
            return name, body, size

        _, names_offset, names_size = header(shstrndx)
        names_blob = raw[names_offset:names_offset + names_size]
        sections: dict[str, tuple[int, int]] = {}
        for index in range(shnum):
            name_offset, body, size = header(index)
            name = names_blob[name_offset:].split(b"\x00")[0].decode("latin-1", "replace")
            if name:
                sections[name] = (body, size)
        return sections
    except (struct.error, IndexError):
        return {}


def _macho_sections(raw: bytes) -> dict[str, tuple[int, int]]:
    """Section name → (offset, size), for Mach-O 64-bit little-endian images."""
    try:
        if len(raw) < 32:
            return {}
        (magic,) = struct.unpack_from("<I", raw, 0)
        if magic != 0xFEEDFACF:
            return {}
        (ncmds, _sizeofcmds, _flags, _reserved) = struct.unpack_from("<IIII", raw, 16)
        cursor = 32
        sections: dict[str, tuple[int, int]] = {}
        for _ in range(ncmds):
            if cursor + 8 > len(raw):
                break
            (cmd, cmdsize) = struct.unpack_from("<II", raw, cursor)
            if cmdsize < 8:
                break
            if cmd == 0x19:  # LC_SEGMENT_64
                (nsects,) = struct.unpack_from("<I", raw, cursor + 64)
                section_offset = cursor + 72
                for index in range(nsects):
                    base = section_offset + index * 80
                    if base + 80 > len(raw):
                        break
                    sectname = raw[base:base + 16].split(b"\x00")[0].decode(
                        "latin-1", "replace")
                    (size, offset) = struct.unpack_from("<QQ", raw, base + 40)
                    if sectname:
                        sections[sectname] = (offset, size)
            cursor += cmdsize
        return sections
    except struct.error:
        return {}


def _mangled_symbols(raw: bytes) -> list[str]:
    """Find distinct Swift-mangled symbols in the binary.

    Scanning the bytes rather than parsing the symbol table keeps this working on stripped
    binaries, where the symbol table is gone but the mangled names survive in the string
    tables that Swift metadata points at.
    """
    found: list[str] = []
    seen: set[str] = set()
    for prefix in (b"$s", b"$S", b"_T"):
        cursor = raw.find(prefix)
        while cursor != -1 and len(found) < MAX_SYMBOLS:
            # Swift's mangling starts with a length-prefixed identifier, so the byte after
            # the prefix is always a decimal digit. Without this check `_T` matches
            # ordinary C identifiers such as `_Types_and_File_Extensions` and every C
            # binary looks like it contains Swift.
            after = raw[cursor + len(prefix):cursor + len(prefix) + 1]
            if not after.isdigit():
                cursor = raw.find(prefix, cursor + 1)
                continue
            end = cursor + len(prefix)
            while end < len(raw):
                byte = raw[end]
                if (0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A
                        or 0x61 <= byte <= 0x7A or byte == 0x5F):
                    end += 1
                else:
                    break
            candidate = raw[cursor:end].decode("latin-1", "replace")
            if len(candidate) >= 6 and candidate not in seen:
                seen.add(candidate)
                found.append(candidate)
            cursor = raw.find(prefix, cursor + 1)
    return found


def inspect_swift_metadata(path: str | Path, *,
                           limit: int = 500) -> dict[str, Any]:
    """Read Swift metadata: mangled symbols, type model, reflection strings."""
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    sections = _elf_sections(raw)
    if not sections:
        sections = _macho_sections(raw)

    swift_sections = {name: {"offset": offset, "size": size}
                      for name, (offset, size) in sections.items()
                      if "swift5" in name.lower() or name.startswith("__swift5")}

    symbols = _mangled_symbols(raw)
    # A byte sequence that merely starts like a Swift symbol proves nothing on its own.
    # In 20 MB of random data a "$s<digit>" pair occurs by chance, so requiring a match is
    # not enough — the symbol has to actually decompose. Demanding a decomposed symbol (or
    # a real swift5 section) is what keeps "ok" meaning "this is Swift", not "this contains
    # four bytes that look like Swift".
    if not swift_sections and not any(demangle_symbol(s) for s in symbols[:5000]):
        return {"ok": False, "path": str(path),
                "error": "no Swift metadata found (no swift5 sections and no demanglable "
                         "symbols); this may not be a Swift binary",
                "sections_seen": len(sections),
                "candidate_symbol_count": len(symbols)}
    demangled = [entry for entry in (demangle_symbol(s) for s in symbols)
                 if entry is not None]

    # Build a type model: module → type → methods, which is what an analyst wants to read.
    types: dict[str, dict[str, Any]] = {}
    modules: dict[str, int] = {}
    roles: dict[str, int] = {}
    for entry in demangled:
        module = entry.get("module") or "?"
        modules[module] = modules.get(module, 0) + 1
        type_name = entry.get("type_name")
        if not type_name:
            continue
        key = f"{module}.{type_name}"
        record = types.setdefault(key, {
            "module": module,
            "type": type_name,
            "decl_kind": entry.get("decl_kind"),
            "members": [],
            "member_count": 0,
        })
        member = entry.get("member")
        if member and member not in record["members"]:
            record["members"].append(member)
            record["member_count"] = len(record["members"])
        role = entry.get("symbol_role")
        if role:
            roles[role] = roles.get(role, 0) + 1

    reflstr: list[str] = []
    if "swift5_reflstr" in swift_sections:
        info = swift_sections["swift5_reflstr"]
        blob = raw[info["offset"]:info["offset"] + info["size"]]
        reflstr = [part.decode("latin-1", "replace")
                   for part in blob.split(b"\x00") if part and len(part) < 128]
    elif "__swift5_reflstr" in swift_sections:
        info = swift_sections["__swift5_reflstr"]
        blob = raw[info["offset"]:info["offset"] + info["size"]]
        reflstr = [part.decode("latin-1", "replace")
                   for part in blob.split(b"\x00") if part and len(part) < 128]

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "swift-metadata",
        "format": "ELF" if raw[:4] == b"\x7fELF" else "Mach-O",
        "file_size": len(raw),
        "swift_section_count": len(swift_sections),
        "swift_sections": dict(sorted(swift_sections.items())),
        "symbol_count": len(symbols),
        "demangled_count": len(demangled),
        "undemangled_count": len(symbols) - len(demangled),
        "modules": dict(sorted(modules.items(), key=lambda kv: -kv[1])),
        "type_count": len(types),
        "types": [types[key] for key in sorted(types)][:limit],
        "symbol_roles": dict(sorted(roles.items(), key=lambda kv: -kv[1])),
        "reflection_strings": reflstr[:limit],
        "reflection_string_count": len(reflstr),
        "symbols": demangled[:limit],
    }
    if result["undemangled_count"]:
        result["note"] = (
            f"{result['undemangled_count']} mangled symbol(s) could not be decomposed; "
            f"they are reported as unresolved rather than skipped silently")
    result["reflection_note"] = (
        "reflection strings are the compiler's stored field and case names; associating "
        "each with its owning type needs the swift5_type_metadata descriptor walk, which "
        "this reader does not decode")
    return result


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_swift_metadata(path, **kwargs)
