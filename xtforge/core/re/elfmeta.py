"""Analyst-facing metadata report for ELF files.

The engine already reads DWARF for names and .eh_frame for function starts, but
never exposes either. This module reports notes (build-id, ABI tag, GNU
property), DWARF compile units and unwind records using ``struct`` only -- no
pyelftools, no external commands.

All bounds are explicit: malformed DWARF becomes a warning for that unit, never
an exception. A file is refused with :class:`ValueError` only when it is not an
ELF file or its ELF header/section table is truncated.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

MAGIC = b"\x7fELF"
MAX_UNITS = 200
MAX_RECS = 5000
MAX_ABBREVS = 10000
MAX_SECTIONS = 100000

SHT_NOTE = 7
SHT_NOBITS = 8

DW_AT_name = 0x03
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_producer = 0x25
DW_AT_str_offsets_base = 0x72
DW_AT_addr_base = 0x73
_FIELDS = {
    DW_AT_name: "name", DW_AT_low_pc: "low_pc",
    DW_AT_high_pc: "high_pc", DW_AT_producer: "producer",
}

DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0A
DW_FORM_data1 = 0x0B
DW_FORM_flag = 0x0C
DW_FORM_sdata = 0x0D
DW_FORM_strp = 0x0E
DW_FORM_udata = 0x0F
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_strx = 0x1A
DW_FORM_addrx = 0x1B
DW_FORM_ref_sup4 = 0x1C
DW_FORM_strp_sup = 0x1D
DW_FORM_data16 = 0x1E
DW_FORM_line_strp = 0x1F
DW_FORM_ref_sig8 = 0x20
DW_FORM_implicit_const = 0x21
DW_FORM_loclistx = 0x22
DW_FORM_rnglistx = 0x23
DW_FORM_ref_sup8 = 0x24
DW_FORM_strx1 = 0x25
DW_FORM_strx2 = 0x26
DW_FORM_strx3 = 0x27
DW_FORM_strx4 = 0x28
DW_FORM_addrx1 = 0x29
DW_FORM_addrx2 = 0x2A
DW_FORM_addrx3 = 0x2B
DW_FORM_addrx4 = 0x2C

_META_SECTIONS = frozenset(
    {".debug_info", ".debug_abbrev", ".debug_str", ".debug_line_str",
     ".debug_str_offsets", ".debug_addr", ".eh_frame"}
)


class _Malformed(Exception):
    """Internal bounded-parse failure, converted into a DWARF warning."""


def _cstr(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


def _str_at(blob: bytes, offset: int) -> str | None:
    text = _cstr(blob, offset)
    return text or None


def _indexed_value(blob: bytes, base: int, index: int, size: int,
                   order: str, strings: bytes | None = None) -> Any:
    """Resolve a DW_FORM_strx/addrx index through .debug_str_offsets/.debug_addr."""
    if not blob or base < 0 or index < 0:
        return None
    pos = base + index * size
    if pos < 0 or pos + size > len(blob):
        return None
    value = int.from_bytes(blob[pos:pos + size], order)
    return _str_at(strings, value) if strings is not None else value


def _uint(blob: bytes, pos: int, size: int, order: str) -> int:
    if size < 1 or pos < 0 or pos + size > len(blob):
        raise _Malformed("truncated integer")
    return int.from_bytes(blob[pos:pos + size], order)


def _uleb(blob: bytes, pos: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < end:
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 70:
            raise _Malformed("oversized ULEB128")
    raise _Malformed("truncated ULEB128")


def _sleb(blob: bytes, pos: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < end:
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos
        if shift > 70:
            raise _Malformed("oversized SLEB128")
    raise _Malformed("truncated SLEB128")


def _header(data: bytes) -> dict[str, Any]:
    if data[:4] != MAGIC:
        raise ValueError(f"not an ELF file: {data[:4].hex()}")
    if len(data) < 16:
        raise ValueError("truncated ELF header")
    elf_class, elf_data = data[4], data[5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        raise ValueError(f"unsupported ELF identification: {data[:16].hex()}")
    bits = 64 if elf_class == 2 else 32
    order = "little" if elf_data == 1 else "big"
    prefix = "<" if elf_data == 1 else ">"
    minimum = 64 if bits == 64 else 52
    if len(data) < minimum:
        raise ValueError("truncated ELF header")
    fmt = prefix + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    keys = ("e_type", "e_machine", "e_version", "e_entry", "e_phoff", "e_shoff",
            "e_flags", "e_ehsize", "e_phentsize", "e_phnum", "e_shentsize",
            "e_shnum", "e_shstrndx")
    header = dict(zip(keys, struct.unpack_from(fmt, data, 16)))
    header.update(bits=bits, endian=order, prefix=prefix)
    return header


def _sections(data: bytes, header: dict[str, Any]) -> list[dict[str, Any]]:
    shoff = header["e_shoff"]
    entsize = header["e_shentsize"]
    if not shoff or not entsize:
        return []
    native = 64 if header["bits"] == 64 else 40
    if entsize < native or shoff + native > len(data):
        raise ValueError("truncated ELF section table")
    fmt = header["prefix"] + ("IIQQQQIIQQ" if header["bits"] == 64
                              else "IIIIIIIIII")
    keys = ("name", "type", "flags", "addr", "offset", "size", "link",
            "info", "addralign", "entsize")

    def read(index: int) -> dict[str, Any]:
        pos = shoff + index * entsize
        if pos + native > len(data):
            raise ValueError("truncated ELF section table")
        return dict(zip(keys, struct.unpack_from(fmt, data, pos)), index=index)

    count = header["e_shnum"]
    if count == 0:
        count = read(0)["size"]
    if count > MAX_SECTIONS or shoff + count * entsize > len(data):
        raise ValueError("truncated ELF section table")
    sections = [read(i) for i in range(count)]
    shstrndx = header["e_shstrndx"]
    if shstrndx == 0xFFFF and sections:
        shstrndx = sections[0]["link"]
    strings = b""
    if 0 <= shstrndx < len(sections):
        table = sections[shstrndx]
        if table["type"] != SHT_NOBITS:
            strings = data[table["offset"]:table["offset"] + table["size"]]
    for section in sections:
        section["name"] = _cstr(strings, section["name"])
    return sections


def _section(sections: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    return next((s for s in sections if s["name"] == name), None)


def _section_bytes(data: bytes, section: dict[str, Any] | None) -> bytes:
    if section is None or section["type"] == SHT_NOBITS:
        return b""
    offset, size = section["offset"], section["size"]
    if offset < 0 or size < 0 or offset + size > len(data):
        return b""
    return data[offset:offset + size]


def _notes(data: bytes, sections: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    result: dict[str, Any] = {"build_id": None, "abi_tag": None,
                              "gnu_property": False}
    header = prefix + "III"
    for section in sections:
        if section["type"] != SHT_NOTE:
            continue
        blob = _section_bytes(data, section)
        pos = 0
        while pos + 12 <= len(blob):
            namesz, descsz, ntype = struct.unpack_from(header, blob, pos)
            pos += 12
            name_end = pos + namesz
            if name_end > len(blob):
                break
            name = blob[pos:name_end].rstrip(b"\0").decode("utf-8", "replace")
            pos = (name_end + 3) & ~3
            desc_end = pos + descsz
            if desc_end > len(blob):
                break
            desc = blob[pos:desc_end]
            pos = (desc_end + 3) & ~3
            if name != "GNU":
                continue
            if ntype == 3 and result["build_id"] is None:
                result["build_id"] = desc.hex()
            elif ntype == 1 and result["abi_tag"] is None:
                result["abi_tag"] = _str_at(desc.rstrip(b"\0"), 0)
            elif ntype == 5:
                result["gnu_property"] = True
    return result


def _abbrevs(blob: bytes, offset: int, order: str) -> dict[int, list[tuple]]:
    if offset < 0 or offset >= len(blob):
        raise _Malformed("abbrev offset out of range")
    table: dict[int, list[tuple]] = {}
    pos = offset
    for _ in range(MAX_ABBREVS):
        code, pos = _uleb(blob, pos, len(blob))
        if code == 0:
            break
        _tag, pos = _uleb(blob, pos, len(blob))
        if pos >= len(blob):
            raise _Malformed("truncated abbrev declaration")
        pos += 1  # DW_CHILDREN
        decl: list[tuple] = []
        for _ in range(MAX_ABBREVS):
            attr, pos = _uleb(blob, pos, len(blob))
            form, pos = _uleb(blob, pos, len(blob))
            if attr == 0 and form == 0:
                break
            implicit = None
            if form == DW_FORM_implicit_const:
                implicit, pos = _sleb(blob, pos, len(blob))
            decl.append((attr, form, implicit))
        table[code] = decl
    return table


def _read_form(blob: bytes, pos: int, end: int, form: int, ctx: dict[str, Any],
               implicit: int | None) -> tuple[Any, int]:
    order = ctx["order"]
    if form == DW_FORM_implicit_const:
        return implicit, pos
    if form == DW_FORM_flag_present:
        return True, pos
    if form == DW_FORM_indirect:
        actual, pos = _uleb(blob, pos, end)
        if actual == DW_FORM_indirect:
            raise _Malformed("recursive indirect form")
        return _read_form(blob, pos, end, actual, ctx, None)
    if form == DW_FORM_string:
        stop = blob.find(b"\0", pos, end)
        if stop < 0:
            raise _Malformed("unterminated string form")
        return blob[pos:stop].decode("utf-8", "replace"), stop + 1
    if form == DW_FORM_addr:
        size = ctx["addr_size"]
        return _uint(blob, pos, size, order), pos + size
    if form in (DW_FORM_strp, DW_FORM_line_strp, DW_FORM_sec_offset,
                DW_FORM_strp_sup):
        size = ctx["offset_size"]
        value = _uint(blob, pos, size, order)
        pos += size
        if form == DW_FORM_strp:
            return _str_at(ctx["debug_str"], value), pos
        if form == DW_FORM_line_strp:
            return _str_at(ctx["debug_line_str"], value), pos
        return value, pos
    if form in (DW_FORM_block2, DW_FORM_block4, DW_FORM_block, DW_FORM_block1,
                DW_FORM_exprloc):
        if form == DW_FORM_block2:
            size = _uint(blob, pos, 2, order)
            pos += 2
        elif form == DW_FORM_block4:
            size = _uint(blob, pos, 4, order)
            pos += 4
        elif form == DW_FORM_block1:
            size = _uint(blob, pos, 1, order)
            pos += 1
        else:
            size, pos = _uleb(blob, pos, end)
        if pos + size > end:
            raise _Malformed("truncated block form")
        return None, pos + size
    if form in (DW_FORM_strx1, DW_FORM_strx2, DW_FORM_strx3, DW_FORM_strx4):
        size = form - DW_FORM_strx1 + 1
        return ("strx", _uint(blob, pos, size, order)), pos + size
    if form in (DW_FORM_addrx1, DW_FORM_addrx2, DW_FORM_addrx3, DW_FORM_addrx4):
        size = form - DW_FORM_addrx1 + 1
        return ("addrx", _uint(blob, pos, size, order)), pos + size
    if form in (DW_FORM_strx, DW_FORM_addrx, DW_FORM_loclistx,
                DW_FORM_rnglistx):
        index, pos = _uleb(blob, pos, end)
        if form == DW_FORM_strx:
            return ("strx", index), pos
        if form == DW_FORM_addrx:
            return ("addrx", index), pos
        return index, pos
    if form == DW_FORM_sdata:
        return _sleb(blob, pos, end)
    if form in (DW_FORM_udata, DW_FORM_ref_udata):
        return _uleb(blob, pos, end)
    sizes = {
        DW_FORM_data1: 1, DW_FORM_flag: 1, DW_FORM_ref1: 1,
        DW_FORM_data2: 2, DW_FORM_ref2: 2,
        DW_FORM_data4: 4, DW_FORM_ref4: 4, DW_FORM_ref_sup4: 4,
        DW_FORM_data8: 8, DW_FORM_ref8: 8, DW_FORM_ref_sig8: 8,
        DW_FORM_ref_sup8: 8, DW_FORM_data16: 16,
        DW_FORM_ref_addr: ctx["addr_size"],
    }
    if form in sizes:
        size = sizes[form]
        return _uint(blob, pos, size, order), pos + size
    raise _Malformed(f"unsupported form 0x{form:02x}")


def _parse_unit(blob: bytes, pos: int, end: int, ctx: dict[str, Any],
                cache: dict[int, dict[int, list[tuple]]]) -> dict[str, Any]:
    unit: dict[str, Any] = {"name": None, "producer": None,
                            "low_pc": None, "high_pc": None}
    order = ctx["order"]
    version = _uint(blob, pos, 2, order)
    pos += 2
    if version < 2 or version > 5:
        raise _Malformed(f"unsupported DWARF version {version}")
    unit_type = 1
    if version >= 5:
        unit_type = _uint(blob, pos, 1, order)
        pos += 1
        addr_size = _uint(blob, pos, 1, order)
        pos += 1
        abbrev_off = _uint(blob, pos, ctx["offset_size"], order)
        pos += ctx["offset_size"]
    else:
        abbrev_off = _uint(blob, pos, ctx["offset_size"], order)
        pos += ctx["offset_size"]
        addr_size = _uint(blob, pos, 1, order)
        pos += 1
    if addr_size == 0 or addr_size > 16:
        raise _Malformed("invalid address size")
    if version >= 5 and unit_type in (0x02, 0x05, 0x06):
        if pos + 8 > end:
            raise _Malformed("truncated dwo id")
        pos += 8
    code, pos = _uleb(blob, pos, end)
    if code == 0:
        return unit
    if abbrev_off not in cache:
        cache[abbrev_off] = _abbrevs(ctx["debug_abbrev"], abbrev_off, order)
    decl = cache[abbrev_off].get(code)
    if decl is None:
        raise _Malformed(f"abbrev {code} not found")
    local = dict(ctx, addr_size=addr_size)
    raw: dict[int, Any] = {}
    for attr, form, implicit in decl:
        value, pos = _read_form(blob, pos, end, form, local, implicit)
        raw[attr] = value
    # DWARF5 strx/addrx forms are indices; resolve them only after the whole
    # DIE is read, because *_base attributes may appear after the name.
    str_offsets = ctx["debug_str_offsets"]
    default_str_base = (16 if len(str_offsets) >= 4 and
                        int.from_bytes(str_offsets[:4], order) == 0xFFFFFFFF
                        else 8)
    str_base = raw.get(DW_AT_str_offsets_base, default_str_base)
    if not isinstance(str_base, int):
        str_base = default_str_base
    addr_base = raw.get(DW_AT_addr_base, 8)
    if not isinstance(addr_base, int):
        addr_base = 8
    for attr, field in _FIELDS.items():
        value = raw.get(attr)
        if isinstance(value, tuple):
            kind, index = value
            if kind == "strx":
                value = _indexed_value(str_offsets, str_base, index,
                                       ctx["offset_size"], order,
                                       ctx["debug_str"])
            elif kind == "addrx":
                value = _indexed_value(ctx["debug_addr"], addr_base, index,
                                       addr_size, order)
        unit[field] = value
    return unit


def _dwarf(data: bytes, sections: list[dict[str, Any]],
           prefix: str) -> dict[str, Any]:
    blob = _section_bytes(data, _section(sections, ".debug_info"))
    result: dict[str, Any] = {"units": [], "count": 0, "warnings": []}
    if not blob:
        return result
    ctx = {
        "order": "little" if prefix == "<" else "big",
        "offset_size": 4,
        "debug_str": _section_bytes(data, _section(sections, ".debug_str")),
        "debug_line_str": _section_bytes(data, _section(sections, ".debug_line_str")),
        "debug_str_offsets": _section_bytes(
            data, _section(sections, ".debug_str_offsets")),
        "debug_addr": _section_bytes(data, _section(sections, ".debug_addr")),
        "debug_abbrev": _section_bytes(data, _section(sections, ".debug_abbrev")),
    }
    cache: dict[int, dict[int, list[tuple]]] = {}
    pos = 0
    while pos + 4 <= len(blob) and len(result["units"]) < MAX_UNITS:
        start = pos
        length = _uint(blob, pos, 4, ctx["order"])
        pos += 4
        ctx["offset_size"] = 4
        if length == 0xFFFFFFFF:  # DWARF64 marker
            length = _uint(blob, pos, 8, ctx["order"])
            pos += 8
            ctx["offset_size"] = 8
        if length == 0 or pos + length > len(blob):
            result["warnings"].append(
                f"unit at {start}: invalid length {length}")
            break
        end = pos + length
        try:
            unit = _parse_unit(blob, pos, end, ctx, cache)
        except _Malformed as exc:
            result["warnings"].append(f"unit at {start}: {exc}")
        except (struct.error, IndexError, ValueError, UnicodeError) as exc:
            result["warnings"].append(f"unit at {start}: unexpected {exc}")
        else:
            result["units"].append(unit)
        if end <= start:
            break
        pos = end
    result["count"] = len(result["units"])
    if len(result["units"]) >= MAX_UNITS and pos + 4 <= len(blob):
        result["warnings"].append(f"stopped after {MAX_UNITS} compile units")
    return result


def _unwind(data: bytes, sections: list[dict[str, Any]],
            prefix: str) -> dict[str, Any]:
    result: dict[str, Any] = {"fde_count": 0, "cie_count": 0,
                              "truncated": False}
    blob = _section_bytes(data, _section(sections, ".eh_frame"))
    order = "little" if prefix == "<" else "big"
    pos = 0
    seen = 0
    while pos + 4 <= len(blob):
        length = _uint(blob, pos, 4, order)
        if length == 0:  # terminator
            break
        header = 4
        if length == 0xFFFFFFFF:
            if pos + 12 > len(blob):
                result["truncated"] = True
                break
            length = _uint(blob, pos + 4, 8, order)
            header = 12
        end = pos + header + length
        if end > len(blob):
            result["truncated"] = True
            break
        id_size = 8 if header == 12 else 4
        cie_id = _uint(blob, pos + header, id_size, order)
        if cie_id == 0:
            result["cie_count"] += 1
        else:
            result["fde_count"] += 1
        seen += 1
        if seen >= MAX_RECS:
            result["truncated"] = True
            break
        pos = end
    return result


def report(path: str | Path) -> dict[str, Any]:
    """Return notes, DWARF compile units and unwind ranges for an ELF file.

    Raises :class:`ValueError` only for a non-ELF file or a truncated ELF
    header/section table. Malformed DWARF is reported in ``dwarf["warnings"]``.
    """
    data = Path(path).read_bytes()
    header = _header(data)
    sections = _sections(data, header)
    prefix = header["prefix"]
    try:
        notes = _notes(data, sections, prefix)
    except (struct.error, IndexError, UnicodeError, ValueError):
        notes = {"build_id": None, "abi_tag": None, "gnu_property": False}
    try:
        dwarf = _dwarf(data, sections, prefix)
    except (struct.error, IndexError, UnicodeError, ValueError) as exc:
        dwarf = {"units": [], "count": 0, "warnings": [f"section: {exc}"]}
    try:
        unwind = _unwind(data, sections, prefix)
    except (struct.error, IndexError, ValueError):
        unwind = {"fde_count": 0, "cie_count": 0, "truncated": True}
    reported = sum(1 for s in sections
                   if s["type"] == SHT_NOTE or s["name"] in _META_SECTIONS)
    return {
        "ok": True,
        "path": str(path),
        "format": "elf",
        "bits": header["bits"],
        "endian": header["endian"],
        "notes": notes,
        "dwarf": dwarf,
        "unwind": unwind,
        "sections_reported": reported,
    }
