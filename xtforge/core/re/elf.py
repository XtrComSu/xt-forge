"""Dependency-free ELF inspection (headers, sections, symbols, dynamic, strings)."""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from ..route import guard

MAGIC = b"\x7fELF"
MAX_BYTES = 256 * 1024 * 1024

TYPE_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACHINE_NAMES = {
    3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64",
    183: "AArch64", 243: "RISC-V",
}
SECTION_TYPE_NAMES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
    5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
    10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
    16: "PREINIT_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX",
}
SYM_TYPE_NAMES = {
    0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
    5: "COMMON", 6: "TLS", 10: "GNU_IFUNC",
}
SYM_BIND_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE"}


class ElfError(ValueError):
    """Raised when a file is not a readable ELF object."""


def _unpack(fmt: str, data: bytes, offset: int) -> tuple:
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error as exc:
        raise ElfError(f"truncated ELF at offset {offset}") from exc


def _slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ElfError(f"truncated ELF at offset {offset}")
    return data[offset:offset + size]


def _cstr(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _load(path: str | Path) -> tuple[Path, bytes]:
    resolved = guard.check_allowed(path)
    if not resolved.exists():
        raise ElfError(f"file not found: {path}")
    if not resolved.is_file():
        raise ElfError(f"not a regular file: {path}")
    size = resolved.stat().st_size
    if size > MAX_BYTES:
        raise ElfError(f"file too large for ELF inspection: {size} bytes")
    try:
        return resolved, resolved.read_bytes()
    except OSError as exc:
        raise ElfError(f"cannot read {path}: {exc}") from exc


def _header(data: bytes) -> dict[str, Any]:
    if len(data) < 16 or data[:4] != MAGIC:
        raise ElfError("not an ELF file")
    elf_class, elf_data = data[4], data[5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        raise ElfError("unsupported ELF ident")
    bits = 64 if elf_class == 2 else 32
    endian = "<" if elf_data == 1 else ">"
    if bits == 64:
        values = _unpack(endian + "HHIQQQIHHHHHH", data, 16)
    else:
        values = _unpack(endian + "HHIIIIIHHHHHH", data, 16)
    keys = ("type", "machine", "version", "entry", "phoff", "shoff", "flags",
            "ehsize", "phentsize", "phnum", "shentsize", "shnum", "shstrndx")
    header = dict(zip(keys, values))
    header.update(bits=bits, endian=endian,
                  endianness="little" if elf_data == 1 else "big")
    return header


def _programs(data: bytes, header: dict[str, Any]) -> list[dict[str, Any]]:
    if not header["phoff"] or not header["phentsize"]:
        return []
    fmt = header["endian"] + ("IIQQQQQQ" if header["bits"] == 64 else "IIIIIIII")
    keys = ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align")
    count = header["phnum"]
    if count == 0xFFFF:
        sections = _sections(data, header)
        count = sections[0]["link"] if sections else 0
    out = []
    for index in range(min(count, 10000)):
        values = _unpack(fmt, data, header["phoff"] + index * header["phentsize"])
        out.append(dict(zip(keys, values), index=index))
    return out


def _sections(data: bytes, header: dict[str, Any]) -> list[dict[str, Any]]:
    if not header["shoff"] or not header["shentsize"]:
        return []
    fmt = header["endian"] + ("IIQQQQIIQQ" if header["bits"] == 64
                              else "IIIIIIIIII")
    keys = ("name_off", "type", "flags", "addr", "offset", "size", "link",
            "info", "addralign", "entsize")
    count = header["shnum"]
    if count == 0:
        values = _unpack(fmt, data, header["shoff"])
        count = values[5]
    out = []
    for index in range(min(count, 10000)):
        values = _unpack(fmt, data, header["shoff"] + index * header["shentsize"])
        out.append(dict(zip(keys, values), index=index, name=""))
    shstrndx = header["shstrndx"]
    if shstrndx == 0xFFFF and out:
        shstrndx = out[0]["link"]
    if 0 <= shstrndx < len(out):
        strtab_sec = out[shstrndx]
        strtab = _slice(data, strtab_sec["offset"], strtab_sec["size"])
        for section in out:
            section["name"] = _cstr(strtab, section["name_off"])
    return out


def _dynamic(data: bytes, header: dict[str, Any],
             sections: list[dict[str, Any]]) -> dict[str, Any]:
    needed: list[str] = []
    soname = None
    rpath = None
    runpath = None
    fmt = header["endian"] + ("qQ" if header["bits"] == 64 else "iI")
    ent = 16 if header["bits"] == 64 else 8
    for section in sections:
        if section["type"] != 6 or not section["size"]:
            continue
        strtab = b""
        if 0 <= section["link"] < len(sections):
            target = sections[section["link"]]
            strtab = _slice(data, target["offset"], target["size"])
        count = section["size"] // (section["entsize"] or ent)
        for index in range(min(count, 10000)):
            tag, val = _unpack(fmt, data, section["offset"] + index * ent)
            if tag == 1:
                name = _cstr(strtab, val)
                if name and name not in needed:
                    needed.append(name)
            elif tag == 14:
                soname = _cstr(strtab, val)
            elif tag == 15:
                rpath = _cstr(strtab, val)
            elif tag == 29:
                runpath = _cstr(strtab, val)
    return {"needed": needed, "soname": soname, "rpath": rpath, "runpath": runpath}


def _build_id(data: bytes, programs: list[dict[str, Any]],
              sections: list[dict[str, Any]]) -> str | None:
    regions = [(p["offset"], p["filesz"]) for p in programs if p["type"] == 4]
    regions += [(s["offset"], s["size"]) for s in sections if s["type"] == 7]
    for offset, size in regions:
        if not size:
            continue
        try:
            blob = _slice(data, offset, size)
        except ElfError:
            continue
        pos = 0
        while pos + 12 <= len(blob):
            namesz, descsz, ntype = _unpack("III", blob, pos)
            pos += 12
            if pos + namesz > len(blob):
                break
            name = blob[pos:pos + namesz].rstrip(b"\0")
            pos = _align4(pos + namesz)
            if pos + descsz > len(blob):
                break
            desc = blob[pos:pos + descsz]
            pos = _align4(pos + descsz)
            if ntype == 3 and name == b"GNU":
                return desc.hex()
    return None


def info(path: str | Path) -> dict[str, Any]:
    resolved, data = _load(path)
    header = _header(data)
    sections = _sections(data, header)
    programs = _programs(data, header)
    interpreter = None
    for program in programs:
        if program["type"] == 3:
            interpreter = _slice(data, program["offset"], program["filesz"])
            interpreter = interpreter.rstrip(b"\0").decode("utf-8", "replace")
            break
    dynamic = _dynamic(data, header, sections)
    return {
        "ok": True,
        "path": str(resolved),
        "size": len(data),
        "class": f"ELF{header['bits']}",
        "endianness": header["endianness"],
        "type": TYPE_NAMES.get(header["type"], f"type-{header['type']}"),
        "type_id": header["type"],
        "machine": MACHINE_NAMES.get(header["machine"],
                                     f"machine-{header['machine']}"),
        "machine_id": header["machine"],
        "entry": hex(header["entry"]),
        "interpreter": interpreter,
        "soname": dynamic["soname"],
        "needed_count": len(dynamic["needed"]),
        "build_id": _build_id(data, programs, sections),
        "program_headers": len(programs),
        "section_headers": len(sections),
    }


def needed(path: str | Path) -> dict[str, Any]:
    resolved, data = _load(path)
    header = _header(data)
    dynamic = _dynamic(data, header, _sections(data, header))
    return {"ok": True, "path": str(resolved), **dynamic}


def sections(path: str | Path) -> dict[str, Any]:
    resolved, data = _load(path)
    header = _header(data)
    out = []
    for section in _sections(data, header):
        out.append({
            "index": section["index"],
            "name": section["name"],
            "type": SECTION_TYPE_NAMES.get(section["type"],
                                          f"type-{section['type']}"),
            "type_id": section["type"],
            "flags": hex(section["flags"]),
            "addr": hex(section["addr"]),
            "offset": section["offset"],
            "size": section["size"],
        })
    return {"ok": True, "path": str(resolved), "sections": out}


def symbols(path: str | Path, limit: int = 500) -> dict[str, Any]:
    resolved, data = _load(path)
    header = _header(data)
    structs = _sections(data, header)
    fmt = header["endian"] + ("IBBHQQ" if header["bits"] == 64 else "IIIBBH")
    ent = 24 if header["bits"] == 64 else 16
    out: list[dict[str, Any]] = []
    total = 0
    truncated = False
    tables: list[str] = []
    for section in structs:
        if section["type"] not in (2, 11):
            continue
        tables.append("symtab" if section["type"] == 2 else "dynsym")
        strtab = b""
        if 0 <= section["link"] < len(structs):
            target = structs[section["link"]]
            strtab = _slice(data, target["offset"], target["size"])
        count = section["size"] // (section["entsize"] or ent)
        for index in range(min(count, 10000)):
            values = _unpack(fmt, data, section["offset"] + index * ent)
            if header["bits"] == 64:
                name_off, info_, other, shndx, value, size = values
            else:
                name_off, value, size, info_, other, shndx = values
            name = _cstr(strtab, name_off)
            if not name:
                continue
            total += 1
            if len(out) >= limit:
                truncated = True
                continue
            out.append({
                "name": name,
                "value": hex(value),
                "size": size,
                "type": SYM_TYPE_NAMES.get(info_ & 0xF, str(info_ & 0xF)),
                "bind": SYM_BIND_NAMES.get(info_ >> 4, str(info_ >> 4)),
                "visibility": other & 0x3,
                "shndx": shndx,
                "table": "symtab" if section["type"] == 2 else "dynsym",
            })
    return {"ok": True, "path": str(resolved), "symbols": out, "count": total,
            "truncated": truncated, "tables": tables}


def strings(path: str | Path, min_len: int = 4,
            limit: int = 200) -> dict[str, Any]:
    resolved, data = _load(path)
    minimum = max(1, int(min_len))
    cap = max(1, int(limit))
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    out: list[str] = []
    seen: set[str] = set()
    truncated = False
    for match in pattern.finditer(data):
        text = match.group().decode("ascii")
        if text in seen:
            continue
        seen.add(text)
        if len(out) >= cap:
            truncated = True
            break
        out.append(text)
    return {"ok": True, "path": str(resolved), "min": minimum, "limit": cap,
            "strings": out, "truncated": truncated}
