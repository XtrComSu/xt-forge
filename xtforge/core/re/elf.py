"""Dependency-free ELF inspection (headers, sections, symbols, dynamic, strings, entropy)."""
from __future__ import annotations

import math
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
    bind_now = False
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
            elif tag == 24:  # DT_BIND_NOW
                bind_now = True
            elif tag == 29:
                runpath = _cstr(strtab, val)
            elif tag == 30 and (val & 0x8):  # DT_FLAGS & DF_BIND_NOW
                bind_now = True
            elif tag == 0x6FFFFFFB and (val & 0x1):  # DT_FLAGS_1 & DF_1_NOW
                bind_now = True
    return {"needed": needed, "soname": soname, "rpath": rpath, "runpath": runpath, "bind_now": bind_now}


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


def _shannon_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts if n)


def entropy(path: str | Path, block: int = 0,
            limit: int = 32) -> dict[str, Any]:
    """Byte entropy (bits/char) overall and per block.

    High entropy (≈7.0+) means packed, compressed or encrypted content; low
    entropy means text or structured data. Useful for spotting a packed
    payload hiding in an otherwise ordinary file.
    """
    resolved, data = _load(path)
    if not data:
        return {"ok": False, "err": "empty_file", "path": str(resolved)}
    overall = round(_shannon_bytes(data), 3)

    def verdict(value: float) -> str:
        if value >= 7.0:
            return "packed_or_encrypted"
        if value >= 5.5:
            return "mixed"
        if value >= 3.5:
            return "structured"
        return "low"

    out: dict[str, Any] = {
        "ok": True, "path": str(resolved), "bytes": len(data),
        "entropy": overall, "verdict": verdict(overall),
    }
    if block and block > 0:
        size = max(16, int(block))
        blocks = []
        for offset in range(0, len(data), size):
            chunk = data[offset:offset + size]
            value = round(_shannon_bytes(chunk), 3)
            blocks.append({"offset": offset, "size": len(chunk),
                           "entropy": value, "verdict": verdict(value)})
            if len(blocks) >= max(1, int(limit)):
                break
        out["block_size"] = size
        out["blocks"] = blocks
        out["truncated"] = len(data) > size * len(blocks)
    return out


def pack(path: str | Path) -> dict[str, Any]:
    """Packing triage: is this binary hiding something?

    Packed or encrypted payloads show high entropy *and* few recoverable
    strings, so the two signals together are far more reliable than entropy
    alone. Works on ELF; degrades to byte-level triage for anything else.
    """
    resolved, data = _load(path)
    if not data:
        return {"ok": False, "err": "empty_file", "path": str(resolved)}
    overall = round(_shannon_bytes(data), 3)

    string_re = re.compile(rb"[\x20-\x7e]{6,}")
    long_re = re.compile(rb"[\x20-\x7e]{20,}")
    strings = string_re.findall(data)
    long_strings = long_re.findall(data)
    density = round(len(strings) * 1024 / max(1, len(data)), 3)
    long_density = round(len(long_strings) * 1024 / max(1, len(data)), 3)
    avg_len = round(sum(len(s) for s in strings) / len(strings), 1) if strings else 0

    section_rows: list[dict[str, Any]] = []
    try:
        info = sections(resolved)
        for section in info.get("sections", []):
            offset, size = section.get("offset"), section.get("size")
            if not offset or not size or size < 64:
                continue
            chunk = data[offset:offset + size]
            if not chunk:
                continue
            section_rows.append({"name": section.get("name"),
                                 "size": size,
                                 "entropy": round(_shannon_bytes(chunk), 3)})
        section_rows.sort(key=lambda s: -s["entropy"])
    except (ElfError, ValueError, OSError):
        section_rows = []                        # not an ELF: byte triage only

    hot = [s for s in section_rows if s["entropy"] >= 7.0]
    # Long strings are the tell: random-looking bytes still produce short
    # printable runs by chance, but not 20-character ones.
    if overall >= 7.0 and long_density < 0.5:
        verdict = "likely_packed_or_encrypted"
    elif hot and long_density < 2.0:
        verdict = "suspicious_section"
    elif overall >= 6.0:
        verdict = "mixed"
    else:
        verdict = "normal"

    return {"ok": True, "path": str(resolved), "bytes": len(data),
            "entropy": overall, "strings": len(strings),
            "long_strings": len(long_strings),
            "string_density_per_kb": density,
            "long_string_density_per_kb": long_density,
            "avg_string_len": avg_len,
            "sections": section_rows[:10], "hot_sections": len(hot),
            "verdict": verdict,
            "note": ("high entropy with few long strings usually means packing, "
                     "encryption or a compressed payload")}


def checksec(path: str | Path) -> dict[str, Any]:
    """Inspect Linux ELF security hardening mitigations."""
    resolved, data = _load(path)
    hdr = _header(data)
    progs = _programs(data, hdr)
    secs = _sections(data, hdr)

    has_relro = any(p.get("type") == 0x6474E552 for p in progs)
    dyn = _dynamic(data, hdr, secs)
    if has_relro and dyn.get("bind_now"):
        relro_status = "Full"
    elif has_relro:
        relro_status = "Partial"
    else:
        relro_status = "No"

    try:
        sym_res = symbols(resolved)
        canary = any("stack_chk" in s.get("name", "") or "security_cookie" in s.get("name", "")
                     for s in sym_res.get("symbols", []))
    except Exception:
        canary = False

    gnu_stack = next((p for p in progs if p.get("type") == 0x6474E551), None)
    nx = True
    if gnu_stack and (gnu_stack.get("flags", 0) & 1):
        nx = False

    pie = hdr.get("type") == 3

    rpath = bool(dyn.get("rpath"))
    runpath = bool(dyn.get("runpath"))

    return {
        "relro": relro_status,
        "canary": canary,
        "nx": nx,
        "pie": pie,
        "rpath": rpath,
        "runpath": runpath,
    }

