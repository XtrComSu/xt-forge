"""Mach-O hardening checks.

`re checksec` answered for ELF and PE only, so an iOS or macOS binary — where these
questions matter most — got "unrecognized binary format". The header and load commands
answer most of it directly, and the undefined symbol table answers the rest.

Everything here reads the file; nothing is inferred from a string match inside code.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

MH_PIE = 0x00200000
MH_NO_HEAP_EXECUTION = 0x01000000
# The value matters: 0x10000 is MH_BINDS_TO_WEAK, not stack execution. Using it made a
# hardened iOS app report nx_stack False. Confirmed against llvm-objdump, which prints
# BINDS_TO_WEAK for a word with 0x10000 set.
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_TWOLEVEL = 0x00000080

LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_MACOSX = 0x24

ARMV7 = 12
ARM64 = 0x0100000C
X86_64 = 0x01000007
CPU_NAMES = {ARM64: "arm64", ARMV7: "armv7", X86_64: "x86_64"}


class MachOError(Exception):
    """Raised when a file is not a Mach-O image this module can read."""


def _slice(data: bytes, arch: str = "") -> tuple[bytes, int]:
    """Return (slice bytes, cputype) for the requested architecture, or the first slice."""
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_CIGAM):
        return data, struct.unpack("<I", data[4:8])[0]
    count = struct.unpack(">I", data[4:8])[0]
    if count == 0 or count > 32:
        raise MachOError("fat header declares an implausible slice count")
    chosen = None
    for index in range(count):
        base = 8 + index * 20
        if base + 20 > len(data):
            break
        cputype, _sub, offset, size, _align = struct.unpack(">5I", data[base:base + 20])
        if chosen is None:
            chosen = (cputype, offset, size)
        wanted = {"arm64": ARM64, "armv7": ARMV7}.get(arch.lower())
        if wanted is not None and cputype == wanted:
            chosen = (cputype, offset, size)
            break
    if chosen is None:
        raise MachOError("fat binary has no readable slices")
    cputype, offset, size = chosen
    return data[offset:offset + size], cputype


def _header_and_commands(slice_bytes: bytes) -> tuple[dict[str, int], list[tuple[int, int]]]:
    magic = struct.unpack("<I", slice_bytes[:4])[0]
    if magic == MH_MAGIC_64:
        cputype, _sub, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            "<6I", slice_bytes[4:28])
        header_size = 32
    elif magic == MH_MAGIC:
        cputype, _sub, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            "<6I", slice_bytes[4:28])
        header_size = 28
    else:
        raise MachOError("not a Mach-O image")
    if ncmds > 4096:
        raise MachOError("implantable load-command count")
    commands: list[tuple[int, int]] = []
    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > len(slice_bytes):
            break
        command, size = struct.unpack("<2I", slice_bytes[offset:offset + 8])
        if size < 8:
            break
        commands.append((command, offset))
        offset += size
    return ({"cputype": cputype, "filetype": filetype, "ncmds": ncmds,
             "flags": flags}, commands)


def _undefined_symbols(slice_bytes: bytes, header_size: int, commands: list[tuple[int, int]]) -> list[str]:
    """Names of undefined (imported) symbols, read through LC_SYMTAB."""
    for command, offset in commands:
        if command != LC_SYMTAB:
            continue
        symoff, nsyms, stroff, strsize = struct.unpack("<4I", slice_bytes[offset + 8:offset + 24])
        entry = 16 if struct.unpack("<I", slice_bytes[:4])[0] == MH_MAGIC_64 else 12
        names: list[str] = []
        for index in range(min(nsyms, 200000)):
            base = symoff + index * entry
            if base + entry > len(slice_bytes):
                break
            strx, ntype = struct.unpack("<IB", slice_bytes[base:base + 5])
            # N_TYPE is bits 1-3: N_UNDF (0x0) means imported, N_SECT (0xe) means defined
            # here. Checking only N_EXT (bit 0) counted every defined symbol as an import,
            # which made a freestanding binary report three.
            if (ntype & 0x0E) != 0 or not ntype & 0x01:
                continue
            if strx >= strsize:
                continue
            start = stroff + strx
            end = slice_bytes.find(b"\x00", start)
            if end < 0:
                continue
            names.append(slice_bytes[start:end].decode("latin-1"))
        return names
    return []


def checksec(path: str | Path, arch: str = "") -> dict[str, Any]:
    """Hardening summary for a Mach-O image."""
    resolved = Path(path)
    data = resolved.read_bytes()
    slice_bytes, cputype = _slice(data, arch)
    header, commands = _header_and_commands(slice_bytes)
    flags = header["flags"]
    command_set = {command for command, _ in commands}
    names = _undefined_symbols(
        slice_bytes,
        32 if struct.unpack("<I", slice_bytes[:4])[0] == MH_MAGIC_64 else 28,
        commands)

    def present(*needles: str) -> bool:
        return any(name in names for name in needles)

    encryption = bool(command_set & {LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64})
    # Count occurrences, not distinct command types. command_set collapses duplicates, so
    # a binary with thirteen LC_LOAD_DYLIB plus fourteen LC_LOAD_WEAK_DYLIB reported two.
    dylib_commands = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB)
    dylibs = len([command for command, _ in commands if command in dylib_commands])
    return {
        "ok": True,
        "path": str(resolved),
        "format": "macho",
        "engine": "python",
        "arch": CPU_NAMES.get(cputype, hex(cputype)),
        "file_type": "executable" if header["filetype"] == 2 else hex(header["filetype"]),
        "flags": hex(flags),
        "pie": bool(flags & MH_PIE),
        "nx_stack": not bool(flags & MH_ALLOW_STACK_EXECUTION),
        "nx_heap": bool(flags & MH_NO_HEAP_EXECUTION),
        "two_level_namespace": bool(flags & MH_TWOLEVEL),
        "code_signed": LC_CODE_SIGNATURE in command_set,
        "encrypted": encryption,
        "stack_canary": present("___stack_chk_fail", "___stack_chk_guard"),
        "arc": present("_objc_release", "_objc_retain"),
        "fortify": any("_chk" in name for name in names),
        "imports": len(names),
        "dylibs": dylibs,
        "undefined_sample": names[:10],
    }
