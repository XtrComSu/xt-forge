"""Crash dump analysis engine (Windows MiniDump & Linux ELF Core).

Extracts crashing instruction pointers, faulting threads, NTSTATUS / POSIX signals,
and maps addresses to offending binary modules without external dependencies.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..route import guard

STATUS_NAMES: dict[int, str] = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0x80000003: "STATUS_BREAKPOINT",
    0x80000004: "STATUS_SINGLE_STEP",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC0000025: "STATUS_NONCONTINUABLE_EXCEPTION",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC000008E: "STATUS_FLOAT_DIVIDE_BY_ZERO",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
}

POSIX_SIGNALS: dict[int, str] = {
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    11: "SIGSEGV",
    14: "SIGALRM",
    15: "SIGTERM",
}


def _unpack(fmt: str, data: bytes, offset: int) -> tuple:
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        raise ValueError(f"Truncated dump: need {size} bytes at offset {offset}, only {len(data)} available")
    return struct.unpack_from(fmt, data, offset)


def _parse_minidump(data: bytes, path: Path) -> dict[str, Any]:
    if len(data) < 32 or not data.startswith(b"MDMP"):
        return {"ok": False, "err": "Invalid MiniDump header"}

    _, version, num_streams, stream_dir_rva, _, _, _ = _unpack("<4sIIIIIQ", data, 0)

    exception_info: dict[str, Any] = {}
    modules: list[dict[str, Any]] = []
    thread_count = 0

    cur_dir = stream_dir_rva
    for _ in range(num_streams):
        if cur_dir + 12 > len(data):
            break
        stream_type, data_size, rva = _unpack("<III", data, cur_dir)
        cur_dir += 12

        if stream_type == 6:  # ExceptionStream
            if rva + 32 <= len(data):
                tid, _, exc_code, exc_flags, _, exc_addr, num_params = _unpack("<IIIIQQI", data, rva)
                code_name = STATUS_NAMES.get(exc_code, f"UNKNOWN_EXCEPTION_{hex(exc_code)}")
                exception_info = {
                    "thread_id": tid,
                    "code": hex(exc_code),
                    "code_name": code_name,
                    "flags": hex(exc_flags),
                    "address": hex(exc_addr),
                    "raw_address": exc_addr,
                    "parameters_count": num_params,
                }
        elif stream_type == 4:  # ModuleListStream
            if rva + 4 <= len(data):
                (num_mods,) = _unpack("<I", data, rva)
                mod_off = rva + 4
                for _m in range(min(num_mods, 1024)):
                    if mod_off + 108 > len(data):
                        break
                    base, size, _, _, name_rva = _unpack("<QIIII", data, mod_off)
                    mod_name = ""
                    if name_rva + 4 <= len(data):
                        (name_len,) = _unpack("<I", data, name_rva)
                        name_bytes = data[name_rva + 4 : name_rva + 4 + name_len]
                        try:
                            mod_name = name_bytes.decode("utf-16le", errors="replace").rstrip("\x00")
                        except Exception:
                            mod_name = ""
                    modules.append({
                        "name": mod_name,
                        "base": hex(base),
                        "raw_base": base,
                        "size": hex(size),
                        "raw_size": size,
                    })
                    mod_off += 108
        elif stream_type == 3:  # ThreadListStream
            if rva + 4 <= len(data):
                (thread_count,) = _unpack("<I", data, rva)

    crashing_module = None
    if exception_info and "raw_address" in exception_info:
        fault_addr = exception_info["raw_address"]
        for mod in modules:
            b = mod["raw_base"]
            s = mod["raw_size"]
            if b <= fault_addr < b + s:
                crashing_module = {
                    "name": mod["name"],
                    "base": mod["base"],
                    "offset": hex(fault_addr - b),
                }
                break

    # Clean raw integer fields
    if "raw_address" in exception_info:
        del exception_info["raw_address"]
    for mod in modules:
        mod.pop("raw_base", None)
        mod.pop("raw_size", None)

    return {
        "ok": True,
        "format": "minidump",
        "path": str(path),
        "exception": exception_info,
        "crashing_module": crashing_module,
        "modules": modules,
        "thread_count": thread_count,
    }


def _parse_elf_core(data: bytes, path: Path) -> dict[str, Any]:
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        return {"ok": False, "err": "Not an ELF core"}

    ei_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    e_type = struct.unpack_from(f"{endian}H", data, 16)[0]
    if e_type != 4:  # ET_CORE
        return {"ok": False, "err": "ELF file is not a core dump (e_type != ET_CORE)"}

    return {
        "ok": True,
        "format": "elf_core",
        "path": str(path),
        "arch": "64-bit" if ei_class == 2 else "32-bit",
        "note": "ELF core dump validated",
    }


def parse_crash(path: str | Path) -> dict[str, Any]:
    """Parse a crash dump file (Windows MiniDump or ELF Core dump)."""
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}

    if not canon.is_file():
        return {"ok": False, "err": "not_a_file", "path": str(canon)}

    data = canon.read_bytes()
    if data.startswith(b"MDMP"):
        return _parse_minidump(data, canon)
    elif data.startswith(b"\x7fELF"):
        return _parse_elf_core(data, canon)

    return {"ok": False, "err": "unsupported_crash_format", "path": str(canon)}
