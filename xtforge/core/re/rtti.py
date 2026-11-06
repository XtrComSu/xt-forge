"""C++ RTTI and Virtual Method Table (vtable) recovery.

Extracts MSVC and GCC/Clang type descriptors, CompleteObjectLocators, and vtable
method pointers from read-only data sections.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from .pe import PEFile, PeError
from .native import sniff_format


def _demangle_msvc(mangled: str) -> str:
    """Basic pure-Python demangler for MSVC RTTI type descriptor names."""
    # .?AVMyClass@@ -> class MyClass
    # .?AUMyStruct@@ -> struct MyStruct
    if mangled.startswith(".?AV"):
        clean = mangled[4:].split("@@")[0]
        return f"class {clean}"
    if mangled.startswith(".?AU"):
        clean = mangled[4:].split("@@")[0]
        return f"struct {clean}"
    return mangled


def _extract_msvc_pe(pe: PEFile) -> list[dict[str, Any]]:
    """Scan PE .rdata section for MSVC RTTI CompleteObjectLocators and vtables."""
    classes: list[dict[str, Any]] = []

    # Find .rdata section
    rdata_sec = None
    for sec in pe._sections:
        if sec["name"] in (".rdata", ".data"):
            rdata_sec = sec
            break

    if not rdata_sec:
        return []

    rdata_off = rdata_sec["pointer_to_raw_data"]
    rdata_sz = rdata_sec["raw_size"]
    rdata_vaddr = rdata_sec["virtual_address"]
    rdata_bytes = pe.data[rdata_off : rdata_off + rdata_sz]

    step = 8 if pe.bits == 64 else 4
    fmt = "<Q" if pe.bits == 64 else "<I"

    # Step 1: Locate all TypeDescriptor strings (starting with .?AV or .?AU)
    td_pattern = re.compile(rb"\.\?[AU]V[a-zA-Z0-9_]+@@")
    for match in td_pattern.finditer(rdata_bytes):
        name_str_off = match.start()
        # In TypeDescriptor: pVFTable (step), spare (step), name string
        td_offset_in_sec = name_str_off - (step * 2)
        if td_offset_in_sec < 0:
            continue

        td_rva = rdata_vaddr + td_offset_in_sec
        mangled_name = match.group().decode("latin1", "replace")
        demangled = _demangle_msvc(mangled_name)

        # Step 2: Search .rdata for CompleteObjectLocator pointing to td_rva
        # In 64-bit: pTypeDescriptor is an RVA (4 bytes) at offset 12 of COL
        col_rvas = []
        if pe.bits == 64:
            td_rva_bytes = struct.pack("<I", td_rva)
            cur = 0
            while True:
                idx = rdata_bytes.find(td_rva_bytes, cur)
                if idx < 0:
                    break
                col_offset = idx - 12
                if col_offset >= 0 and col_offset + 24 <= len(rdata_bytes):
                    sig = struct.unpack_from("<I", rdata_bytes, col_offset)[0]
                    if sig == 1:
                        col_rva = rdata_vaddr + col_offset
                        col_rvas.append(col_rva)
                cur = idx + 4
        else:
            td_va_bytes = struct.pack("<I", pe.image_base + td_rva)
            cur = 0
            while True:
                idx = rdata_bytes.find(td_va_bytes, cur)
                if idx < 0:
                    break
                col_offset = idx - 12
                if col_offset >= 0 and col_offset + 20 <= len(rdata_bytes):
                    col_rva = rdata_vaddr + col_offset
                    col_rvas.append(col_rva)
                cur = idx + 4

        # Step 3: For each COL, search for vtable - step pointing to COL's Virtual Address
        for col_rva in col_rvas:
            col_va = pe.image_base + col_rva
            col_va_bytes = struct.pack(fmt, col_va)
            cur = 0
            while True:
                idx = rdata_bytes.find(col_va_bytes, cur)
                if idx < 0:
                    break
                vtable_offset_in_sec = idx + step
                vtable_rva = rdata_vaddr + vtable_offset_in_sec

                # Read virtual method function pointers
                methods = []
                method_cur = vtable_offset_in_sec
                while method_cur + step <= len(rdata_bytes):
                    (m_ptr,) = struct.unpack_from(fmt, rdata_bytes, method_cur)
                    if m_ptr == 0:
                        break
                    # Verify method pointer points into an executable section
                    m_rva = m_ptr - pe.image_base
                    is_code = False
                    for sec in pe._sections:
                        if sec["virtual_address"] <= m_rva < sec["virtual_address"] + max(sec["virtual_size"], sec["raw_size"]):
                            if sec["characteristics"] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                                is_code = True
                                break
                    if not is_code and len(methods) > 0:
                        break
                    if is_code or len(methods) == 0:
                        methods.append(hex(m_ptr))
                    method_cur += step
                    if len(methods) >= 256:
                        break

                classes.append({
                    "mangled_name": mangled_name,
                    "demangled_name": demangled,
                    "vtable_rva": hex(vtable_rva),
                    "methods": methods,
                    "method_count": len(methods),
                })
                cur = idx + step

    return classes


def extract_rtti(target: str | Path) -> dict[str, Any]:
    """Recover C++ class hierarchies, RTTI names, and vtables."""
    canon = guard.read_guard(target)
    if not canon.is_file():
        return {"ok": False, "err": "target is not a file"}

    fmt = sniff_format(canon)
    if fmt == "pe":
        try:
            pe = PEFile(canon)
            classes = _extract_msvc_pe(pe)
            return {
                "ok": True,
                "path": str(canon),
                "format": "pe",
                "class_count": len(classes),
                "classes": classes,
            }
        except PeError as exc:
            return {"ok": False, "err": str(exc), "path": str(canon)}
    elif fmt == "elf":
        # For ELF binaries, inspect symbol table for vtable / typeinfo symbols
        from . import elf
        try:
            syms = elf.symbols(canon, limit=2000).get("symbols", [])
            vtables = [
                {"name": s["name"], "address": s["value"], "size": s.get("size", 0)}
                for s in syms if "_ZTV" in s.get("name", "")
            ]
            return {
                "ok": True,
                "path": str(canon),
                "format": "elf",
                "class_count": len(vtables),
                "classes": vtables,
            }
        except Exception as exc:
            return {"ok": False, "err": str(exc), "path": str(canon)}

    return {"ok": False, "err": f"unrecognized format for {target}"}
