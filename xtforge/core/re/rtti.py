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


def _extract_itanium_elf(canon: Path) -> list[dict[str, Any]]:
    """Recover stripped Itanium C++ ABI RTTI classes, typeinfos, and vtables from ELF."""
    from . import elf

    raw = canon.read_bytes()
    info = elf.info(canon)
    bits = int(info.get("bits") or 64)
    step = 8 if bits == 64 else 4
    endian = "<" if info.get("endian") != "big" else ">"
    ptr_fmt = f"{endian}{'Q' if bits == 64 else 'I'}"

    def _as_int(v: Any) -> int:
        if isinstance(v, int):
            return v
        s = str(v)
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s)

    secs = elf.sections(canon).get("sections", [])
    text_ranges = [
        (_as_int(s["addr"]), _as_int(s["addr"]) + _as_int(s["size"]))
        for s in secs if (_as_int(s.get("flags", 0)) & 0x4 or "X" in str(s.get("flags", ""))) and _as_int(s.get("size", 0)) > 0
    ]

    def _is_exec(va: int) -> bool:
        return any(lo <= va < hi for lo, hi in text_ranges)

    # Parse .rela.dyn / .rela.* R_X86_64_RELATIVE / R_AARCH64_RELATIVE relocations (r_offset -> r_addend)
    rel_map: dict[int, int] = {}
    if bits == 64:
        for s in secs:
            if str(s.get("type", "")) in ("RELA", "SHT_RELA"):
                off = _as_int(s["offset"])
                sz = _as_int(s["size"])
                for pos in range(off, min(len(raw), off + sz) - 23, 24):
                    r_offset, r_info, r_addend = struct.unpack_from(f"{endian}QQq", raw, pos)
                    r_type = r_info & 0xFFFFFFFF
                    if r_type in (8, 1027) and r_addend > 0:  # R_X86_64_RELATIVE, R_AARCH64_RELATIVE
                        rel_map[r_offset] = r_addend

    # Also build raw pointer lookup across data sections for non-PIE ELFs
    ptr_map: dict[int, int] = dict(rel_map)
    for s in secs:
        sname = str(s.get("name", ""))
        if sname in (".rodata", ".data.rel.ro", ".data"):
            off = _as_int(s["offset"])
            sz = _as_int(s["size"])
            va_base = _as_int(s["addr"])
            for rel_off in range(0, sz - step + 1, step):
                va = va_base + rel_off
                if va not in ptr_map:
                    (val,) = struct.unpack_from(ptr_fmt, raw, off + rel_off)
                    if val != 0:
                        ptr_map[va] = val

    # Invert ptr_map: target_va -> [pointing_va, ...]
    rev_ptrs: dict[int, list[int]] = {}
    for src_va, dst_va in ptr_map.items():
        rev_ptrs.setdefault(dst_va, []).append(src_va)

    # Scan .rodata for Itanium mangled typeinfo names: <len><Ident>\0 (e.g. 18SecureVaultHandler)
    ro_secs = [s for s in secs if str(s.get("name", "")) == ".rodata"]
    found_classes: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    ti_pat = re.compile(rb"(?<=\x00)(\d{1,3})([A-Za-z_][A-Za-z0-9_]{2,120})\x00")

    for rs in ro_secs:
        ro_off = _as_int(rs["offset"])
        ro_sz = _as_int(rs["size"])
        ro_va = _as_int(rs["addr"])
        chunk = raw[ro_off : ro_off + ro_sz]
        for m in ti_pat.finditer(chunk):
            decl_len = int(m.group(1))
            ident = m.group(2).decode("ascii", errors="ignore")
            if decl_len != len(ident) or ident.startswith("__"):
                continue
            name_va = ro_va + m.start()
            if ident in seen_names:
                continue
            # TypeInfo struct has __type_name pointer at offset +step
            ti_vas = [src - step for src in rev_ptrs.get(name_va, [])]
            if not ti_vas:
                # Try nested namespace N<len><ns><len><cls>E if not direct
                continue
            seen_names.add(ident)
            vtables: list[dict[str, Any]] = []
            for ti_va in ti_vas:
                # Vtable has RTTI pointer at vtable_slot[-1] (offset -step from first virtual method)
                for rtti_slot_va in rev_ptrs.get(ti_va, []):
                    vt_va = rtti_slot_va + step
                    methods: list[str] = []
                    cur = vt_va
                    for _ in range(128):
                        m_va = ptr_map.get(cur)
                        if m_va is None or not _is_exec(m_va):
                            break
                        methods.append(hex(m_va))
                        cur += step
                    if methods:
                        vtables.append({"vtable_va": hex(vt_va), "methods": methods, "method_count": len(methods)})
            found_classes.append({
                "name": ident,
                "typeinfo_va": hex(ti_vas[0]),
                "vtables": vtables,
                "address": vtables[0]["vtable_va"] if vtables else hex(ti_vas[0]),
                "methods": vtables[0]["methods"] if vtables else [],
                "method_count": vtables[0]["method_count"] if vtables else 0,
            })
    return found_classes


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
        # Recover stripped Itanium ABI RTTI classes from .rodata + .rela.dyn first,
        # then supplement with any unstripped _ZTV symbols.
        from . import elf
        try:
            classes = _extract_itanium_elf(canon)
            seen = {c["name"] for c in classes}
            syms = elf.symbols(canon, limit=2000).get("symbols", [])
            for s in syms:
                sname = s.get("name", "")
                if "_ZTV" in sname and sname not in seen:
                    classes.append({"name": sname, "address": s["value"], "size": s.get("size", 0)})
                    seen.add(sname)
            return {
                "ok": True,
                "path": str(canon),
                "format": "elf",
                "class_count": len(classes),
                "classes": classes,
            }
        except Exception as exc:
            return {"ok": False, "err": str(exc), "path": str(canon)}

    return {"ok": False, "err": f"unrecognized format for {target}"}
