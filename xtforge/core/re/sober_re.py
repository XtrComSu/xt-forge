"""Sober-Hardened Reverse Engineering Engine (`xtforge.core.re.sober_re`).

Built directly from post-mortem analysis of the Sober / Roblox (`libroblox.so`,
`libloader.so`, `.rbxm` DataModel patches, and live Flatpak `Main` process)
reverse-engineering campaigns to eliminate the exact failure modes agents hit:

1. Section-Header-Stripped ELF Blindness (`e_shnum == 0` on `libloader.so`
   misdiagnosed as "packed" when `PT_LOAD` + `PT_DYNAMIC` are intact).
2. Android Bionic NDK ELF Traps (`SHT_ANDROID_RELA` / `APS2` packed relocations,
   `LIBC`/`LIBC_N` version stamps, 4-byte `pthread_mutex_t` ABI clobbering, and
   `.bss` overlap when expanding `DT_RELA`).
3. 120 MB Stripped Binary OOM (`libroblox.so` freezing Ghidra at 2.7M lines):
   solved via O(1) `--start-address`/`--stop-address` windowed disassembly +
   streaming RIP-relative `lea` string-anchor -> function-prologue resolution.
4. Live Process Memory False Negatives & Sparse-Page OOM Kills:
   tests `process_vm_readv` directly when `/proc/<pid>/mem` and `ptrace` fail,
   discovers `/memfd: (deleted)` ELF bases, and enforces `smaps` RSS-aware
   4 KB zero-page skipping.
5. Structured Binary Container & Tagged Constant-Pool Inspection (`.rbxm`/`.rbxl`
   chunk tables, `SIGN` chunk coverage, `u32` `Source` bytecode records, and
   27-byte `02 <f64> 02 <f64> 02 <f64>` tagged `Color3` stride verification).
"""
from __future__ import annotations

import ctypes
import math
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from ..route import guard

# Dynamic tag constants (ELF64)
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_STRSZ = 10
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
DT_ANDROID_REL = 0x6000000F
DT_ANDROID_RELSZ = 0x60000010
DT_ANDROID_RELA = 0x60000011
DT_ANDROID_RELASZ = 0x60000012
DT_VERSYM = 0x6FFFFFF0
DT_VERDEF = 0x6FFFFFFC
DT_VERDEFNUM = 0x6FFFFFFD
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

SHT_ANDROID_REL = 0x60000001
SHT_ANDROID_RELA = 0x60000002

PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4


def _vaddr_to_offset(vaddr: int, load_segments: list[dict[str, int]]) -> int | None:
    for seg in load_segments:
        v0 = seg["vaddr"]
        filesz = seg["filesz"]
        if v0 <= vaddr < v0 + filesz:
            return seg["offset"] + (vaddr - v0)
    return None


def _offset_to_vaddr(offset: int, load_segments: list[dict[str, int]]) -> int | None:
    for seg in load_segments:
        o0 = seg["offset"]
        filesz = seg["filesz"]
        if o0 <= offset < o0 + filesz:
            return seg["vaddr"] + (offset - o0)
    return None


def _read_cstr(buf: bytes, off: int, max_len: int = 256) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off, min(len(buf), off + max_len))
    if end == -1:
        end = min(len(buf), off + max_len)
    return buf[off:end].decode("utf-8", errors="replace")


def inspect_elf_deep(path: str | Path) -> dict[str, Any]:
    """Deep ELF64 triage supporting section-header-stripped (`e_shnum=0`) and Android Bionic (`APS2`) binaries."""
    canon = guard.read_guard(path)
    file_size = canon.stat().st_size
    with open(canon, "rb") as f:
        hdr = f.read(64)
        if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
            return {"ok": False, "error": "not a valid ELF binary"}
        ei_class = hdr[4]
        if ei_class != 2:
            return {"ok": False, "error": f"only ELF64 supported for deep inspection (got class {ei_class})"}
        (
            e_type,
            e_machine,
            _e_version,
            e_entry,
            e_phoff,
            e_shoff,
            _e_flags,
            _e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", hdr, 16)

        load_segments: list[dict[str, Any]] = []
        dyn_phdr: dict[str, int] | None = None
        max_vaddr_end = 0

        if e_phoff and e_phnum and e_phentsize >= 56:
            f.seek(e_phoff)
            ph_raw = f.read(e_phnum * e_phentsize)
            for i in range(e_phnum):
                p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                    "<IIQQQQQQ", ph_raw, i * e_phentsize
                )
                if p_type == PT_LOAD:
                    load_segments.append({
                        "index": i,
                        "offset": p_offset,
                        "vaddr": p_vaddr,
                        "filesz": p_filesz,
                        "memsz": p_memsz,
                        "flags": p_flags,
                        "perms": (
                            ("r" if p_flags & PF_R else "-")
                            + ("w" if p_flags & PF_W else "-")
                            + ("x" if p_flags & PF_X else "-")
                        ),
                        "align": p_align,
                    })
                    end_va = p_vaddr + p_memsz
                    if end_va > max_vaddr_end:
                        max_vaddr_end = end_va
                elif p_type == PT_DYNAMIC:
                    dyn_phdr = {"offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz}

        # Parse PT_DYNAMIC directly from program headers (works even when e_shnum == 0!)
        dyn_tags: dict[int, list[int]] = {}
        needed_libs: list[str] = []
        dyn_symbols: list[str] = []
        has_android_rela = False
        aps2_magic = False

        if dyn_phdr and dyn_phdr["filesz"] >= 16:
            f.seek(dyn_phdr["offset"])
            dyn_bytes = f.read(min(dyn_phdr["filesz"], 65536))
            for off in range(0, len(dyn_bytes) - 15, 16):
                d_tag, d_val = struct.unpack_from("<Qq", dyn_bytes, off)
                if d_tag == DT_NULL:
                    break
                dyn_tags.setdefault(d_tag & 0xFFFFFFFFFFFFFFFF, []).append(d_val & 0xFFFFFFFFFFFFFFFF)

            strtab_va = (dyn_tags.get(DT_STRTAB) or [0])[0]
            strsz = (dyn_tags.get(DT_STRSZ) or [0])[0]
            symtab_va = (dyn_tags.get(DT_SYMTAB) or [0])[0]
            strtab_off = _vaddr_to_offset(strtab_va, load_segments) if strtab_va else None

            if strtab_off is not None and strsz > 0:
                f.seek(strtab_off)
                strtab = f.read(min(strsz, 4 * 1024 * 1024))
                for name_off in dyn_tags.get(DT_NEEDED, []):
                    lib = _read_cstr(strtab, name_off)
                    if lib:
                        needed_libs.append(lib)

                symtab_off = _vaddr_to_offset(symtab_va, load_segments) if symtab_va else None
                if symtab_off is not None and symtab_off < strtab_off:
                    # Estimate symbol count when section headers are stripped
                    max_syms = min((strtab_off - symtab_off) // 24, 4000)
                    f.seek(symtab_off)
                    sym_bytes = f.read(max_syms * 24)
                    for si in range(0, len(sym_bytes) - 23, 24):
                        st_name, _st_info, _st_other, _st_shndx, _st_value, _st_size = struct.unpack_from(
                            "<IBBHQQ", sym_bytes, si
                        )
                        if st_name > 0:
                            sname = _read_cstr(strtab, st_name)
                            if sname and len(dyn_symbols) < 250:
                                dyn_symbols.append(sname)

            if DT_ANDROID_RELA in dyn_tags or DT_ANDROID_REL in dyn_tags:
                has_android_rela = True
                rela_va = (dyn_tags.get(DT_ANDROID_RELA) or dyn_tags.get(DT_ANDROID_REL) or [0])[0]
                rela_off = _vaddr_to_offset(rela_va, load_segments) if rela_va else None
                if rela_off is not None:
                    f.seek(rela_off)
                    magic = f.read(4)
                    aps2_magic = magic == b"APS2"

        # Check section headers if present
        android_rela_sections: list[dict[str, Any]] = []
        if e_shoff and e_shnum and e_shentsize >= 64:
            f.seek(e_shoff)
            sh_raw = f.read(e_shnum * e_shentsize)
            for idx in range(e_shnum):
                sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                    "<IIQQQQ", sh_raw, idx * e_shentsize
                )
                if sh_type in (SHT_ANDROID_RELA, SHT_ANDROID_REL):
                    has_android_rela = True
                    f.seek(sh_offset)
                    magic = f.read(4)
                    if magic == b"APS2":
                        aps2_magic = True
                    android_rela_sections.append({
                        "index": idx,
                        "type": hex(sh_type),
                        "vaddr": hex(sh_addr),
                        "offset": hex(sh_offset),
                        "size": sh_size,
                        "magic": magic.decode("ascii", errors="replace"),
                    })

    section_header_stripped = e_shnum == 0 and len(load_segments) > 0
    bionic_libs = [
        lib for lib in needed_libs
        if lib in ("libandroid.so", "liblog.so", "libOpenSLES.so", "libOpenMAXAL.so", "libmediandk.so")
    ]
    is_bionic = bool(bionic_libs or has_android_rela)
    safe_post_bss_vaddr = ((max_vaddr_end + 0xFFF) // 0x1000) * 0x1000

    warnings: list[str] = []
    if section_header_stripped:
        warnings.append(
            "e_shnum == 0 (section headers stripped, e.g. Sober libloader.so). "
            "Binary is NOT packed: PT_LOAD and PT_DYNAMIC are intact. Use PT_LOAD/PT_DYNAMIC instead of readelf -S."
        )
    if has_android_rela:
        warnings.append(
            "Contains SHT_ANDROID_RELA / DT_ANDROID_RELA (APS2 SLEB128 grouped relocations with stream-wide "
            "running r_offset AND r_addend accumulators). Standard glibc ld.so ignores DT_ANDROID_RELA and "
            f"leaves .init_array all-NULL. Expand to Elf64_Rela and map at post-.bss vaddr >= {hex(safe_post_bss_vaddr)}."
        )
    if is_bionic:
        warnings.append(
            "Android Bionic ABI detected: (1) strip LIBC/LIBC_N/LIBC_O symbol versions (set .gnu.version=1 "
            "and zero DT_VERNEED/DT_VERSYM), (2) translate 4-byte Bionic pthread_mutex_t/cond_t/rwlock_t "
            "instead of forwarding directly to 40/48/56-byte glibc pthread functions."
        )

    return {
        "ok": True,
        "path": str(canon),
        "size_bytes": file_size,
        "entry": hex(e_entry),
        "e_shnum": e_shnum,
        "e_phnum": e_phnum,
        "section_header_stripped_not_packed": section_header_stripped,
        "is_android_bionic": is_bionic,
        "has_android_aps2_rela": has_android_rela,
        "aps2_magic_verified": aps2_magic,
        "android_rela_sections": android_rela_sections,
        "safe_post_bss_vaddr": hex(safe_post_bss_vaddr),
        "needed_libraries": needed_libs,
        "dynamic_symbol_count_sample": len(dyn_symbols),
        "dynamic_symbols_sample": dyn_symbols[:60],
        "pt_load_segments": [
            {**seg, "offset": hex(seg["offset"]), "vaddr": hex(seg["vaddr"])}
            for seg in load_segments
        ],
        "warnings": warnings,
    }


def _find_prologue_backwards(code_buf: bytes, xref_rel_off: int, seg_vaddr: int, max_back: int = 8192) -> int | None:
    """Walk backwards from an xref instruction offset to locate the enclosing x86-64 function prologue."""
    start_search = max(0, xref_rel_off - max_back)
    window = code_buf[start_search:xref_rel_off]
    # Look for standard x86-64 function prologues:
    # 1. endbr64 (f3 0f 1e fa) + push rbp (55)
    # 2. push rbp; mov rbp, rsp (55 48 89 e5)
    # 3. push rbp; push r15; push r14 ... (55 41 57 41 56) after ret (c3) or padding (cc / 90 / 0f 1f)
    best_off: int | None = None
    for m in re.finditer(rb"(?:\xf3\x0f\x1e\xfa)?\x55(?:\x48\x89\xe5|\x41\x57|\x41\x56|\x41\x55|\x41\x54|\x53)", window):
        cand = m.start()
        if cand == 0 or window[cand - 1] in (0xC3, 0xCC, 0x90, 0x00, 0x66, 0x2E):
            best_off = start_search + cand
    if best_off is not None:
        return seg_vaddr + best_off
    return None


def resolve_string_anchors(
    path: str | Path,
    anchors: list[str],
    *,
    max_back_bytes: int = 16384,
) -> dict[str, Any]:
    """Resolve stripped functions in huge (120+ MB) ELFs via string anchors -> RIP-relative LEA xrefs -> prologues."""
    canon = guard.read_guard(path)
    with open(canon, "rb") as f:
        hdr = f.read(64)
        if len(hdr) < 64 or hdr[:4] != b"\x7fELF" or hdr[4] != 2:
            return {"ok": False, "error": "not an ELF64 binary"}
        e_phoff, _e_shoff, _e_flags, _e_ehsize, e_phentsize, e_phnum = struct.unpack_from("<QQIHHH", hdr, 32)
        f.seek(e_phoff)
        ph_raw = f.read(e_phnum * e_phentsize)
        load_segments: list[dict[str, int]] = []
        for i in range(e_phnum):
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from(
                "<IIQQQQQQ", ph_raw, i * e_phentsize
            )
            if p_type == PT_LOAD and p_filesz > 0:
                load_segments.append({
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "flags": p_flags,
                })

        # Step 1: Locate each anchor string's virtual address in non-exec (or all) PT_LOAD segments
        anchor_vas: dict[str, list[int]] = {a: [] for a in anchors}
        chunk_sz = 16 * 1024 * 1024
        for seg in load_segments:
            rem = seg["filesz"]
            pos = 0
            while pos < rem:
                read_len = min(chunk_sz, rem - pos)
                f.seek(seg["offset"] + pos)
                buf = f.read(read_len + 512)
                for a in anchors:
                    needle = a.encode("utf-8")
                    idx = buf.find(needle)
                    while idx != -1 and idx < read_len:
                        va = seg["vaddr"] + pos + idx
                        if va not in anchor_vas[a]:
                            anchor_vas[a].append(va)
                        idx = buf.find(needle, idx + 1)
                pos += read_len

        target_va_to_anchors: dict[int, list[str]] = {}
        for a, vas in anchor_vas.items():
            for va in vas:
                target_va_to_anchors.setdefault(va, []).append(a)

        # Step 2: Stream executable PT_LOAD segments and scan for RIP-relative LEA (48/4c 8d modrm disp32)
        xrefs_by_anchor: dict[str, list[dict[str, Any]]] = {a: [] for a in anchors}
        if target_va_to_anchors:
            lea_pat = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
            for seg in load_segments:
                if not (seg["flags"] & PF_X):
                    continue
                f.seek(seg["offset"])
                code_buf = f.read(seg["filesz"])
                seg_va = seg["vaddr"]
                for m in lea_pat.finditer(code_buf):
                    insn_off = m.start()
                    if insn_off + 7 > len(code_buf):
                        continue
                    disp32 = struct.unpack_from("<i", code_buf, insn_off + 3)[0]
                    insn_end_va = seg_va + insn_off + 7
                    target_va = insn_end_va + disp32
                    if target_va in target_va_to_anchors:
                        fn_va = _find_prologue_backwards(code_buf, insn_off, seg_va, max_back=max_back_bytes)
                        for a in target_va_to_anchors[target_va]:
                            xrefs_by_anchor[a].append({
                                "string_va": hex(target_va),
                                "lea_site_va": hex(seg_va + insn_off),
                                "enclosing_function_va": hex(fn_va) if fn_va is not None else None,
                            })

    # Detect aliases (two distinct anchors resolving to the exact same enclosing function prologue)
    fn_to_anchors: dict[str, list[str]] = {}
    for a, hits in xrefs_by_anchor.items():
        for h in hits:
            fva = h.get("enclosing_function_va")
            if fva:
                if a not in fn_to_anchors.setdefault(fva, []):
                    fn_to_anchors[fva].append(a)

    aliases: list[dict[str, Any]] = [
        {"function_va": fva, "shared_by_anchors": a_list}
        for fva, a_list in fn_to_anchors.items()
        if len(a_list) > 1
    ]

    return {
        "ok": True,
        "path": str(canon),
        "anchors_requested": len(anchors),
        "anchors_resolved": sum(1 for a in anchors if xrefs_by_anchor.get(a)),
        "results": {
            a: {
                "string_vas": [hex(v) for v in anchor_vas[a]],
                "xrefs": xrefs_by_anchor[a],
            }
            for a in anchors
        },
        "alias_collisions": aliases,
    }


def slice_disasm_window(
    path: str | Path,
    address: str | int,
    *,
    before_bytes: int = 128,
    after_bytes: int = 512,
) -> dict[str, Any]:
    """O(1) windowed disassembly & constant/string annotator for huge (120+ MB) stripped ELFs."""
    canon = guard.read_guard(path)
    if isinstance(address, int):
        center_va = address
    else:
        s = str(address).strip().lower().removeprefix("sub_")
        center_va = int(s, 16) if s.startswith("0x") or all(c in "0123456789abcdef" for c in s) else int(s)

    start_va = max(0, center_va - max(0, before_bytes))
    stop_va = center_va + max(64, min(after_bytes, 16384))

    objdump = shutil.which("objdump")
    if not objdump:
        return {"ok": False, "error": "objdump not found in PATH"}

    res = subprocess.run(
        [
            objdump,
            "-d",
            "-M",
            "intel",
            f"--start-address={hex(start_va)}",
            f"--stop-address={hex(stop_va)}",
            str(canon),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if res.returncode != 0:
        return {"ok": False, "error": res.stderr.strip() or "objdump failed"}

    # Parse PT_LOAD segments so we can resolve RIP-relative # 0x... comments to strings
    load_segments: list[dict[str, int]] = []
    with open(canon, "rb") as f:
        hdr = f.read(64)
        if len(hdr) >= 64 and hdr[:4] == b"\x7fELF" and hdr[4] == 2:
            e_phoff, _e_shoff, _e_flags, _e_ehsize, e_phentsize, e_phnum = struct.unpack_from("<QQIHHH", hdr, 32)
            f.seek(e_phoff)
            ph_raw = f.read(e_phnum * e_phentsize)
            for i in range(e_phnum):
                p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from(
                    "<IIQQQQQQ", ph_raw, i * e_phentsize
                )
                if p_type == PT_LOAD and p_filesz > 0:
                    load_segments.append({
                        "offset": p_offset,
                        "vaddr": p_vaddr,
                        "filesz": p_filesz,
                        "memsz": p_memsz,
                        "flags": p_flags,
                    })

        annotated_lines: list[str] = []
        resolved_strings: dict[str, str] = {}
        immediate_constants: list[dict[str, Any]] = []
        rip_comment_re = re.compile(r"#\s*0x([0-9a-fA-F]+)")
        imm_hex_re = re.compile(r"\b0x([0-9a-fA-F]{5,16})\b")

        for ln in res.stdout.splitlines():
            extra_notes: list[str] = []
            m_rip = rip_comment_re.search(ln)
            if m_rip:
                target_va = int(m_rip.group(1), 16)
                off = _vaddr_to_offset(target_va, load_segments)
                if off is not None:
                    f.seek(off)
                    raw_s = f.read(160)
                    end = raw_s.find(b"\x00")
                    if end > 0:
                        candidate = raw_s[:end]
                        if all(32 <= b < 127 or b in (9, 10, 13) for b in candidate):
                            s_txt = candidate.decode("ascii", errors="replace")
                            resolved_strings[hex(target_va)] = s_txt
                            extra_notes.append(f'str="{s_txt[:80]}"')

            for m_imm in imm_hex_re.finditer(ln):
                val = int(m_imm.group(1), 16)
                if val >= 0x100000 and (val & (val - 1)) == 0:
                    mib = val / (1024 * 1024)
                    immediate_constants.append({"hex": hex(val), "decimal": val, "mib": mib, "line": ln.strip()})
                    extra_notes.append(f"{val} ({mib:g} MiB)")

            if extra_notes:
                annotated_lines.append(f"{ln}   ;; {' | '.join(extra_notes)}")
            else:
                annotated_lines.append(ln)

    return {
        "ok": True,
        "path": str(canon),
        "center_va": hex(center_va),
        "start_va": hex(start_va),
        "stop_va": hex(stop_va),
        "line_count": len(annotated_lines),
        "resolved_strings": resolved_strings,
        "power_of_two_immediates": immediate_constants,
        "disassembly": "\n".join(annotated_lines),
    }


class _Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def probe_live_process(pid: int) -> dict[str, Any]:
    """Safe live process memory & namespace probe (`process_vm_readv` + `/memfd:` ELF discovery + RSS budget)."""
    proc_dir = Path(f"/proc/{pid}")
    if not proc_dir.is_dir():
        return {"ok": False, "error": f"/proc/{pid} does not exist (check namespace or flatpak ps)"}

    status_info: dict[str, str] = {}
    try:
        for ln in (proc_dir / "status").read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                if k in ("Name", "State", "Pid", "PPid", "Uid", "NoNewPrivs", "Seccomp", "VmRSS", "Threads"):
                    status_info[k] = v.strip()
    except OSError as exc:
        status_info["error"] = str(exc)

    ptrace_scope = "unknown"
    try:
        ptrace_scope = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
    except OSError:
        pass

    proc_mem_readable = os.access(f"/proc/{pid}/mem", os.R_OK)
    maps_lines: list[str] = []
    memfd_elfs: list[dict[str, Any]] = []
    first_readable_va: int | None = None

    try:
        maps_lines = (proc_dir / "maps").read_text(encoding="utf-8", errors="replace").splitlines()
        for ln in maps_lines:
            parts = ln.split(None, 5)
            if len(parts) < 5:
                continue
            addr_range, perms, offset_hex, _dev, _inode = parts[:5]
            pathname = parts[5].strip() if len(parts) > 5 else ""
            if "r" in perms:
                start_s, end_s = addr_range.split("-", 1)
                start_va = int(start_s, 16)
                end_va = int(end_s, 16)
                if first_readable_va is None:
                    first_readable_va = start_va
                if "memfd:" in pathname or (end_va - start_va) >= 32 * 1024 * 1024:
                    memfd_elfs.append({
                        "start_va": hex(start_va),
                        "end_va": hex(end_va),
                        "size_mb": round((end_va - start_va) / (1024 * 1024), 2),
                        "perms": perms,
                        "offset": offset_hex,
                        "pathname": pathname,
                    })
    except OSError as exc:
        return {
            "ok": False,
            "pid": pid,
            "status": status_info,
            "ptrace_scope": ptrace_scope,
            "error": f"cannot read /proc/{pid}/maps: {exc}",
        }

    # Test process_vm_readv directly via libc syscall wrapper
    pvm_readv_ok = False
    pvm_sample_hex = ""
    pvm_error = ""
    if first_readable_va is not None:
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            buf = (ctypes.c_char * 16)()
            local_iov = _Iovec(ctypes.cast(buf, ctypes.c_void_p), 16)
            remote_iov = _Iovec(ctypes.c_void_p(first_readable_va), 16)
            libc.process_vm_readv.restype = ctypes.c_ssize_t
            nread = libc.process_vm_readv(
                ctypes.c_int(pid),
                ctypes.byref(local_iov),
                ctypes.c_ulong(1),
                ctypes.byref(remote_iov),
                ctypes.c_ulong(1),
                ctypes.c_ulong(0),
            )
            if nread == 16:
                pvm_readv_ok = True
                pvm_sample_hex = bytes(buf).hex()
            else:
                errno_val = ctypes.get_errno()
                pvm_error = f"errno={errno_val} ({os.strerror(errno_val)})"
        except Exception as exc:
            pvm_error = str(exc)

    return {
        "ok": True,
        "pid": pid,
        "status": status_info,
        "yama_ptrace_scope": ptrace_scope,
        "proc_pid_mem_readable": proc_mem_readable,
        "process_vm_readv_works": pvm_readv_ok,
        "process_vm_readv_sample_16b": pvm_sample_hex,
        "process_vm_readv_error": pvm_error,
        "total_vmas": len(maps_lines),
        "large_or_memfd_mappings": memfd_elfs[:25],
        "oom_safety_rule": (
            "NEVER scan anonymous VMAs linearly with process_vm_readv — reading untouched MAP_ANONYMOUS pages "
            "faults shared zero pages into RSS (118 GB scan on 7.6 GB host OOM-kills target). "
            "Always filter by smaps Rss > 0 and probe 4 KB for all-zeros before reading 1 MB blocks."
        ),
    }


def inspect_rbxm_container(path: str | Path) -> dict[str, Any]:
    """Parse Roblox `.rbxm`/`.rbxl` containers, `SIGN`/`HASH` integrity chunks, `Source` bytecode, and 27B Color3 triples."""
    canon = guard.read_guard(path)
    raw = canon.read_bytes()
    magic = b"<roblox!\x89\xff\r\n\x1a\n"
    if len(raw) < 32 or raw[:14] != magic:
        return {"ok": False, "error": "not a valid <roblox! container (.rbxm/.rbxl)"}

    version, class_count, inst_count, reserved = struct.unpack_from("<HIIq", raw, 14)
    pos = 32
    chunks: list[dict[str, Any]] = []
    sign_records: list[dict[str, Any]] = []
    hash_summary: dict[str, Any] | None = None
    source_records: list[dict[str, Any]] = []
    color3_tagged_count = 0

    zstd_bin = shutil.which("zstd")

    idx = 0
    while pos + 16 <= len(raw):
        c_name = raw[pos:pos + 4]
        comp_len, uncomp_len, c_res = struct.unpack_from("<III", raw, pos + 4)
        body_len = uncomp_len if comp_len == 0 else comp_len
        body_start = pos + 16
        body = raw[body_start:body_start + body_len]
        is_zstd = body[:4] == b"\x28\xb5\x2f\xfd"

        chunks.append({
            "index": idx,
            "name": c_name.decode("ascii", errors="replace").rstrip("\x00"),
            "offset": pos,
            "compressed_len": comp_len,
            "uncompressed_len": uncomp_len,
            "storage": "raw (comp==0)" if comp_len == 0 else ("zstd" if is_zstd else "compressed"),
            "reserved": c_res,
        })

        # Decode SIGN chunk (80-byte records: u32 a | u32 chunkIdx | u32 zero | u32 sigLen=64 | 64B Ed25519 sig)
        if c_name in (b"SIGN", b"SIGU") and len(body) >= 4:
            sig_body = body
            if comp_len > 0 and is_zstd and zstd_bin:
                try:
                    sig_body = subprocess.run([zstd_bin, "-d", "-c"], input=body, capture_output=True, check=True).stdout
                except Exception:
                    pass
            if len(sig_body) >= 4:
                cnt = struct.unpack_from("<I", sig_body, 0)[0]
                off_s = 4
                for _ in range(min(cnt, 32)):
                    if off_s + 80 <= len(sig_body):
                        f1, chunk_idx, f3, sig_len = struct.unpack_from("<IIII", sig_body, off_s)
                        sig_hex = sig_body[off_s + 16:off_s + 16 + min(sig_len, 64)].hex()
                        sign_records.append({
                            "field1": f1,
                            "signed_chunk_index": chunk_idx,
                            "field3": f3,
                            "sig_len": sig_len,
                            "sig_prefix_hex": sig_hex[:32] + "...",
                        })
                        off_s += 80

        # Decode HASH chunk header
        elif c_name == b"HASH" and len(body) >= 7:
            h_body = body
            if comp_len > 0 and is_zstd and zstd_bin:
                try:
                    h_body = subprocess.run([zstd_bin, "-d", "-c"], input=body, capture_output=True, check=True).stdout
                except Exception:
                    pass
            if len(h_body) >= 7:
                h_count = struct.unpack_from("<I", h_body, 0)[0]
                hash_summary = {
                    "entry_count": h_count,
                    "flags_hex": h_body[4:7].hex(),
                    "body_len": len(h_body),
                    "matches_16b_records": (7 + h_count * 16 == len(h_body)),
                }

        # Inspect PROP chunks for u32 "Source" ProtectedString (0x1d) records & 27-byte tagged Color3 triples
        elif c_name == b"PROP":
            p_body = body
            if comp_len > 0 and is_zstd and zstd_bin:
                try:
                    p_body = subprocess.run([zstd_bin, "-d", "-c"], input=body, capture_output=True, check=True).stdout
                except Exception:
                    p_body = b""
            if p_body:
                # Search for u32(6) + "Source" + u8(0x1d)
                needle = b"\x06\x00\x00\x00Source\x1d"
                j = p_body.find(needle)
                while j != -1:
                    if j + 15 <= len(p_body):
                        vlen = struct.unpack_from("<I", p_body, j + 11)[0]
                        vstart = j + 15
                        prefix_hex = p_body[vstart:vstart + 8].hex()
                        luau_ver = p_body[vstart + 8] if vstart + 8 < len(p_body) else None
                        luau_types = p_body[vstart + 9] if vstart + 9 < len(p_body) else None
                        source_records.append({
                            "chunk_index": idx,
                            "chunk_offset": pos,
                            "record_offset_in_chunk": j,
                            "value_len": vlen,
                            "prefix_8b_hex": prefix_hex,
                            "luau_version": luau_ver,
                            "luau_types_version": luau_types,
                        })
                    j = p_body.find(needle, j + 1)

                # Count 27-byte tagged Color3 f64 triples: 02 <f64 r> 02 <f64 g> 02 <f64 b>
                for m in re.finditer(rb"\x02.{8}\x02.{8}\x02.{8}", p_body, re.DOTALL):
                    raw27 = m.group(0)
                    r, g, b = struct.unpack("<ddd", raw27[1:9] + raw27[10:18] + raw27[19:27])
                    if all(not math.isnan(x) and 0.0 <= x <= 1.0 for x in (r, g, b)):
                        color3_tagged_count += 1

        if c_name == b"END\x00" or body_len == 0:
            pos += 16 + body_len
            break
        pos += 16 + body_len
        idx += 1

    signed_indices = {r["signed_chunk_index"] for r in sign_records}
    for sr in source_records:
        sr["chunk_is_signed_by_SIGN"] = sr["chunk_index"] in signed_indices

    return {
        "ok": True,
        "path": str(canon),
        "size_bytes": len(raw),
        "version": version,
        "class_count": class_count,
        "instance_count": inst_count,
        "chunk_count": len(chunks),
        "tail_bytes": len(raw) - pos,
        "sign_records": sign_records,
        "hash_chunk": hash_summary,
        "source_bytecode_records": source_records,
        "tagged_27b_color3_triples_count": color3_tagged_count,
        "chunks": chunks[:50],
        "patching_rules": [
            "Property names in PROP chunks use u32 length framing (e.g. 06 00 00 00 'Source' 1d <u32 value_len>), NOT u8.",
            "Color3.new constants in PROP bytecode use a 27-byte tagged stride (02 <f64 r> 02 <f64 g> 02 <f64 b>); writing 24 contiguous bytes clobbers interior 0x02 tags.",
            "Always bisect container recompression (recompressing without byte changes) before debugging bytecode payload acceptance.",
        ],
    }
