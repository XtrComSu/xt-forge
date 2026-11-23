"""Dependency-free Windows PE/COFF parser.

Parses PE headers, sections, exports, imports, TLS callbacks, and x86_64 exception
tables in pure Python with zero external dependencies.
"""
from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any

from ..route import guard

MAX_BYTES = 256 * 1024 * 1024

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0xAA64: "ARM64",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0x5032: "RISC-V 32",
    0x5064: "RISC-V 64",
    0x0200: "IA-64",
}

SUBSYSTEM_NAMES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

DATA_DIRECTORY_NAMES = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Certificate",
    "BaseRelocation",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLRRuntime",
    "Reserved",
]


class PeError(ValueError):
    """Raised when a file is not a readable or valid PE/COFF object."""


def _shannon_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


class PEFile:
    """Dependency-free PE32/PE32+ binary parser."""

    def __init__(self, target: str | Path | bytes):
        if isinstance(target, (str, Path)):
            canon = guard.read_guard(target)
            if not canon.is_file():
                raise PeError(f"file not found or not regular: {target}")
            size = canon.stat().st_size
            if size > MAX_BYTES:
                raise PeError(f"file too large: {size} bytes (max {MAX_BYTES})")
            try:
                self.data = canon.read_bytes()
            except OSError as exc:
                raise PeError(f"cannot read {target}: {exc}") from exc
            self.path = str(canon)
        elif isinstance(target, (bytes, bytearray)):
            if len(target) > MAX_BYTES:
                raise PeError(f"data too large: {len(target)} bytes (max {MAX_BYTES})")
            self.data = bytes(target)
            self.path = "<memory>"
        else:
            raise PeError(f"unsupported target type: {type(target)}")

        self._parse()

    def _unpack(self, fmt: str, offset: int) -> tuple:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self.data):
            raise PeError(f"truncated PE at offset {offset}")
        try:
            return struct.unpack_from(fmt, self.data, offset)
        except struct.error as exc:
            raise PeError(f"corrupt PE structure at offset {offset}") from exc

    def _cstr(self, offset: int, max_len: int = 512) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\0", offset, min(len(self.data), offset + max_len))
        if end < 0:
            end = min(len(self.data), offset + max_len)
        return self.data[offset:end].decode("utf-8", "replace")

    def _parse(self) -> None:
        if len(self.data) < 64:
            raise PeError("file too small for DOS header")
        if self.data[:2] != b"MZ":
            raise PeError("invalid DOS signature (expected MZ)")

        (e_lfanew,) = self._unpack("<I", 0x3C)
        self.pe_offset = e_lfanew
        if self.pe_offset < 0 or self.pe_offset + 24 > len(self.data):
            raise PeError(f"invalid e_lfanew pointer: {self.pe_offset}")

        if self.data[self.pe_offset : self.pe_offset + 4] != b"PE\0\0":
            raise PeError("invalid PE signature (expected PE\\0\\0)")

        # COFF File Header (20 bytes)
        coff_offset = self.pe_offset + 4
        (
            self.machine_code,
            self.num_sections,
            self.time_date_stamp,
            self.pointer_to_sym_table,
            self.num_symbols,
            self.size_of_opt_header,
            self.characteristics,
        ) = self._unpack("<HHIIIHH", coff_offset)

        self.machine = MACHINE_NAMES.get(self.machine_code, f"0x{self.machine_code:04x}")

        opt_offset = coff_offset + 20
        if self.size_of_opt_header < 2:
            raise PeError("missing or empty optional header")

        (self.opt_magic,) = self._unpack("<H", opt_offset)
        if self.opt_magic == 0x010B:
            self.bits = 32
        elif self.opt_magic == 0x020B:
            self.bits = 64
        else:
            raise PeError(f"unrecognized optional header magic: 0x{self.opt_magic:04x}")

        if self.bits == 64:
            if self.size_of_opt_header < 112:
                raise PeError("truncated PE32+ optional header")
            (
                _,
                self.major_linker,
                self.minor_linker,
                self.size_of_code,
                self.size_of_init_data,
                self.size_of_uninit_data,
                self.entry_point_rva,
                self.base_of_code,
                self.image_base,
                self.section_alignment,
                self.file_alignment,
                self.major_os,
                self.minor_os,
                self.major_image,
                self.minor_image,
                self.major_subsystem,
                self.minor_subsystem,
                self.win32_version,
                self.size_of_image,
                self.size_of_headers,
                self.checksum,
                self.subsystem_code,
                self.dll_characteristics,
                self.size_of_stack_reserve,
                self.size_of_stack_commit,
                self.size_of_heap_reserve,
                self.size_of_heap_commit,
                self.loader_flags,
                self.num_rva_and_sizes,
            ) = self._unpack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", opt_offset)
            data_dirs_offset = opt_offset + 112
        else:
            if self.size_of_opt_header < 96:
                raise PeError("truncated PE32 optional header")
            (
                _,
                self.major_linker,
                self.minor_linker,
                self.size_of_code,
                self.size_of_init_data,
                self.size_of_uninit_data,
                self.entry_point_rva,
                self.base_of_code,
                self.base_of_data,
                self.image_base,
                self.section_alignment,
                self.file_alignment,
                self.major_os,
                self.minor_os,
                self.major_image,
                self.minor_image,
                self.major_subsystem,
                self.minor_subsystem,
                self.win32_version,
                self.size_of_image,
                self.size_of_headers,
                self.checksum,
                self.subsystem_code,
                self.dll_characteristics,
                self.size_of_stack_reserve,
                self.size_of_stack_commit,
                self.size_of_heap_reserve,
                self.size_of_heap_commit,
                self.loader_flags,
                self.num_rva_and_sizes,
            ) = self._unpack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", opt_offset)
            data_dirs_offset = opt_offset + 96

        self.subsystem = SUBSYSTEM_NAMES.get(
            self.subsystem_code, f"0x{self.subsystem_code:04x}"
        )

        # Parse Data Directories
        self.data_directories: list[dict[str, int]] = []
        for i in range(min(16, self.num_rva_and_sizes)):
            entry_offset = data_dirs_offset + i * 8
            if entry_offset + 8 <= len(self.data):
                rva, size = self._unpack("<II", entry_offset)
            else:
                rva, size = 0, 0
            name = DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else f"Entry_{i}"
            self.data_directories.append({"name": name, "rva": rva, "size": size})

        # Parse Section Headers
        sections_offset = opt_offset + self.size_of_opt_header
        self._sections: list[dict[str, Any]] = []
        for i in range(self.num_sections):
            sh_offset = sections_offset + i * 40
            if sh_offset + 40 > len(self.data):
                raise PeError(f"truncated section header {i}")
            raw_name, vsize, vaddr, raw_size, raw_ptr, _, _, _, _, chars = (
                self._unpack("<8sIIIIIIHHI", sh_offset)
            )
            name = raw_name.split(b"\0")[0].decode("ascii", "replace")
            self._sections.append(
                {
                    "name": name,
                    "virtual_size": vsize,
                    "virtual_address": vaddr,
                    "raw_size": raw_size,
                    "pointer_to_raw_data": raw_ptr,
                    "characteristics": chars,
                }
            )

    def rva_to_offset(self, rva: int) -> int | None:
        """Convert a Relative Virtual Address (RVA) to file offset."""
        for sec in self._sections:
            vaddr = sec["virtual_address"]
            vsize = sec["virtual_size"]
            raw_size = sec["raw_size"]
            # Some sections have vsize 0 or smaller than raw_size
            effective_vsize = max(vsize, raw_size)
            if vaddr <= rva < vaddr + effective_vsize:
                offset_within_sec = rva - vaddr
                if offset_within_sec < raw_size:
                    return sec["pointer_to_raw_data"] + offset_within_sec
        # If RVA is within headers
        if rva < self.size_of_headers:
            return rva
        return None

    def checksec(self) -> dict[str, Any]:
        """Evaluate Windows binary mitigation and security flags."""
        chars = self.dll_characteristics
        has_cert = False
        if len(self.data_directories) > 4:
            has_cert = bool(self.data_directories[4]["size"])
        return {
            "aslr": bool(chars & 0x0040),
            "high_entropy_va": bool(chars & 0x0020) and (self.bits == 64),
            "dep_nx": bool(chars & 0x0100),
            "cfg": bool(chars & 0x4000),
            "force_integrity": bool(chars & 0x0080),
            "no_seh": bool(chars & 0x0400),
            "authenticode": has_cert,
        }

    def info(self) -> dict[str, Any]:
        """Summary information about the PE binary."""
        tls_info = self.tls()
        has_pdata = False
        if len(self.data_directories) > 3:
            has_pdata = self.data_directories[3]["size"] > 0

        return {
            "format": f"PE32{'+' if self.bits == 64 else ''}",
            "bits": self.bits,
            "machine": self.machine,
            "image_base": hex(self.image_base),
            "entry_point": hex(self.entry_point_rva),
            "subsystem": self.subsystem,
            "section_count": self.num_sections,
            "has_pdata": has_pdata,
            "tls_callbacks": [hex(cb) for cb in tls_info.get("callbacks", [])],
        }

    def sections(self) -> list[dict[str, Any]]:
        """Return section list with Shannon entropy calculations."""
        out = []
        for sec in self._sections:
            raw_ptr = sec["pointer_to_raw_data"]
            raw_size = sec["raw_size"]
            chunk = self.data[raw_ptr : raw_ptr + raw_size]
            entropy = round(_shannon_bytes(chunk), 3) if chunk else 0.0
            out.append(
                {
                    "name": sec["name"],
                    "rva": hex(sec["virtual_address"]),
                    "virtual_size": sec["virtual_size"],
                    "raw_size": raw_size,
                    "entropy": entropy,
                    "characteristics": hex(sec["characteristics"]),
                }
            )
        return out

    def tls(self) -> dict[str, Any]:
        """Extract TLS directory information and TLS callbacks."""
        if len(self.data_directories) <= 9:
            return {"callbacks": []}

        tls_entry = self.data_directories[9]
        if not tls_entry["rva"] or not tls_entry["size"]:
            return {"callbacks": []}

        offset = self.rva_to_offset(tls_entry["rva"])
        if offset is None or offset + (40 if self.bits == 64 else 24) > len(self.data):
            return {"callbacks": []}

        if self.bits == 64:
            start_raw, end_raw, index_addr, callbacks_addr, zero_fill, chars = (
                self._unpack("<QQQQII", offset)
            )
        else:
            start_raw, end_raw, index_addr, callbacks_addr, zero_fill, chars = (
                self._unpack("<IIIIII", offset)
            )

        callbacks: list[int] = []
        if callbacks_addr:
            cb_rva = callbacks_addr - self.image_base
            cb_offset = self.rva_to_offset(cb_rva)
            if cb_offset is not None:
                step = 8 if self.bits == 64 else 4
                fmt = "<Q" if self.bits == 64 else "<I"
                cur = cb_offset
                while cur + step <= len(self.data):
                    (cb_val,) = self._unpack(fmt, cur)
                    if cb_val == 0:
                        break
                    callbacks.append(cb_val)
                    cur += step
                    if len(callbacks) >= 64:  # safety bound
                        break

        return {
            "raw_data_start": hex(start_raw),
            "raw_data_end": hex(end_raw),
            "index_address": hex(index_addr),
            "callbacks_address": hex(callbacks_addr),
            "callbacks": callbacks,
        }

    def exports(self) -> list[dict[str, Any]]:
        """Extract exported functions."""
        if len(self.data_directories) == 0:
            return []
        exp_dir = self.data_directories[0]
        if not exp_dir["rva"] or not exp_dir["size"]:
            return []

        dir_off = self.rva_to_offset(exp_dir["rva"])
        if dir_off is None or dir_off + 40 > len(self.data):
            return []

        (
            _,
            _,
            _,
            _,
            name_rva,
            ordinal_base,
            num_funcs,
            num_names,
            funcs_rva,
            names_rva,
            ordinals_rva,
        ) = self._unpack("<IIHHIIIIIII", dir_off)

        funcs_off = self.rva_to_offset(funcs_rva)
        names_off = self.rva_to_offset(names_rva)
        ords_off = self.rva_to_offset(ordinals_rva)

        if not funcs_off:
            return []

        # Read function RVAs (num_funcs entries)
        funcs: list[int] = []
        for i in range(min(num_funcs, 4096)):
            foff = funcs_off + i * 4
            if foff + 4 <= len(self.data):
                (f_rva,) = self._unpack("<I", foff)
                funcs.append(f_rva)

        name_to_ord: list[tuple[str, int]] = []
        if names_off and ords_off:
            for i in range(min(num_names, 4096)):
                noff = names_off + i * 4
                ooff = ords_off + i * 2
                if noff + 4 <= len(self.data) and ooff + 2 <= len(self.data):
                    (n_rva,) = self._unpack("<I", noff)
                    (ord_idx,) = self._unpack("<H", ooff)
                    str_off = self.rva_to_offset(n_rva)
                    name = self._cstr(str_off) if str_off is not None else ""
                    name_to_ord.append((name, ord_idx))

        # Map to exports
        out: list[dict[str, Any]] = []
        if name_to_ord:
            for name, ord_idx in name_to_ord:
                if ord_idx < len(funcs):
                    rva = funcs[ord_idx]
                    out.append(
                        {
                            "name": name,
                            "ordinal": ordinal_base + ord_idx,
                            "rva": hex(rva),
                        }
                    )
        else:
            for i, rva in enumerate(funcs):
                out.append(
                    {
                        "name": f"Ordinal_{ordinal_base + i}",
                        "ordinal": ordinal_base + i,
                        "rva": hex(rva),
                    }
                )
        return out

    def imports(self) -> list[dict[str, Any]]:
        """Extract imported DLLs and functions."""
        if len(self.data_directories) <= 1:
            return []
        imp_dir = self.data_directories[1]
        if not imp_dir["rva"] or not imp_dir["size"]:
            return []

        imp_off = self.rva_to_offset(imp_dir["rva"])
        if imp_off is None:
            return []

        results: list[dict[str, Any]] = []
        cur_desc = imp_off
        step = 8 if self.bits == 64 else 4
        fmt = "<Q" if self.bits == 64 else "<I"
        ord_mask = 0x8000000000000000 if self.bits == 64 else 0x80000000

        while cur_desc + 20 <= len(self.data):
            orig_thunk, _, _, name_rva, first_thunk = self._unpack("<IIIII", cur_desc)
            if orig_thunk == 0 and first_thunk == 0 and name_rva == 0:
                break

            dll_off = self.rva_to_offset(name_rva)
            dll_name = self._cstr(dll_off) if dll_off is not None else ""

            thunk_rva = orig_thunk if orig_thunk else first_thunk
            thunk_off = self.rva_to_offset(thunk_rva) if thunk_rva else None

            funcs: list[str] = []
            if thunk_off is not None:
                cur_thunk = thunk_off
                while cur_thunk + step <= len(self.data):
                    (val,) = self._unpack(fmt, cur_thunk)
                    if val == 0:
                        break
                    if val & ord_mask:
                        funcs.append(f"Ordinal_{val & 0xFFFF}")
                    else:
                        ibn_off = self.rva_to_offset(val)
                        if ibn_off is not None and ibn_off + 2 < len(self.data):
                            # Skip 2-byte Hint, read ASCII cstring
                            fn_name = self._cstr(ibn_off + 2)
                            funcs.append(fn_name)
                    cur_thunk += step
                    if len(funcs) >= 1024:
                        break

            results.append({"dll": dll_name, "functions": funcs})
            cur_desc += 20
            if len(results) >= 256:
                break

        return results

    # ------------------------------------------------------------------ resources
    # Resource types are defined by the PE spec; the ids below are the standard
    # ones. An id above these is a user-defined type and is reported by number
    # rather than invented as a name.
    _RESOURCE_TYPES = {
        1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
        7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
        12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
        19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML",
        24: "MANIFEST",
    }
    _RESOURCE_MAX_ENTRIES = 4096

    def resources(self) -> dict[str, Any]:
        """Walk the resource directory tree and inventory every leaf.

        WHY this exists: a PE's resources are where its icon, version block and
        manifest live, and they are the first thing that distinguishes a real
        application from a stub. REA exposes `inspect_pe_resources`; without this
        the engine could list imports and exports and still say nothing about what
        the binary presents to the OS.

        The tree is three levels deep by convention (type -> name -> language) but
        the format allows arbitrary depth, so this walks recursively with a hard
        entry cap. A malformed tree yields a warning and stops that branch: a
        broken resource section must not make the rest of the binary unreadable.
        """
        result: dict[str, Any] = {"ok": True, "entries": [], "types": [],
                                  "count": 0, "warnings": []}
        if len(self.data_directories) <= 2:
            result["warnings"].append("no resource data directory")
            return result
        res_dir = self.data_directories[2]
        if not res_dir["rva"] or not res_dir["size"]:
            result["warnings"].append("resource directory is empty")
            return result

        base = self.rva_to_offset(res_dir["rva"])
        if base is None:
            result["warnings"].append("resource directory RVA is not mapped to a file offset")
            return result

        entries: list[dict[str, Any]] = []
        seen: set[int] = set()
        truncated = False

        def walk(offset: int, depth: int, path: list[str]) -> None:
            nonlocal truncated
            if depth > 4 or len(entries) >= self._RESOURCE_MAX_ENTRIES:
                truncated = True
                return
            start = base + offset
            if start + 16 > len(self.data) or start < 0:
                result["warnings"].append(f"resource directory at 0x{offset:x} is out of bounds")
                return
            if offset in seen:
                result["warnings"].append(f"resource directory at 0x{offset:x} forms a cycle")
                return
            seen.add(offset)

            (_chars, _ts, _maj, _min, named, ids) = self._unpack("<IIHHHH", start)
            total = named + ids
            if total > self._RESOURCE_MAX_ENTRIES:
                result["warnings"].append(
                    f"resource directory at 0x{offset:x} claims {total} entries; capped")
                total = self._RESOURCE_MAX_ENTRIES
                truncated = True
            for i in range(total):
                entry_off = start + 16 + i * 8
                if entry_off + 8 > len(self.data):
                    result["warnings"].append("resource entry runs past end of file")
                    break
                name_field, data_field = self._unpack("<II", entry_off)
                # High bit set means "this is a subdirectory", not a leaf.
                is_dir = bool(data_field & 0x80000000)
                child = data_field & 0x7FFFFFFF
                if name_field & 0x80000000:
                    # Name is an offset into the resource string table (UTF-16).
                    str_off = base + (name_field & 0x7FFFFFFF)
                    label = self._resource_string(str_off)
                elif depth == 0:
                    # The type map applies only at the top level. At deeper levels an
                    # integer id is a resource *name* or a language, and reusing the
                    # type table there turns name id 2 into "CURSOR" — which reads as
                    # a fact and is wrong.
                    label = str(self._RESOURCE_TYPES.get(name_field, name_field))
                else:
                    label = str(name_field)
                if is_dir:
                    walk(child, depth + 1, path + [label])
                    continue
                # Leaf: IMAGE_RESOURCE_DATA_ENTRY, 16 bytes.
                leaf = base + child
                if leaf + 16 > len(self.data):
                    result["warnings"].append("resource data entry runs past end of file")
                    continue
                data_rva, data_size, _cp, _res = self._unpack("<IIII", leaf)
                file_off = self.rva_to_offset(data_rva)
                # The leaf's own label is the innermost component, so it is the
                # *language* in the conventional type/name/language tree — not the
                # name. Reading it the other way round produced name=1033,
                # language=1 for a VERSIONINFO that is actually type 16, name 1,
                # language 1033; llvm-readobj is the check that caught it.
                full = path + [label]
                entries.append({
                    "type": full[0] if full else label,
                    "name": full[1] if len(full) > 1 else None,
                    "path": "/".join(full),
                    "language": full[2] if len(full) > 2 else None,
                    "rva": f"0x{data_rva:x}",
                    "offset": file_off,
                    "size": data_size,
                    "in_file": file_off is not None,
                })
                if len(entries) >= self._RESOURCE_MAX_ENTRIES:
                    truncated = True
                    return

        walk(0, 0, [])
        result["entries"] = entries
        result["count"] = len(entries)
        result["types"] = sorted({e["type"] for e in entries})
        result["truncated"] = truncated
        return result

    def _resource_string(self, offset: int) -> str:
        """Read a length-prefixed UTF-16 resource name."""
        if offset < 0 or offset + 2 > len(self.data):
            return ""
        (length,) = self._unpack("<H", offset)
        # Each unit is 2 bytes; cap so a corrupt length cannot read the whole file.
        length = min(length, 512)
        start = offset + 2
        end = min(start + length * 2, len(self.data))
        try:
            return self.data[start:end].decode("utf-16-le", "replace")
        except (UnicodeDecodeError, ValueError):
            return ""

    # --------------------------------------------------------------- load config
    def load_config(self) -> dict[str, Any]:
        """Read the PE load-configuration directory.

        WHY this matters for analysis: the load config is where a binary declares
        its security-relevant behaviour — the SafeSEH handler table, CFG guard
        flags and check function, the stack cookie, and (in newer links) the
        pointer to the CFG bitmap. Exploit developers read it to find mitigations;
        defenders read it to check them. REA exposes `inspect_pe_load_config`.

        The structure grew across Windows versions, so the field layout is chosen
        by *size*, not by magic: a 0x40-byte directory predates SEH fields, 0x5C
        ends at SecurityCookie, 0x70 adds SEHandlerTable/Count. Reading a field
        the directory does not contain would report a mitigation the binary was
        never linked with, so each field is gated on the declared size.
        """
        result: dict[str, Any] = {"ok": True, "present": False, "size": 0,
                                  "fields": {}, "warnings": []}
        if len(self.data_directories) <= 10:
            result["warnings"].append("no load-config data directory")
            return result
        entry = self.data_directories[10]
        if not entry["rva"] or not entry["size"]:
            result["warnings"].append("load config directory is empty")
            return result
        offset = self.rva_to_offset(entry["rva"])
        if offset is None or offset + 4 > len(self.data):
            result["warnings"].append("load config RVA is not mapped to a file offset")
            return result

        # The directory declares its own size as the first DWORD, which is the
        # authority on how many fields follow. Trust the smaller of that and the
        # data-directory size so a lie in either cannot walk past the file.
        declared = min(self._unpack("<I", offset)[0], entry["size"])
        result["present"] = True
        result["size"] = declared
        result["signature"] = f"0x{self._unpack('<I', offset)[0]:x}"

        # (name, struct offset from directory start, struct format)
        layout = [
            ("timestamp", 0x04, "<I"),
            ("major_version", 0x08, "<H"),
            ("minor_version", 0x0A, "<H"),
            ("global_flags_clear", 0x0C, "<I"),
            ("global_flags_set", 0x10, "<I"),
            ("critical_section_default_timeout", 0x14, "<I"),
            ("decommit_free_block_threshold", 0x18, "<Q"),
            ("decommit_total_free_threshold", 0x20, "<Q"),
            ("lock_prefix_table", 0x28, "<Q"),
            ("maximum_allocation_size", 0x30, "<Q"),
            ("virtual_memory_threshold", 0x38, "<Q"),
            ("process_affinity_mask", 0x40, "<Q"),
            ("process_heap_flags", 0x48, "<I"),
            ("csd_version", 0x4C, "<H"),
            ("dependent_load_flags", 0x4E, "<H"),
            ("edit_list", 0x50, "<Q"),
            ("security_cookie", 0x58, "<Q"),
            ("se_handler_table", 0x60, "<Q"),
            ("se_handler_count", 0x68, "<Q"),
            ("guard_cf_check_function", 0x70, "<Q"),
            ("guard_cf_dispatch_function", 0x78, "<Q"),
            ("guard_cf_function_table", 0x80, "<Q"),
            ("guard_cf_function_count", 0x88, "<Q"),
            ("guard_flags", 0x90, "<I"),
            ("code_integrity_flags", 0x94, "<H"),
        ]
        fields: dict[str, Any] = {}
        for name, rel, fmt in layout:
            width = struct.calcsize(fmt)
            if rel + width > declared:
                continue
            value = self._unpack(fmt, offset + rel)[0]
            fields[name] = value
        result["fields"] = fields

        # Decode the mitigations an analyst actually asks about, and only when the
        # field was present. A mitigation reported from an absent field is a false
        # statement about the binary's defences.
        mitigations: dict[str, Any] = {}
        if "security_cookie" in fields:
            mitigations["gs_cookie"] = fields["security_cookie"] != 0
        if "se_handler_table" in fields:
            mitigations["safe_seh"] = fields["se_handler_table"] != 0
        guard = fields.get("guard_flags")
        if guard is not None:
            mitigations["control_flow_guard"] = bool(guard & 0x100)
            mitigations["cfg_export_suppression"] = bool(guard & 0x800)
            mitigations["xfg_enabled"] = bool(guard & 0x40000)
            mitigations["cast_guard"] = bool(guard & 0x80000)
            guard_flags = guard
        else:
            guard_flags = None
        mitigations["high_entropy_va"] = bool(fields.get("global_flags_set", 0) & 0x20)

        # SafeSEH only means anything on a 32-bit image; on x64 the table is unused
        # and a zero there is not a missing mitigation, so do not claim one.
        if self.opt_magic == 0x020B and "safe_seh" in mitigations:
            mitigations["safe_seh"] = None
            result["warnings"].append(
                "safe_seh is not applicable to a 64-bit image (SEH is table-based)")
        result["mitigations"] = mitigations
        if guard_flags is not None:
            result["guard_flags"] = f"0x{guard_flags:x}"
        return result

    # ------------------------------------------------------------- certificates
    def certificates(self) -> dict[str, Any]:
        """Inventory the Authenticode signature table.

        The certificate directory is special: unlike every other data directory,
        its "rva" is a *file offset*, not an RVA. Treating it as an RVA walks into
        an unrelated part of the image and reports a signature that is not there,
        so this reads it as an offset explicitly.

        The payload is a WIN_CERTIFICATE aligned on an 8-byte boundary inside the
        file. This reports the structure and the DER size; it does not verify the
        signature (that needs the trust chain, which is a different question).
        """
        result: dict[str, Any] = {"ok": True, "signed": False, "certificates": [],
                                  "warnings": []}
        if len(self.data_directories) <= 4:
            result["warnings"].append("no certificate data directory")
            return result
        entry = self.data_directories[4]
        if not entry["rva"] or not entry["size"]:
            result["warnings"].append("image is not signed (certificate directory empty)")
            return result

        # Deliberately NOT rva_to_offset: see docstring.
        offset = entry["rva"]
        end = offset + entry["size"]
        if offset >= len(self.data):
            result["warnings"].append(
                f"certificate table offset 0x{offset:x} is past end of file "
                f"(size {len(self.data)}); treated as a file offset per spec")
            return result
        end = min(end, len(self.data))

        cursor = offset
        while cursor + 8 <= end:
            length, revision, cert_type = self._unpack("<IHH", cursor)
            if length < 8:
                result["warnings"].append(
                    f"certificate entry at 0x{cursor:x} declares length {length}; stopping")
                break
            payload_start = cursor + 8
            payload_end = min(cursor + length, len(self.data))
            payload = self.data[payload_start:payload_end]
            # Detect DER SEQUENCE so we can describe the encoding rather than guess.
            encoding = "unknown"
            if payload[:1] == b"\x30":
                encoding = "DER PKCS#7 (SEQUENCE)"
            elif payload[:4] == b"\x00\x02\x00\x00" or payload[:2] == b"\x1e\x00":
                encoding = "legacy PKCS#1/SignedData"
            result["certificates"].append({
                "offset": cursor,
                "length": length,
                "revision": f"0x{revision:x}",
                "revision_name": {0x100: "1.0", 0x200: "2.0"}.get(revision, "unknown"),
                "type": f"0x{cert_type:x}",
                "type_name": {0x0001: "X509", 0x0002: "PKCS_SIGNED_DATA",
                              0x0003: "RESERVED_1", 0x0004: "TS_STACK_SIGNED"}.get(
                                  cert_type, "unknown"),
                "payload_size": len(payload),
                "encoding": encoding,
            })
            # Entries are 8-byte aligned; step by the aligned length.
            step = (length + 7) & ~7
            if step == 0:
                break
            cursor += step

        result["signed"] = bool(result["certificates"])
        if not result["signed"] and not result["warnings"]:
            result["warnings"].append("certificate directory present but no entry parsed")
        return result
