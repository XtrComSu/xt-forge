"""Contract tests for pure-Python dependency-free PE parser."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.pe import PEFile, PeError


def create_minimal_pe(
    bits: int = 64,
    sections: list[tuple[str, int, int, bytes, int]] | None = None,
    entry_point_rva: int = 0x1000,
    image_base: int = 0x140000000,
    tls_callbacks: list[int] | None = None,
    exports: list[tuple[str, int, int]] | None = None,
    imports: dict[str, list[str]] | None = None,
) -> bytes:
    """Helper to synthesize a valid minimal PE32 or PE32+ binary in memory."""
    # DOS Header (64 bytes)
    # e_magic = 'MZ' (0x5A4D), e_lfanew at 0x3C = 0x80 (128)
    dos_header = bytearray(128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 128)

    # PE Signature (4 bytes)
    pe_sig = b"PE\0\0"

    # COFF File Header (20 bytes)
    machine = 0x8664 if bits == 64 else 0x14C
    sec_count = len(sections or [])
    time_date = 0x60000000
    sym_ptr = 0
    sym_count = 0
    opt_size = 240 if bits == 64 else 224
    chars = 0x0002 | 0x0020  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        sec_count,
        time_date,
        sym_ptr,
        sym_count,
        opt_size,
        chars,
    )

    # Optional Header
    opt_magic = 0x20B if bits == 64 else 0x10B
    linker_major = 14
    linker_minor = 0
    code_size = 0x1000
    init_data_size = 0x1000
    uninit_data_size = 0
    entry_rva = entry_point_rva
    base_of_code = 0x1000

    # Data directories count = 16
    num_rva_sizes = 16

    # Build data directories table placeholder (16 * 8 = 128 bytes)
    data_dirs = bytearray(128)

    # We will assemble sections and populate data dirs if requested
    raw_headers_size = 0x400  # 1024 bytes
    section_alignment = 0x1000
    file_alignment = 0x200
    subsystem = 3  # Windows CUI
    dll_chars = 0x8160

    if bits == 64:
        opt_standard = struct.pack(
            "<HBBIIIII",
            opt_magic,
            linker_major,
            linker_minor,
            code_size,
            init_data_size,
            uninit_data_size,
            entry_rva,
            base_of_code,
        )
        opt_windows = struct.pack(
            "<QIIHHHHHHIIIIHHQQQQII",
            image_base,
            section_alignment,
            file_alignment,
            6, 0,  # OS version
            0, 0,  # Image version
            6, 0,  # Subsystem version
            0,     # Win32VersionValue
            0x4000, # SizeOfImage
            raw_headers_size,
            0,     # Checksum
            subsystem,
            dll_chars,
            0x100000, 0x1000, # Stack reserve/commit
            0x100000, 0x1000, # Heap reserve/commit
            0,     # LoaderFlags
            num_rva_sizes,
        )
    else:
        base_of_data = 0x2000
        opt_standard = struct.pack(
            "<HBBIIIIII",
            opt_magic,
            linker_major,
            linker_minor,
            code_size,
            init_data_size,
            uninit_data_size,
            entry_rva,
            base_of_code,
            base_of_data,
        )
        opt_windows = struct.pack(
            "<IIIHHHHHHIIIIHHIIIIII",
            image_base,
            section_alignment,
            file_alignment,
            6, 0,
            0, 0,
            6, 0,
            0,
            0x4000,
            raw_headers_size,
            0,
            subsystem,
            dll_chars,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0,
            num_rva_sizes,
        )

    # Prepare file image buffer
    buf = bytearray(raw_headers_size)
    buf[0:128] = dos_header
    buf[128:132] = pe_sig
    buf[132:152] = coff_header
    buf[152 : 152 + len(opt_standard)] = opt_standard
    off = 152 + len(opt_standard)
    buf[off : off + len(opt_windows)] = opt_windows
    off += len(opt_windows)
    data_dir_offset = off
    # Space for 16 data dirs
    off += 128

    # Sections header offset is `off`
    sec_header_offset = off
    curr_raw_offset = raw_headers_size

    sec_headers = []
    sec_bodies = []
    if sections:
        for name, vaddr, vsize, content, sec_chars in sections:
            padded_name = name.encode("ascii")[:8].ljust(8, b"\0")
            raw_size = len(content)
            # Section header is 40 bytes
            sh = struct.pack(
                "<8sIIIIIIHHI",
                padded_name,
                vsize,
                vaddr,
                raw_size,
                curr_raw_offset,
                0, 0, 0, 0,
                sec_chars,
            )
            sec_headers.append(sh)
            sec_bodies.append((curr_raw_offset, content))
            curr_raw_offset += (raw_size + 0x1FF) & ~0x1FF

    for i, sh in enumerate(sec_headers):
        buf[sec_header_offset + i * 40 : sec_header_offset + (i + 1) * 40] = sh

    # Now pad up to headers size and append section bodies
    out = bytearray(buf)
    for raw_off, body in sec_bodies:
        if len(out) < raw_off:
            out.extend(b"\0" * (raw_off - len(out)))
        out.extend(body)
        pad = ((len(body) + 0x1FF) & ~0x1FF) - len(body)
        if pad > 0:
            out.extend(b"\0" * pad)

    # Directory 0: Export Directory (RVA, Size)
    # Directory 1: Import Directory
    # Directory 9: TLS Directory
    # Directory 3: Exception Directory (.pdata)
    if exports and sections:
        # Build Export Directory Table
        sec_vaddr = sections[0][1]
        exp_dir_rva = sec_vaddr + 0x300
        # Export directory structure: 40 bytes
        # AddressOfFunctions at exp_dir_rva + 40
        # AddressOfNames at exp_dir_rva + 40 + 4*len(exports)
        # AddressOfNameOrdinals at exp_dir_rva + 40 + 8*len(exports)
        # Strings after ordinals
        funcs_rva = exp_dir_rva + 40
        names_rva = funcs_rva + 4 * len(exports)
        ords_rva = names_rva + 4 * len(exports)
        strings_rva = ords_rva + 2 * len(exports)

        funcs_table = bytearray()
        names_table = bytearray()
        ords_table = bytearray()
        strings_blob = bytearray()

        for idx, (exp_name, exp_rva, exp_ord) in enumerate(exports):
            funcs_table.extend(struct.pack("<I", exp_rva))
            names_table.extend(struct.pack("<I", strings_rva + len(strings_blob)))
            ords_table.extend(struct.pack("<H", idx))
            strings_blob.extend(exp_name.encode("ascii") + b"\0")

        exp_dir = struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            strings_rva + len(strings_blob), # DLL name
            1, # ordinal base
            len(exports),
            len(exports),
            funcs_rva,
            names_rva,
            ords_rva,
        )
        strings_blob.extend(b"test.dll\0")

        exp_total_data = exp_dir + funcs_table + names_table + ords_table + strings_blob
        file_exp_off = raw_headers_size + 0x300
        out[file_exp_off : file_exp_off + len(exp_total_data)] = exp_total_data
        struct.pack_into("<II", out, data_dir_offset + 0 * 8, exp_dir_rva, len(exp_total_data))

    if imports and sections:
        # Build Import Directory
        sec_vaddr = sections[0][1]
        imp_dir_rva = sec_vaddr + 0x600
        file_imp_off = raw_headers_size + 0x600
        
        # We will write:
        # 1. Import descriptors (20 bytes each, plus 20 byte null terminator)
        # 2. DLL name strings
        # 3. ILT (INT) arrays (null terminated)
        # 4. IAT arrays (null terminated)
        # 5. Hint/Name entries
        step = 8 if bits == 64 else 4
        fmt = "<Q" if bits == 64 else "<I"

        desc_count = len(imports) + 1
        desc_bytes_len = desc_count * 20
        blob_offset = imp_dir_rva + desc_bytes_len
        blob = bytearray()

        descriptors = bytearray()
        for dll_name, funcs in imports.items():
            dll_str_rva = blob_offset + len(blob)
            blob.extend(dll_name.encode("ascii") + b"\0")

            # Build ILT and IAT entries
            thunk_rva = blob_offset + len(blob)
            thunk_entries = bytearray()
            for fn in funcs:
                hint_name_rva = blob_offset + len(blob) + (len(funcs) + 1) * step + len(thunk_entries) # placeholder
                # We will place hint/name after thunks
                thunk_entries.extend(struct.pack(fmt, hint_name_rva))
            thunk_entries.extend(struct.pack(fmt, 0)) # null terminator

            # We write ILT thunk
            ilt_rva = blob_offset + len(blob)
            blob.extend(thunk_entries)

            # Write Hint/Name structures
            # Hint (2 bytes) + Name + \0
            hn_rvas = []
            for fn in funcs:
                hn_rvas.append(blob_offset + len(blob))
                blob.extend(struct.pack("<H", 0) + fn.encode("ascii") + b"\0")

            # Fix up the ILT entries with exact hn_rvas
            for i, hn_rva in enumerate(hn_rvas):
                struct.pack_into(fmt, blob, ilt_rva - blob_offset + i * step, hn_rva)

            desc = struct.pack("<IIIII", ilt_rva, 0, 0, dll_str_rva, ilt_rva)
            descriptors.extend(desc)

        descriptors.extend(b"\0" * 20) # null descriptor
        total_imp = descriptors + blob
        out[file_imp_off : file_imp_off + len(total_imp)] = total_imp
        struct.pack_into("<II", out, data_dir_offset + 1 * 8, imp_dir_rva, len(total_imp))

    # If TLS callbacks requested, write TLS directory to .data if available
    if tls_callbacks and sections:
        # Put TLS dir in first section
        sec_vaddr = sections[0][1]
        sec_raw = sections[0][3]
        tls_dir_rva = sec_vaddr + 0x100
        # TLS Directory structure
        # In PE32+: StartAddressOfRawData (Q), EndAddressOfRawData (Q), AddressOfIndex (Q), AddressOfCallBacks (Q)
        # In PE32: StartAddressOfRawData (I), EndAddressOfRawData (I), AddressOfIndex (I), AddressOfCallBacks (I)
        callbacks_va = image_base + tls_dir_rva + 0x40
        callbacks_rva = tls_dir_rva + 0x40
        if bits == 64:
            tls_data = struct.pack("<QQQQII", 0, 0, 0, callbacks_va, 0, 0)
        else:
            tls_data = struct.pack("<IIIIII", 0, 0, 0, callbacks_va, 0, 0)

        # Write callbacks array (null terminated)
        cb_bytes = bytearray()
        for cb in tls_callbacks:
            cb_bytes.extend(struct.pack("<Q" if bits == 64 else "<I", cb))
        cb_bytes.extend(struct.pack("<Q" if bits == 64 else "<I", 0))

        # Place inside file
        file_tls_off = raw_headers_size + 0x100
        out[file_tls_off : file_tls_off + len(tls_data)] = tls_data
        out[file_tls_off + 0x40 : file_tls_off + 0x40 + len(cb_bytes)] = cb_bytes

        # Set TLS directory entry in Data Directories (index 9)
        struct.pack_into("<II", out, data_dir_offset + 9 * 8, tls_dir_rva, len(tls_data))

    return bytes(out)


class TestPEParser(unittest.TestCase):
    def test_invalid_magic_raises_pe_error(self):
        with self.assertRaises(PeError):
            PEFile(b"NOT_A_PE_FILE")

    def test_truncated_pe_raises_pe_error(self):
        with self.assertRaises(PeError):
            PEFile(b"MZ" + b"\0" * 30)

    def test_valid_minimal_pe64(self):
        sec_code = b"\x90\x90\xc3\x00" * 256
        pe_bytes = create_minimal_pe(
            bits=64,
            sections=[(".text", 0x1000, 0x1000, sec_code, 0x60000020)],
            entry_point_rva=0x1000,
            tls_callbacks=[0x140001050, 0x140001080],
        )
        pe = PEFile(pe_bytes)
        info = pe.info()
        self.assertEqual(info["bits"], 64)
        self.assertEqual(info["machine"], "x86-64")
        self.assertEqual(info["entry_point"], "0x1000")
        self.assertEqual(info["image_base"], "0x140000000")
        self.assertEqual(len(info["tls_callbacks"]), 2)
        self.assertIn("0x140001050", info["tls_callbacks"])

        secs = pe.sections()
        self.assertEqual(len(secs), 1)
        self.assertEqual(secs[0]["name"], ".text")
        self.assertEqual(secs[0]["rva"], "0x1000")
        self.assertGreater(secs[0]["entropy"], 0.0)

        # Test RVA to file offset
        self.assertEqual(pe.rva_to_offset(0x1010), 0x400 + 0x10)
        self.assertIsNone(pe.rva_to_offset(0x999999))

    def test_pe32_exports_and_imports(self):
        sec_code = b"\x90" * 0x1000
        pe_bytes = create_minimal_pe(
            bits=32,
            sections=[(".text", 0x1000, 0x1000, sec_code, 0x60000020)],
            entry_point_rva=0x1000,
            image_base=0x400000,
            exports=[("InitPlugin", 0x1020, 1), ("DestroyPlugin", 0x1040, 2)],
            imports={"kernel32.dll": ["ExitProcess", "GetLastError"], "user32.dll": ["MessageBoxA"]},
        )
        pe = PEFile(pe_bytes)
        info = pe.info()
        self.assertEqual(info["bits"], 32)
        self.assertEqual(info["machine"], "x86")
        self.assertEqual(info["image_base"], "0x400000")

        exps = pe.exports()
        self.assertEqual(len(exps), 2)
        self.assertEqual(exps[0]["name"], "InitPlugin")
        self.assertEqual(exps[0]["rva"], "0x1020")
        self.assertEqual(exps[1]["name"], "DestroyPlugin")

        imps = pe.imports()
        self.assertEqual(len(imps), 2)
        self.assertEqual(imps[0]["dll"], "kernel32.dll")
        self.assertIn("ExitProcess", imps[0]["functions"])
        self.assertIn("GetLastError", imps[0]["functions"])
        self.assertEqual(imps[1]["dll"], "user32.dll")
        self.assertIn("MessageBoxA", imps[1]["functions"])

    def test_file_path_and_guard(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "test.exe"
            sec_code = b"\xcc" * 0x1000
            data = create_minimal_pe(
                bits=64,
                sections=[(".text", 0x1000, 0x1000, sec_code, 0x60000020)],
            )
            fpath.write_bytes(data)

            pe = PEFile(fpath)
            self.assertEqual(pe.info()["bits"], 64)

            # Nonexistent file raises PeError
            with self.assertRaises(PeError):
                PEFile(Path(tmpdir) / "nonexistent.exe")

    def test_corrupt_structures_raise_pe_error(self):
        # Corrupt e_lfanew pointing out of file bounds
        b = bytearray(b"MZ" + b"\0" * 126)
        struct.pack_into("<I", b, 0x3C, 0x7FFFFFFF)
        with self.assertRaises(PeError):
            PEFile(bytes(b))

        # Corrupt section table extending past file
        pe_bytes = bytearray(create_minimal_pe(bits=64, sections=[(".text", 0x1000, 0x1000, b"\0"*512, 0x60000020)]))
        # Modify number of sections to 100
        pe_offset = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        struct.pack_into("<H", pe_bytes, pe_offset + 4 + 2, 100)
        with self.assertRaises(PeError):
            PEFile(bytes(pe_bytes))
