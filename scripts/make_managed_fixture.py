#!/usr/bin/env python3
"""Hand-build a minimal PE/CLI (.NET) assembly with known metadata.

WHY hand-build rather than compile: no .NET toolchain exists on this host, and the
only managed assemblies available (Wine's .winmd files) are reference metadata with
placeholder versions of 255.255.255.255 and no IL bodies. Asserting against those
would only prove the parser can read a degenerate file.

Building the bytes here means every expected value is chosen by this script, so the
test asserts against a fact rather than against another reader. The layout follows
ECMA-335 II.24 (metadata physical layout) and II.22 (table definitions).

What the fixture contains, deliberately chosen to exercise the awkward paths:
  * one Assembly with a real 1.2.3.4 version and a non-empty culture
  * three TypeDefs, one nested inside another (NestedClass table present)
  * a static method, a virtual method, and an abstract method (flag decoding)
  * one P/Invoke into kernel32.dll via ImplMap + ModuleRef (native boundary)
  * two AssemblyRefs (dependency listing)
  * #Strings larger than 64 KiB? No — that would need a big heap. Instead the
    #Strings heap is small and the heap-size flags stay 2 bytes, which is the
    common case. scripts/make_pe_fixtures.py covers the PE side.

Usage: python3 scripts/make_managed_fixture.py <output-dir>
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------- chosen values
ASSEMBLY_NAME = "XtForgeFixture"
ASSEMBLY_VERSION = (1, 2, 3, 4)
ASSEMBLY_CULTURE = "neutral"
MODULE_NAME = "XtForgeFixture.dll"
TYPE_NAMES = ["Program", "Outer", "Inner"]
TYPE_NAMESPACES = ["XtForge", "XtForge", "XtForge.Nested"]
METHOD_NAMES = ["Main", "VirtualThing", "AbstractThing", "NativeCall"]
REF_NAMES = ["System.Runtime", "System.Console"]
PINVOKE_DLL = "kernel32.dll"
PINVOKE_IMPORT = "Beep"


class StringsHeap:
    """#Strings heap. Index 0 is always the empty string."""

    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self._offsets: dict[str, int] = {"": 0}

    def add(self, value: str) -> int:
        if value in self._offsets:
            return self._offsets[value]
        offset = len(self.data)
        self.data.extend(value.encode("utf-8") + b"\0")
        self._offsets[value] = offset
        return offset


class BlobHeap:
    """#Blob heap. Index 0 is an empty blob."""

    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self._offsets: dict[bytes, int] = {b"": 0}

    def add(self, value: bytes) -> int:
        if value in self._offsets:
            return self._offsets[value]
        offset = len(self.data)
        self.data.extend(_compressed_uint(len(value)) + value)
        self._offsets[value] = offset
        return offset


def _compressed_uint(value: int) -> bytes:
    """ECMA-335 II.23.2 compressed unsigned integer."""
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    return bytes([0xC0 | (value >> 24), (value >> 16) & 0xFF,
                  (value >> 8) & 0xFF, value & 0xFF])


def build() -> bytes:
    strings = StringsHeap()
    blobs = BlobHeap()

    # ---- table rows, as lists of already-encoded fields ----------------------
    # Indexes into #Strings / #Blob are 2 bytes because the heaps stay small.
    def s(value: str) -> bytes:
        return struct.pack("<H", strings.add(value))

    def b(value: bytes) -> bytes:
        return struct.pack("<H", blobs.add(value))

    def u16(value: int) -> bytes:
        return struct.pack("<H", value)

    def u32(value: int) -> bytes:
        return struct.pack("<I", value)

    # A TypeDefOrRef coded index with tag 0 (TypeDef) and the given 1-based rid.
    def typedef_or_ref(rid: int) -> bytes:
        return struct.pack("<H", (rid << 2) | 0)

    # MemberForwarded with tag 1 (MethodDef).
    def member_forwarded(method_rid: int) -> bytes:
        return struct.pack("<H", (method_rid << 1) | 1)

    # ---- Module (0x00): generation, name, mvid, encid, encbaseid ------------
    module_rows = [u16(0) + s(MODULE_NAME) + u16(0) + u16(0) + u16(0)]

    # ---- TypeRef (0x01): resolution_scope, name, namespace ------------------
    # Scope uses ResolutionScope with tag 2 (AssemblyRef).
    def assembly_ref_scope(rid: int) -> bytes:
        return struct.pack("<H", (rid << 2) | 2)

    type_ref_rows = [
        assembly_ref_scope(1) + s("Object") + s("System"),
        assembly_ref_scope(2) + s("Console") + s("System"),
    ]

    # ---- TypeDef (0x02): flags, name, ns, extends, fieldlist, methodlist ----
    # Field and MethodDef lists are 1-based starting indexes into their tables.
    type_def_rows = [
        u32(0x00100001) + s(TYPE_NAMES[0]) + s(TYPE_NAMESPACES[0])
        + typedef_or_ref(1) + u16(1) + u16(1),
        u32(0x00100001) + s(TYPE_NAMES[1]) + s(TYPE_NAMESPACES[1])
        + typedef_or_ref(1) + u16(1) + u16(2),
        u32(0x00100002) + s(TYPE_NAMES[2]) + s(TYPE_NAMESPACES[2])
        + typedef_or_ref(1) + u16(1) + u16(4),
    ]

    # ---- MethodDef (0x06): rva, implflags, flags, name, sig, paramlist -----
    # RVA 0 means "no IL body", which is what a P/Invoke has.
    # ECMA-335 II.23.1.10. The bit positions matter and are easy to mix up:
    # MemberAccess 0x0007 (an exclusive range), Static 0x0010, Final 0x0020,
    # Virtual 0x0040, HideBySig 0x0080, NewSlot 0x0100, Abstract 0x0400.
    method_flags_private_static = 0x0010 | 0x0001           # Static | Private
    method_flags_public_virtual = 0x0010 | 0x0006 | 0x0040  # Static|Public|Virtual
    method_flags_public_abstract = 0x0006 | 0x0040 | 0x0400  # Public|Virtual|Abstract
    impl_il = 0x0000
    impl_pinvoke = 0x0001 | 0x2000  # Native | PreserveSig
    method_def_rows = [
        u32(0x2050) + u16(impl_il) + u16(method_flags_private_static)
        + s(METHOD_NAMES[0]) + b(b"\x00\x00\x01") + u16(1),
        u32(0x2060) + u16(impl_il) + u16(method_flags_public_virtual)
        + s(METHOD_NAMES[1]) + b(b"\x00\x00\x01") + u16(1),
        u32(0) + u16(impl_il) + u16(method_flags_public_abstract)
        + s(METHOD_NAMES[2]) + b(b"\x00\x00\x01") + u16(1),
        u32(0) + u16(impl_pinvoke) + u16(0x0010 | 0x0006)
        + s(METHOD_NAMES[3]) + b(b"\x00\x00\x01") + u16(1),
    ]

    # ---- ModuleRef (0x1A): name --------------------------------------------
    module_ref_rows = [s(PINVOKE_DLL)]

    # ---- ImplMap (0x1C): mappingflags, memberforwarded, importname, moduleref
    impl_map_rows = [
        u16(0x0100) + member_forwarded(4) + s(PINVOKE_IMPORT) + u16(1),
    ]

    # ---- Assembly (0x20) ---------------------------------------------------
    assembly_rows = [
        u32(0x8004)                       # hash algorithm: SHA1
        + u16(ASSEMBLY_VERSION[0]) + u16(ASSEMBLY_VERSION[1])
        + u16(ASSEMBLY_VERSION[2]) + u16(ASSEMBLY_VERSION[3])
        + u32(0x0001)                      # flags: PublicKey
        + b(b"\x01\x02\x03\x04")           # 4-byte "public key"
        + s(ASSEMBLY_NAME) + s(ASSEMBLY_CULTURE)
    ]

    # ---- AssemblyRef (0x23) ------------------------------------------------
    assembly_ref_rows = [
        u16(4) + u16(0) + u16(0) + u16(0) + u32(0)
        + b(b"\xb0\x3f\x5f\x7f\x11\xd5\x0a\x3a")
        + s(REF_NAMES[0]) + s("") + b(b""),
        u16(4) + u16(0) + u16(0) + u16(0) + u32(0)
        + b(b"\xb0\x3f\x5f\x7f\x11\xd5\x0a\x3a")
        + s(REF_NAMES[1]) + s("") + b(b""),
    ]

    # ---- NestedClass (0x29): nested_class, enclosing_class ----------------
    nested_class_rows = [u16(3) + u16(2)]  # TypeDef rid 3 nested in rid 2

    # Table id -> rows, in ascending id order (required: row data is ordered).
    tables = {
        0x00: module_rows,
        0x01: type_ref_rows,
        0x02: type_def_rows,
        0x06: method_def_rows,
        0x1A: module_ref_rows,
        0x1C: impl_map_rows,
        0x20: assembly_rows,
        0x23: assembly_ref_rows,
        0x29: nested_class_rows,
    }

    # ---- #~ stream ---------------------------------------------------------
    valid = 0
    for tid in tables:
        valid |= 1 << tid
    header = bytearray()
    header += u32(0)                 # Reserved
    header += bytes([2, 0, 0])       # Major=2, Minor=0, HeapSizes=0 (all 2-byte)
    header += bytes([1])             # Reserved
    header += struct.pack("<Q", valid)
    header += struct.pack("<Q", 0)   # Sorted mask: nothing claims to be sorted
    for tid in sorted(tables):
        header += u32(len(tables[tid]))
    rows = bytearray(header)
    for tid in sorted(tables):
        for row in tables[tid]:
            rows += row

    # ---- metadata root -----------------------------------------------------
    version = b"v4.0.30319\0\0"
    root = bytearray()
    root += u32(0x424A5342)          # BSJB
    root += u16(1) + u16(1)          # Major, Minor
    root += u32(0)                   # Reserved
    root += u32(len(version))
    root += version
    streams = [
        ("#~", bytes(rows)),
        ("#Strings", bytes(strings.data)),
        ("#US", b"\0"),
        ("#GUID", b"\0" * 16),
        ("#Blob", bytes(blobs.data)),
    ]
    root += u16(0) + u16(len(streams))
    # Stream headers first, then the payloads, each 4-byte aligned.
    header_size = 4 + 2 + 2 + 4 + 4 + len(version)
    header_size += 4
    for name, _ in streams:
        header_size += 8 + len(name.encode()) + 1
        header_size += (-(header_size)) % 4
    payload_offsets = []
    cursor = header_size
    for name, payload in streams:
        padded = len(payload) + (-len(payload)) % 4
        payload_offsets.append(cursor)
        cursor += padded

    stream_headers = bytearray()
    for (name, payload), offset in zip(streams, payload_offsets):
        stream_headers += u32(offset) + u32(len(payload))
        encoded = name.encode() + b"\0"
        stream_headers += encoded
        stream_headers += b"\0" * ((-len(encoded)) % 4)
    root += stream_headers
    # Pad the root to the computed header size, then append the payloads.
    if len(root) < header_size:
        root += b"\0" * (header_size - len(root))
    for (name, payload), offset in zip(streams, payload_offsets):
        while len(root) < offset:
            root += b"\0"
        root += payload
        root += b"\0" * ((-len(payload)) % 4)

    return _wrap_in_pe(bytes(root))


def _wrap_in_pe(metadata: bytes) -> bytes:
    """Wrap the metadata blob in a minimal PE32 file with a COM descriptor."""
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200

    text = bytearray(0x200)           # a tiny .text with a ret
    text[0] = 0xC3

    # Layout: .text at RVA 0x1000, .mdat at RVA 0x2000 (metadata + CLI header)
    cli_header_offset_in_mdat = 0
    cli_header_size = 0x48
    metadata_offset_in_mdat = cli_header_size
    mdat = bytearray(cli_header_size) + bytearray(metadata)
    mdat += b"\0" * ((-len(mdat)) % file_alignment)

    text_raw = 0x200
    mdat_raw = text_raw + len(text)
    text_rva = 0x1000
    mdat_rva = 0x2000
    metadata_rva = mdat_rva + metadata_offset_in_mdat

    # CLI header (IMAGE_COR20_HEADER)
    cli = bytearray()
    cli += struct.pack("<I", cli_header_size)         # cb
    cli += struct.pack("<HH", 2, 5)                   # MajorRuntimeVersion 2.5
    cli += struct.pack("<II", metadata_rva, len(metadata))
    cli += struct.pack("<I", 0x00000001)              # flags: ILONLY
    cli += struct.pack("<I", 0x06000002)              # entry point: MethodDef rid 2
    cli += struct.pack("<II", 0, 0)                   # Resources
    cli += struct.pack("<II", 0, 0)                   # StrongNameSignature
    cli += struct.pack("<II", 0, 0)                   # CodeManagerTable
    cli += struct.pack("<II", 0, 0)                   # VTableFixups
    cli += struct.pack("<II", 0, 0)                   # ExportAddressTableJumps
    cli += struct.pack("<II", 0, 0)                   # ManagedNativeHeader
    assert len(cli) == cli_header_size
    mdat[0:cli_header_size] = cli

    size_of_image = mdat_rva + (len(mdat) + section_alignment - 1) // section_alignment \
        * section_alignment

    dos = bytearray(headers_size)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)           # e_lfanew

    coff = bytearray()
    coff += b"PE\0\0"
    coff += struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)
    pe_header_size = len(coff)

    opt = bytearray()
    opt += struct.pack("<H", 0x020B)                  # PE32+
    opt += struct.pack("<BB", 14, 0)                  # linker version
    opt += struct.pack("<III", len(text), len(mdat), 0)
    opt += struct.pack("<I", 0x1000)                  # entry point RVA
    opt += struct.pack("<I", text_rva)                # base of code
    opt += struct.pack("<Q", 0x140000000)             # image base
    opt += struct.pack("<II", section_alignment, file_alignment)
    opt += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
    opt += struct.pack("<II", size_of_image, headers_size)
    opt += struct.pack("<I", 0)                       # checksum
    opt += struct.pack("<HH", 2, 0x8160)              # subsystem, dll characteristics
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)                  # NumberOfRvaAndSizes = 16
    dirs = bytearray(16 * 8)
    # index 14 = COM descriptor
    struct.pack_into("<II", dirs, 14 * 8, mdat_rva, cli_header_size)
    opt += dirs
    assert len(opt) == 0xF0, len(opt)

    sections = bytearray()
    sections += struct.pack("<8sIIIIIIHHI", b".text", len(text), text_rva,
                            len(text), text_raw, 0, 0, 0, 0, 0x60000020)
    sections += struct.pack("<8sIIIIIIHHI", b".mdat", len(mdat), mdat_rva,
                            len(mdat), mdat_raw, 0, 0, 0, 0, 0x40000040)

    image = bytearray(headers_size)
    image[0:len(dos)] = dos
    cursor = 0x80
    image[cursor:cursor + pe_header_size] = coff
    cursor += pe_header_size
    image[cursor:cursor + len(opt)] = opt
    cursor += len(opt)
    image[cursor:cursor + len(sections)] = sections
    if len(image) < text_raw:
        image += b"\0" * (text_raw - len(image))
    image += text
    image += mdat
    return bytes(image)


EXPECTED = {
    "assembly_name": ASSEMBLY_NAME,
    "assembly_version": ".".join(str(v) for v in ASSEMBLY_VERSION),
    "assembly_culture": ASSEMBLY_CULTURE,
    "module_name": MODULE_NAME,
    "type_names": TYPE_NAMES,
    "type_namespaces": TYPE_NAMESPACES,
    "method_names": METHOD_NAMES,
    "references": REF_NAMES,
    "pinvoke_dll": PINVOKE_DLL,
    "pinvoke_import": PINVOKE_IMPORT,
    "runtime_version": "2.5",
    "entry_point_token": "0x06000002",
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    target = out / "managed_fixture.dll"
    target.write_bytes(build())
    print(f"wrote {target} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
