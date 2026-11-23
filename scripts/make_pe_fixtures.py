#!/usr/bin/env python3
"""Build PE fixtures that carry a load-config directory and an Authenticode
certificate table.

WHY this is a separate builder: mingw will not emit a load config for a trivial
program, and no tool on this box produces a signed PE. Without a fixture the two
new parsers in xtforge/core/re/pe.py could only ever be exercised against
binaries that lack the directories, so every assertion would be about an empty
result. Hand-crafting the directories means the expected values are known exactly
AND the result can be checked against llvm-readobj, which parses the same bytes
from an independent implementation.

The fixture is produced by:
  1. compiling a normal mingw PE (real, loadable structure),
  2. appending a new section holding the load-config struct and a
     WIN_CERTIFICATE,
  3. pointing data directories 10 (LoadConfig) and 4 (Certificate) at it.

Directory 4 is a file offset by spec, not an RVA, and the builder sets it as one.

Usage: python3 scripts/make_pe_fixtures.py <output-dir>
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

# Load-config fields this fixture sets, chosen to exercise every mitigation decode
# path rather than to look realistic.
SECURITY_COOKIE = 0x00007FF6_1234_5678
SE_HANDLER_TABLE = 0x00000001_4000_1000
SE_HANDLER_COUNT = 3
GUARD_CF_CHECK_FUNCTION = 0x00000001_4000_1100
GUARD_CF_DISPATCH_FUNCTION = 0x00000001_4000_1200
GUARD_CF_FUNCTION_TABLE = 0x00000001_4000_1300
GUARD_CF_FUNCTION_COUNT = 7
# 0x100 = CFG instrumented, 0x40000 = XFG, 0x80000 = cast guard.
GUARD_FLAGS = 0x100 | 0x40000 | 0x80000
GLOBAL_FLAGS_SET = 0x20  # high-entropy VA
LOAD_CONFIG_SIZE = 0x98

WIN_CERT_REVISION = 0x0200
WIN_CERT_TYPE_PKCS = 0x0002


def build_load_config(base_rva: int) -> bytes:
    """Assemble a 0x98-byte load-config struct whose fields are the constants above."""
    buf = bytearray(LOAD_CONFIG_SIZE)
    field = lambda rel, fmt, value: struct.pack_into(fmt, buf, rel, value)  # noqa: E731
    field(0x00, "<I", LOAD_CONFIG_SIZE)         # Size
    field(0x04, "<I", 0x5F5E1000)               # TimeDateStamp
    field(0x08, "<H", 1)                        # MajorVersion
    field(0x0A, "<H", 0)                        # MinorVersion
    field(0x0C, "<I", 0)                        # GlobalFlagsClear
    field(0x10, "<I", GLOBAL_FLAGS_SET)         # GlobalFlagsSet
    field(0x14, "<I", 0)                        # CriticalSectionDefaultTimeout
    field(0x18, "<Q", 0)                        # DeCommitFreeBlockThreshold
    field(0x20, "<Q", 0)                        # DeCommitTotalFreeThreshold
    field(0x28, "<Q", 0)                        # LockPrefixTable
    field(0x30, "<Q", 0)                        # MaximumAllocationSize
    field(0x38, "<Q", 0)                        # VirtualMemoryThreshold
    field(0x40, "<Q", 0)                        # ProcessAffinityMask
    field(0x48, "<I", 0)                        # ProcessHeapFlags
    field(0x4C, "<H", 0)                        # CSDVersion
    field(0x4E, "<H", 0)                        # DependentLoadFlags
    field(0x50, "<Q", 0)                        # EditList
    field(0x58, "<Q", SECURITY_COOKIE)          # SecurityCookie
    field(0x60, "<Q", SE_HANDLER_TABLE)         # SEHandlerTable
    field(0x68, "<Q", SE_HANDLER_COUNT)         # SEHandlerCount
    field(0x70, "<Q", GUARD_CF_CHECK_FUNCTION)  # GuardCFCheckFunctionPointer
    field(0x78, "<Q", GUARD_CF_DISPATCH_FUNCTION)
    field(0x80, "<Q", GUARD_CF_FUNCTION_TABLE)
    field(0x88, "<Q", GUARD_CF_FUNCTION_COUNT)
    field(0x90, "<I", GUARD_FLAGS)              # GuardFlags
    field(0x94, "<H", 0)                        # CodeIntegrity flags
    return bytes(buf)


def build_certificate_blob() -> bytes:
    """A WIN_CERTIFICATE whose payload is a syntactically valid DER SEQUENCE.

    The payload is a minimal but well-formed PKCS#7 ContentInfo prefix so the
    parser's DER detection is exercised for real rather than on random bytes.
    """
    der = bytes.fromhex(
        "3082" "0100"                      # SEQUENCE, length 0x100
        "0609" "2a864886f70d010702"        # OID 1.2.840.113549.1.7.2 (signedData)
        "a082" "00f1"                      # [0] EXPLICIT, length 0xf1
    )
    der += b"\x00" * (0x100 - len(der))
    body = der
    total = 8 + len(body)
    header = struct.pack("<IHH", total, WIN_CERT_REVISION, WIN_CERT_TYPE_PKCS)
    blob = header + body
    # WIN_CERTIFICATE entries are 8-byte aligned within the file.
    pad = (-len(blob)) % 8
    return blob + b"\x00" * pad


def add_section(pe_path: Path, name: bytes, payload: bytes) -> dict[str, int]:
    """Append a section to a PE and return its RVA/file offset/raw size."""
    data = bytearray(pe_path.read_bytes())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections, = struct.unpack_from("<H", data, coff + 2)
    size_opt, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from("<H", data, opt)
    if magic != 0x020B:
        raise SystemExit(f"fixture must be PE32+ (magic 0x{magic:04x})")
    section_alignment, = struct.unpack_from("<I", data, opt + 32)
    file_alignment, = struct.unpack_from("<I", data, opt + 36)
    size_of_image, = struct.unpack_from("<I", data, opt + 56)
    num_dirs, = struct.unpack_from("<I", data, opt + 108)
    dirs = opt + 112

    # Append after the last section's raw data, respecting file alignment.
    section_table = opt + size_opt
    last_raw_end = 0
    highest_va = 0
    for i in range(num_sections):
        hdr = section_table + i * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, hdr + 8)
        last_raw_end = max(last_raw_end, raw_ptr + raw_size)
        highest_va = max(highest_va, vaddr + max(vsize, raw_size))

    raw_ptr = (last_raw_end + file_alignment - 1) // file_alignment * file_alignment
    new_rva = (highest_va + section_alignment - 1) // section_alignment * section_alignment
    raw_size = (len(payload) + file_alignment - 1) // file_alignment * file_alignment

    if len(data) < raw_ptr:
        data.extend(b"\x00" * (raw_ptr - len(data)))
    data.extend(payload)
    data.extend(b"\x00" * (raw_ptr + raw_size - len(data)))

    # The new header goes immediately after the last existing one, extending the
    # table by exactly 40 bytes. Writing it conditionally (as the first version
    # did) silently overwrote nothing when the slot happened to be zero-filled,
    # which corrupted the section count instead of adding a section.
    header = struct.pack("<8sIIIIIIHHI", name[:8], len(payload), new_rva, raw_size,
                         raw_ptr, 0, 0, 0, 0, 0x40000040)
    insert_at = section_table + num_sections * 40
    data[insert_at:insert_at + 40] = header

    struct.pack_into("<H", data, coff + 2, num_sections + 1)
    struct.pack_into("<I", data, opt + 56,
                     (new_rva + raw_size + section_alignment - 1)
                     // section_alignment * section_alignment)
    struct.pack_into("<I", data, opt + 60, raw_ptr + raw_size)  # SizeOfInitializedData
    pe_path.write_bytes(bytes(data))
    return {"rva": new_rva, "offset": raw_ptr, "size": raw_size,
            "dirs_offset": dirs, "num_dirs": num_dirs, "opt": opt}


def set_directory(pe_path: Path, dirs_offset: int, index: int,
                  rva: int, size: int) -> None:
    data = bytearray(pe_path.read_bytes())
    struct.pack_into("<II", data, dirs_offset + index * 8, rva, size)
    pe_path.write_bytes(bytes(data))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("clang")
    if not compiler:
        print("no PE compiler available", file=sys.stderr)
        return 1

    src = out_dir / "fixture.c"
    src.write_text("int main(void){return 0;}\n"
                   "__declspec(dllexport) int exported(void){return 42;}\n")
    pe = out_dir / "loadconfig_signed.exe"
    built = subprocess.run([compiler, str(src), "-o", str(pe)],
                           capture_output=True, text=True)
    if built.returncode != 0:
        print(built.stderr, file=sys.stderr)
        return 1

    # The load config must be at a known RVA before it can be written, so reserve
    # the section first with placeholder bytes, then fill it once the RVA is known.
    info = add_section(pe, b".xtcfg", b"\x00" * 0x400)
    config_rva = info["rva"]

    data = bytearray(pe.read_bytes())
    config = build_load_config(config_rva)
    data[info["offset"]:info["offset"] + len(config)] = config

    # Certificate goes after the load config in the same section, 8-byte aligned.
    cert_off_in_section = (len(config) + 7) & ~7
    cert = build_certificate_blob()
    data[info["offset"] + cert_off_in_section:
         info["offset"] + cert_off_in_section + len(cert)] = cert
    pe.write_bytes(bytes(data))

    set_directory(pe, info["dirs_offset"], 10, config_rva, LOAD_CONFIG_SIZE)
    # Directory 4 stores a FILE OFFSET, not an RVA. Setting it as an RVA is the
    # classic mistake and is exactly what the parser is written to avoid.
    cert_file_offset = info["offset"] + cert_off_in_section
    set_directory(pe, info["dirs_offset"], 4, cert_file_offset, len(cert))

    print(f"wrote {pe}")
    print(f"  load config  rva=0x{config_rva:x} size=0x{LOAD_CONFIG_SIZE:x}")
    print(f"  certificate  file_offset=0x{cert_file_offset:x} size=0x{len(cert):x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
