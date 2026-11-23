"""Read a UEFI firmware volume from a raw image.

The engine detects firmware volumes but only answers "does this parse": it lists
FFS files without saying anything about the volume that holds them, and it cannot
explain why a file has no content.  This module reads the bytes directly and
answers the volume-level questions: where the FV starts, whether its header
checksum holds, which FFS files it declares, and why a file was skipped.

Nothing is decompressed here.  In UEFI, compression lives in GUIDed sections
*inside* an FFS file, not in the FFS file type (0x0d is SMM_CORE, not a
compression marker).  Every file is therefore reported with ``compressed:
False`` and the notes state plainly that section-level compression was not
inspected and extraction is not implemented.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

FV_SIGNATURE = b"_FVH"
FV_SIGNATURE_OFFSET = 0x28
SEARCH_LIMIT = 1024 * 1024  # never scan more than the first 1 MiB
ALIGNMENT = 8
MAX_FILES = 512

FV_HEADER_MIN = 0x38  # EFI_FIRMWARE_VOLUME_HEADER through Revision
FFS_HEADER_SIZE = 24  # EFI_FFS_FILE_HEADER
FFS_TYPE_PAD = 0xF0

TYPE_NAMES = {
    0x01: "RAW",
    0x02: "FREEFORM",
    0x03: "SECURITY_CORE",
    0x04: "PEI_CORE",
    0x05: "DXE_CORE",
    0x06: "PEIM",
    0x07: "DRIVER",
    0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION",
    0x0A: "SMM",
    0x0B: "FIRMWARE_VOLUME_IMAGE",
    0x0C: "COMBINED_SMM_DXE",
    0x0D: "SMM_CORE",
    0xF0: "PAD",
    0xFF: "ALL",
}

COMPRESSION_NOTE = (
    "section-level compression not inspected; extract is not implemented"
)


def format_guid(raw: bytes) -> str:
    """Render a 16-byte UEFI GUID as canonical 8-4-4-4-12 text.

    The first three fields (u32, u16, u16) are little-endian; the trailing eight
    bytes are emitted in order.  Writing this once keeps every GUID in the
    output identical to what a hex editor / UEFI tool would print.
    """
    if len(raw) < 16:
        raise ValueError("a UEFI GUID is 16 bytes")
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    node = raw[8:16]
    return (
        f"{d1:08x}-{d2:04x}-{d3:04x}-"
        f"{node[0]:02x}{node[1]:02x}-{node[2]:02x}{node[3]:02x}"
        f"{node[4]:02x}{node[5]:02x}{node[6]:02x}{node[7]:02x}"
    )


def _checksum16(raw: bytes) -> int:
    """UEFI FV checksum: sum little-endian 16-bit words, modulo 65536.

    The header is 16-bit aligned, so "16-bit sum of the header bytes" means the
    bytes are paired into words first.  Summing raw bytes instead can never wrap
    to zero for a real (non-empty) header, which would mark every volume bad.
    """
    total = 0
    for index in range(0, len(raw) - 1, 2):
        total += raw[index] | (raw[index + 1] << 8)
    if len(raw) & 1:
        total += raw[-1]
    return total & 0xFFFF


def _find_volume(data: bytes) -> int:
    """Return the offset of the first _FVH in the search window, or -1."""
    limit = min(len(data), SEARCH_LIMIT)
    pos = 0
    while pos + FV_SIGNATURE_OFFSET + 4 <= limit:
        if data[pos + FV_SIGNATURE_OFFSET:pos + FV_SIGNATURE_OFFSET + 4] == FV_SIGNATURE:
            return pos
        pos += ALIGNMENT
    return -1


def _unknown(path: Path, data: bytes, notes: list[str], volume_offset: int = -1) -> dict[str, Any]:
    return {
        "ok": True,
        "path": str(path),
        "format": "unknown",
        "size": len(data),
        "volume_offset": volume_offset,
        "volume": None,
        "files": [],
        "truncated": False,
        "notes": notes,
    }


def _parse_files(data: bytes, volume_offset: int, fv_length: int,
                 header_length: int, notes: list[str]) -> tuple[list[dict[str, Any]], bool]:
    """Walk the FFS files, collecting a bounded list and human-readable reasons."""
    files: list[dict[str, Any]] = []
    volume_end = volume_offset + fv_length
    pos = volume_offset + header_length
    ordinal = 0
    pads = 0
    truncated = False

    while pos + FFS_HEADER_SIZE <= len(data):
        if pos >= volume_end:
            notes.append(
                f"FFS data at volume offset {pos - volume_offset} is past the "
                f"declared volume length {fv_length}"
            )
            break

        guid = format_guid(data[pos:pos + 16])
        ftype = data[pos + 18]
        state = data[pos + 23]
        size = int.from_bytes(data[pos + 20:pos + 23], "little")

        if size < FFS_HEADER_SIZE:
            notes.append(f"file {ordinal} declares an invalid size of {size} bytes")
            break
        if pos + size > volume_end:
            notes.append(
                f"file {ordinal} runs past the volume "
                f"(volume offset {pos - volume_offset}, size {size}, "
                f"volume length {fv_length})"
            )

        if ftype == FFS_TYPE_PAD:
            # Padding is part of the FV layout, not a file worth listing.
            pads += 1
            pos += size
            ordinal += 1
            continue

        files.append({
            "index": ordinal,
            "guid": guid,
            "type": ftype,
            "type_name": TYPE_NAMES.get(ftype, f"UNKNOWN_0x{ftype:02x}"),
            "size": size,
            "offset": pos,  # absolute offset in the image
            "compressed": False,
            "state": state,
        })
        ordinal += 1
        pos += size
        if len(files) >= MAX_FILES:
            truncated = True
            notes.append(f"file list bounded to {MAX_FILES} entries")
            break

    if pads:
        noun = "file" if pads == 1 else "files"
        notes.append(f"skipped {pads} PAD {noun} (type 0xf0)")
    return files, truncated


def inspect(path: str | Path) -> dict[str, Any]:
    """Inspect a UEFI firmware volume (or report that the blob is not one).

    A directory is a caller error and raises ValueError.  A non-FV blob is a
    normal answer: ``format`` is ``"unknown"`` and a note names the first 16
    bytes in hex so the caller can see what was actually examined.
    """
    resolved = Path(path)
    if resolved.is_dir():
        raise ValueError(f"{path} is a directory, not a firmware image")

    data = resolved.read_bytes()
    notes: list[str] = []
    volume_offset = _find_volume(data)
    if volume_offset < 0:
        notes.append(
            f"no _FVH signature found in the searched region; "
            f"first 16 bytes: {data[:16].hex()}"
        )
        return _unknown(resolved, data, notes)

    if volume_offset + FV_HEADER_MIN > len(data):
        notes.append("firmware volume header is truncated")
        return _unknown(resolved, data, notes, volume_offset)

    fs_guid = format_guid(data[volume_offset + 0x10:volume_offset + 0x20])
    fv_length = struct.unpack_from("<Q", data, volume_offset + 0x20)[0]
    attributes = struct.unpack_from("<I", data, volume_offset + 0x2C)[0]
    header_length = struct.unpack_from("<H", data, volume_offset + 0x30)[0]
    ext_header_offset = struct.unpack_from("<H", data, volume_offset + 0x34)[0]
    revision = data[volume_offset + 0x37]

    available = len(data) - volume_offset
    if header_length < FV_HEADER_MIN or header_length > available:
        notes.append(
            f"invalid FV header length {header_length} (available {available} bytes)"
        )
        checksum_ok = False
    else:
        checksum_ok = _checksum16(data[volume_offset:volume_offset + header_length]) == 0
    if not checksum_ok:
        notes.append("checksum mismatch")

    matches = fv_length == available
    if not matches:
        notes.append(
            f"FV length {fv_length} does not match the {available} bytes "
            f"available from volume offset {volume_offset}"
        )

    files, truncated = _parse_files(data, volume_offset, fv_length, header_length, notes)
    notes.append(COMPRESSION_NOTE)

    return {
        "ok": True,
        "path": str(resolved),
        "format": "uefi_fv",
        "size": len(data),
        "volume_offset": volume_offset,
        "volume": {
            "fs_guid": fs_guid,
            "length": fv_length,
            "header_length": header_length,
            "revision": revision,
            "attributes": attributes,
            "checksum_ok": checksum_ok,
            "ext_header_offset": ext_header_offset,
            "reported_length_matches_file": matches,
        },
        "files": files,
        "truncated": truncated,
        "notes": notes,
    }
