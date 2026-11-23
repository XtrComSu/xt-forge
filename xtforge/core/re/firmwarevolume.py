"""UEFI firmware volume and FFS file extraction.

WHY: the existing `re uefi` reads NVRAM *variables*, which is what you examine after a
system is running. This reads the firmware *image* itself — the container that holds the
DXE drivers, PEI modules, option ROMs and setup application before anything boots. That
is the artifact in a firmware dump, a BIOS update file, or a dumped SPI flash.

The hierarchy, confirmed against EDK2's own OVMF builds:

    Firmware Volume   "zero vector" (16 bytes) + FS GUID (16) + length (8) + "_FVH"
      |               attributes, header length, checksum, revision
      |- FFS file     name GUID (16) + integrity checks + type + attributes + size
      |  |            size occupies 3 bytes; the header is 24 bytes (or 32 with a
      |  |            extended size field when the large-file attribute is set)
      |  |- section   size (3 bytes) + type (1 byte), then type-specific body
      |     |- PE32   a UEFI executable image
      |     |- UI     a UTF-16 user-facing name — the friendly label for the driver
      |- free space   erased (0xFF) or zero-filled to the end of the volume

Five things are easy to get wrong and all of them fail quietly:

  * The volume length is a **u64** at offset 32, and the file-system GUID at 16 is stored
    with the first three fields byte-swapped relative to the text form.
  * An FFS file's size is **three bytes**, not four, at offset 20.
  * The `LARGE_FILE` attribute switches the header to 32 bytes with a u64 size at 24.
    Reading the 24-byte header anyway yields a size of 0 and silently stops the walk.
  * Section sizes are also **three bytes**, and a section of type 0x19 (RAW) or an
    encapsulation section wraps further sections rather than holding a leaf payload.
  * Free space is 0xFF or 0x00 filled. Parsing it as a file yields a GUID of all-ones
    and a nonsense size; both must be detected and reported as free space.
"""
from __future__ import annotations

import lzma
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 20000
MAX_DEPTH = 4

FV_SIGNATURE = b"_FVH"
FFS_HEADER_SIZE = 24
FFS_HEADER2_SIZE = 32  # with LARGE_FILE
_PAD = b"\xff"

# FFS file types (PI spec).
FFS_TYPES = {
    0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE",
    0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DRIVER", 0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION", 0x0A: "MM", 0x0B: "FIRMWARE_VOLUME_IMAGE",
    0x0C: "COMBINED_MM_DXE", 0x0D: "MM_CORE", 0x0E: "MM_STANDALONE",
    0x0F: "MM_CORE_STANDALONE", 0xF0: "PAD",
}

# Section types.
SECTION_TYPES = {
    0x01: "COMPRESSION", 0x02: "GUID_DEFINED", 0x03: "DISPOSABLE",
    0x10: "PE32", 0x11: "PIC", 0x12: "TE", 0x13: "DXE_DEPEX", 0x14: "VERSION",
    0x15: "USER_INTERFACE", 0x16: "COMPATIBILITY16", 0x17: "FIRMWARE_VOLUME_IMAGE",
    0x18: "FREEFORM_SUBTYPE_GUID", 0x19: "RAW", 0x1B: "PEI_DEPEX", 0x1C: "MM_DEPEX",
}

# Attributes.
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_CHECKSUM = 0x40

# File-system GUIDs, in the on-disk (mixed-endian) byte order.
_FS_GUIDS = {
    "78e58c8c3d8a1c4f9935896185c32dd3":
        "EFI_FIRMWARE_FILE_SYSTEM3_GUID (FFS3, large files)",
    "d9458ce55a4c4e4b8b7b02d5e6f7a1b9":
        "EFI_FIRMWARE_FILE_SYSTEM2_GUID (FFS2)",
    "7aa35e7cf9d84d4b8b7b8b7b8b7b8b7b":
        "EFI_FIRMWARE_FILE_SYSTEM_GUID (FFS1)",
}


MAX_DECOMPRESSED = 256 * 1024 * 1024


class FirmwareError(Exception):
    """Raised when the image is not a firmware volume this reader understands."""


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _guid(raw: bytes) -> str:
    """Format a 16-byte EFI GUID in its canonical text form.

    The first three fields are little-endian on disk; the last two are not. Printing the
    bytes straight through gives an identifier nobody can match against a spec.
    """
    if len(raw) < 16:
        return ""
    data1, data2, data3 = struct.unpack_from("<IHH", raw, 0)
    return (f"{data1:08x}-{data2:04x}-{data3:04x}-"
            f"{raw[8:10].hex()}-{raw[10:16].hex()}")


def _is_pad(blob: bytes) -> bool:
    """Free space is 0xFF or 0x00 filled, not a file."""
    return all(byte == 0xFF for byte in blob) or all(byte == 0x00 for byte in blob)


def _utf16(raw: bytes) -> str:
    text = raw.decode("utf-16-le", "replace")
    return text.split("\x00")[0].replace("\ufeff", "").strip()


def _try_lzma(blob: bytes) -> tuple[bytes | None, str]:
    """Decompress an EFI LZMA section body.

    EDK2 writes the raw `.lzma` container: 5 bytes of properties, an 8-byte
    uncompressed size, then the stream — which is exactly what `lzma.decompress` with the
    default (auto-detect) format accepts. It is NOT the `.xz` wrapper, so an xz-only
    reader silently fails on every real firmware image.

    A GUID_DEFINED section may also prefix the payload with its own header, so if the
    direct attempt fails, retry past the plausible header lengths rather than giving up.
    """
    for skip in (0, 5, 13, 20, 24):
        candidate = blob[skip:]
        if not candidate:
            continue
        try:
            out = lzma.decompress(candidate)
        except (lzma.LZMAError, EOFError, ValueError):
            continue
        if 0 < len(out) <= MAX_DECOMPRESSED:
            return out, (f"lzma (payload at +{skip})" if skip else "lzma")
    return None, ""


def _sections(raw: bytes, *, depth: int = 0, limit: int = 200) -> list[dict[str, Any]]:
    """Walk the section stream inside an FFS file (or an encapsulation section)."""
    out: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 4 <= len(raw) and len(out) < limit:
        header = raw[cursor:cursor + 4]
        if _is_pad(header) or header == b"\x00\x00\x00\x00":
            break
        # Section size is 3 bytes; 0xFFFFFF means the real size follows as a u32.
        size = int.from_bytes(header[0:3], "little")
        kind = header[3]
        extended = False
        body_start = cursor + 4
        if size == 0xFFFFFF:
            if cursor + 8 > len(raw):
                break
            size = struct.unpack_from("<I", raw, cursor + 4)[0]
            body_start = cursor + 8
            extended = True
        if size < 4 or cursor + size > len(raw):
            # A size that overruns the file means the walk has desynchronised; stop
            # rather than emit garbage sections from arbitrary offsets.
            break
        body = raw[body_start:cursor + size]
        name = SECTION_TYPES.get(kind, f"UNKNOWN_0x{kind:02x}")
        record: dict[str, Any] = {
            "type": name,
            "type_id": f"0x{kind:02x}",
            "size": size,
            "offset": cursor,
        }
        if extended:
            record["extended_size"] = True

        if name == "USER_INTERFACE":
            record["ui_name"] = _utf16(body)
        elif name in ("PE32", "TE", "PIC"):
            record["has_image"] = True
            if len(body) >= 2 and body[:2] == b"MZ":
                record["format"] = "PE32"
                if len(body) >= 0x40:
                    (pe_offset,) = struct.unpack_from("<I", body, 0x3C)
                    if pe_offset + 4 <= len(body) and body[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                        record["pe_signature"] = True
                        if pe_offset + 6 <= len(body):
                            (machine,) = struct.unpack_from("<H", body, pe_offset + 4)
                            record["machine"] = {
                                0x8664: "x86-64", 0x014C: "i386",
                                0xAA64: "aarch64", 0x01C2: "thumb",
                            }.get(machine, f"0x{machine:04x}")
        elif name in ("COMPRESSION", "GUID_DEFINED", "FIRMWARE_VOLUME_IMAGE"):
            # Encapsulation sections wrap more sections. They are frequently LZMA
            # compressed, and a reader that only walks the raw bytes reports a nested
            # volume of zero files — which reads as "this firmware has no drivers".
            #
            # For GUID_DEFINED the DataOffset field is measured from the START OF THE
            # SECTION, not from the end of the 4-byte section header. Slicing the body
            # at DataOffset therefore cuts 4 bytes late and feeds the decompressor a
            # corrupt stream — which fails silently if the error is swallowed.
            payload = body
            if name == "GUID_DEFINED" and len(body) >= 20:
                (data_offset,) = struct.unpack_from("<H", body, 16)
                attributes = struct.unpack_from("<H", body, 18)[0]
                record["data_offset"] = data_offset
                record["guid_attributes"] = f"0x{attributes:04x}"
                if attributes & 0x01:
                    record["compression_flagged"] = True
                # Payload starts immediately after the 20-byte GUID_DEFINED header
                # (GUID 16 + DataOffset 2 + Attributes 2). `body` here already excludes
                # the 4-byte section header, so that is body + 20 — the section-relative
                # offset 24 minus those 4 bytes. Getting this off by four feeds the
                # decompressor a stream starting mid-header, which fails silently because
                # the error is caught per-offset.
                candidates = [20, data_offset - 4, data_offset]
                payload = next(
                    (body[c:] for c in candidates if 0 <= c < len(body)), body)
            elif name == "COMPRESSION" and len(body) > 4:
                algorithm = body[4]
                record["algorithm"] = {0: "none", 1: "EFI standard",
                                       2: "LZMA custom"}.get(algorithm,
                                                            f"0x{algorithm:02x}")
                payload = body[5:]
            decoded, method = _try_lzma(payload)
            if decoded is not None:
                record["compression"] = method
                record["decompressed_size"] = len(decoded)
                payload = decoded
            # The decompressed blob is NOT a volume at offset 0: EDK2 wraps it in a
            # further set of sections (here the volume starts at +128), so the volume
            # must be located rather than assumed to begin the stream.
            volume_base = _find_volume_base(payload)
            nested: list[dict[str, Any]] = []
            if volume_base is not None:
                try:
                    record["volume"] = _volume_header(payload[volume_base:])
                except FirmwareError:
                    pass
                # Hold the whole blob, not just the first volume: a decompressed stream
                # routinely carries several volumes back to back (OVMF packs an 851 KB
                # PEI volume followed by a 15 MB DXE volume into one GUID_DEFINED
                # section). Slicing at the first volume base silently loses every driver
                # in the second, which is where the DXE phase actually lives.
                record["_payload"] = payload
                nested = _sections(payload[:volume_base], depth=depth + 1,
                                   limit=limit)
            elif depth < MAX_DEPTH and payload:
                nested = _sections(payload, depth=depth + 1, limit=limit)
            if nested:
                record["sections"] = nested
        out.append(record)
        cursor += size
    return out


def _ffs_file(raw: bytes, cursor: int, end: int) -> tuple[dict[str, Any] | None, int]:
    """Parse one FFS file at `cursor`. Returns (record, next_cursor)."""
    if cursor + FFS_HEADER_SIZE > end:
        return None, end
    head = raw[cursor:cursor + FFS_HEADER_SIZE]
    if _is_pad(head):
        return None, end

    name = _guid(head[0:16])
    integrity = head[16:18].hex()
    kind = head[18]
    attributes = head[19]
    size = int.from_bytes(head[20:23], "little")
    state = head[23]

    header_size = FFS_HEADER_SIZE
    if attributes & FFS_ATTRIB_LARGE_FILE:
        # LARGE_FILE moves the size to a u64 at offset 24 and the header to 32 bytes.
        # Reading the 24-byte header anyway gives size 0 and stops the walk dead.
        if cursor + FFS_HEADER2_SIZE > end:
            return None, end
        size = struct.unpack_from("<Q", raw, cursor + 24)[0]
        header_size = FFS_HEADER2_SIZE

    if size < header_size or cursor + size > end:
        return None, end

    body = raw[cursor + header_size:cursor + size]
    record: dict[str, Any] = {
        "name": name,
        "type": FFS_TYPES.get(kind, f"UNKNOWN_0x{kind:02x}"),
        "type_id": f"0x{kind:02x}",
        "size": size,
        "offset": cursor,
        "attributes": f"0x{attributes:02x}",
        "state": f"0x{state:02x}",
        "integrity": integrity,
    }
    if attributes & FFS_ATTRIB_LARGE_FILE:
        record["large_file"] = True
    sections = _sections(body)
    if sections:
        record["sections"] = sections
        # A FIRMWARE_VOLUME_IMAGE section usually wraps a whole volume, often LZMA
        # compressed. Its FFS files ARE the drivers — not reporting them means a
        # firmware whose entire DXE phase is inside one encapsulated section looks
        # empty, which is precisely the OVMF layout.
        nested_files, nested_volumes = _nested_volume_files(sections)
        record.pop("_payload", None)
        if nested_files:
            record["nested_files"] = nested_files
            record["nested_file_count"] = len(nested_files)
        if nested_volumes:
            record["nested_volumes"] = nested_volumes
        for section in sections:
            if section.get("ui_name"):
                record["ui_name"] = section["ui_name"]
                break
        # Keep the first freeform "raw name" the sections expose, which is often the
        # only human-readable identifier a driver has.
        for section in sections:
            if section.get("machine"):
                record["machine"] = section["machine"]
                break
    return record, cursor + size


def _volume_header(raw: bytes) -> dict[str, Any]:
    if len(raw) < 56:
        raise FirmwareError(f"volume header truncated ({len(raw)} bytes, need 56)")
    if raw[40:44] != FV_SIGNATURE:
        raise FirmwareError(
            f"no _FVH signature at offset 40 (found {raw[40:44]!r})")
    fs_guid_raw = raw[16:32]
    fs_guid = _guid(fs_guid_raw)
    (length,) = struct.unpack_from("<Q", raw, 32)
    (attributes, header_length, checksum, ext_offset, _reserved,
     revision) = struct.unpack_from("<IHHHBB", raw, 44)
    return {
        "file_system": _FS_GUIDS.get(fs_guid_raw.hex(), fs_guid),
        "fs_guid": fs_guid,
        "length": length,
        "attributes": f"0x{attributes:08x}",
        "header_length": header_length,
        "checksum": f"0x{checksum:04x}",
        "ext_header_offset": ext_offset,
        "revision": revision,
        "erase_polarity": "0xFF" if attributes & 0x800 else "0x00",
    }


def _nested_volume_files(sections: list[dict[str, Any]],
                         *, depth: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Walk firmware volumes buried inside encapsulation sections.

    Returns (files, volume_count). Recursion is bounded because encapsulation sections
    can nest, and a self-referential or malformed image must not loop.
    """
    files: list[dict[str, Any]] = []
    volumes = 0
    if depth > MAX_DEPTH:
        return files, volumes
    for section in sections:
        payload = section.get("_payload")
        if not payload:
            files_inner, volumes_inner = _nested_volume_files(
                section.get("sections") or [], depth=depth + 1)
            files.extend(files_inner)
            volumes += volumes_inner
            continue
        for base, length in _volume_bases(payload):
            volumes += 1
            inner, _frees = _walk_volume(
                payload, base, min(base + length, len(payload)))
            for record in inner:
                # Label which nested volume a file came from. Without this a caller
                # cannot tell a PEI module from a DXE driver, or notice that only one of
                # several volumes was actually read.
                record["nested_volume_index"] = volumes
                record["nested_volume_offset"] = base
                nested, nested_volumes = _nested_volume_files(
                    record.get("sections") or [], depth=depth + 1)
                if nested:
                    record["nested_files"] = nested
                    record["nested_file_count"] = len(nested)
                files.append(record)
                volumes += nested_volumes
    return files, volumes


def _find_volume_base(blob: bytes) -> int | None:
    """Offset of the first firmware volume inside a decompressed blob, or None.

    The blob is not a volume header followed by files — EDK2 emits another layer of
    sections first, so the volume can begin hundreds of bytes in. Assuming offset 0
    reports a nested file of type 0xF5 with a nonsense size and no drivers at all.
    """
    cursor = blob.find(FV_SIGNATURE)
    while cursor != -1:
        base = cursor - 40
        if base >= 0 and base + 56 <= len(blob):
            (length,) = struct.unpack_from("<Q", blob, base + 32)
            (hdr_len,) = struct.unpack_from("<H", blob, base + 48)
            if 56 <= hdr_len <= 4096 and 512 <= length <= len(blob) - base:
                return base
        cursor = blob.find(FV_SIGNATURE, cursor + 1)
    return None


def _volume_bases(raw: bytes) -> list[tuple[int, int]]:
    """Find every firmware volume in an image, in order.

    A volume is identified by `_FVH` at offset 40 from its base plus a plausible u64
    length at offset 32. The length check matters: `_FVH` also occurs inside compressed
    payloads and inside file data, and without it those false hits are treated as
    volumes with absurd lengths.
    """
    found: list[tuple[int, int]] = []
    seen: set[int] = set()
    cursor = raw.find(FV_SIGNATURE)
    while cursor != -1 and len(found) < 64:
        base = cursor - 40
        if base >= 0 and base not in seen:
            (length,) = struct.unpack_from("<Q", raw, base + 32)
            (hdr_len,) = struct.unpack_from("<H", raw, base + 48)
            if 56 <= hdr_len <= 4096 and 512 <= length <= len(raw) - base:
                seen.add(base)
                found.append((base, length))
        cursor = raw.find(FV_SIGNATURE, cursor + 1)
    found.sort()
    return found


def _walk_volume(raw: bytes, base: int, end: int,
                 *, limit: int = MAX_FILES) -> tuple[list[dict[str, Any]], int]:
    """Walk the FFS files in one volume, returning (files, free_region_count)."""
    (header_length,) = struct.unpack_from("<H", raw, base + 48)
    cursor = base + (header_length or 72)
    cursor = (cursor + 7) & ~7
    files: list[dict[str, Any]] = []
    frees = 0
    while cursor < end and len(files) < limit:
        record, next_cursor = _ffs_file(raw, cursor, end)
        if record is None:
            frees += 1
            # Free space does not necessarily end the volume: EDK2 allocates some files
            # at erase-block boundaries, leaving 0xFF gaps mid-volume. Look ahead for
            # the next header that passes a full validity check, and stop only if there
            # is none — never resynchronise byte by byte, which invents files.
            resume = _next_valid_file(raw, (cursor + 8) & ~7, end)
            if resume is None:
                break
            cursor = resume
            continue
        files.append(record)
        cursor = (next_cursor + 7) & ~7
    return files, frees


def _next_valid_file(raw: bytes, start: int, end: int) -> int | None:
    """Find the next offset holding a structurally valid FFS header, or None.

    Validity is a strict conjunction, because each condition on its own matches noise:
    a known type byte, attributes with no undefined bits, a size that fits and is
    8-byte aligned, a state byte whose HEADER_VALID bit is set, and a header that is
    not all-0xFF.
    """
    cursor = start
    while cursor + FFS_HEADER_SIZE <= end:
        head = raw[cursor:cursor + FFS_HEADER_SIZE]
        if not _is_pad(head):
            kind = head[18]
            attributes = head[19]
            size = int.from_bytes(head[20:23], "little")
            state = head[23]
            if (kind in FFS_TYPES
                    and not attributes & ~0x7F
                    and 24 <= size <= end - cursor
                    and size % 8 == 0
                    and state & 0x02):
                return cursor
        cursor += 8
    return None


def _strip_private(records: list[dict[str, Any]],
                   *, depth: int = 0) -> None:
    """Remove in-memory-only keys before anything is serialised.

    `_payload` holds the decompressed volume bytes so the nested walk can use them. They
    are not JSON serialisable, so leaving them in makes every CLI and MCP call fail on a
    result that otherwise looks complete — the error surfaces far from this module.
    """
    if depth > MAX_DEPTH + 2:
        return
    for record in records:
        for key in [k for k in record if k.startswith("_")]:
            record.pop(key, None)
        nested = record.get("nested_files")
        if isinstance(nested, list):
            _strip_private(nested, depth=depth + 1)
        sections = record.get("sections")
        if isinstance(sections, list):
            _strip_private(sections, depth=depth + 1)


def inspect_firmware_volume(path: str | Path, *,
                            limit: int = 500) -> dict[str, Any]:
    """Read a UEFI firmware volume: FFS files, their sections, and named drivers."""
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(raw) < 56:
        return {"ok": False, "path": str(path),
                "error": f"file too small for a firmware volume ({len(raw)} bytes)"}

    try:
        header = _volume_header(raw)
    except FirmwareError as exc:
        return {"ok": False, "path": str(path), "error": str(exc),
                "hint": "expected an EDK2/OVMF firmware volume; a raw dump with a "
                        "chipset descriptor prefix needs the volume offset first"}

    # A flash image usually stacks several volumes back to back (a 4 MB OVMF build
    # holds three: the SEC/PEI volume, the main DXE volume and a 208 KB tail). Walking
    # only the first reports one file and looks like an empty firmware.
    volumes = _volume_bases(raw)
    files: list[dict[str, Any]] = []
    free_regions = 0
    walked = 0
    for base, length in volumes:
        if len(files) >= MAX_FILES:
            break
        walked += 1
        volume_files, frees = _walk_volume(
            raw, base, min(base + length, len(raw)), limit=MAX_FILES - len(files))
        for record in volume_files:
            record["volume"] = walked
        files.extend(volume_files)
        free_regions += frees

    if header["length"] > len(raw):
        header["truncated"] = True

    # Files inside an encapsulated (usually LZMA) volume are the drivers. Counting only
    # the top level understates a firmware whose whole DXE phase is compressed into one
    # section — OVMF keeps 156 FFS files inside a single 1.7 MB GUID_DEFINED section.
    all_files = list(files)
    for record in files:
        all_files.extend(record.get("nested_files") or [])

    _DRIVER_TYPES = ("DRIVER", "DXE_CORE", "PEIM", "PEI_CORE", "APPLICATION",
                     "COMBINED_PEIM_DRIVER", "MM", "MM_CORE", "MM_STANDALONE",
                     "SECURITY_CORE", "COMBINED_MM_DXE", "FIRMWARE_VOLUME_IMAGE")
    named = [f for f in all_files if f.get("ui_name")]
    drivers = [f for f in all_files if f.get("type") in _DRIVER_TYPES]
    machines: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for record in all_files:
        machine = record.get("machine")
        if machine:
            machines[machine] = machines.get(machine, 0) + 1
        kind = record.get("type")
        if kind:
            type_counts[kind] = type_counts.get(kind, 0) + 1

    _strip_private(all_files)

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "uefi-firmware-volume",
        "file_size": len(raw),
        "volume": header,
        "file_count": len(all_files),
        "top_level_count": len(files),
        "volume_count": walked,
        "type_counts": dict(sorted(type_counts.items(),
                                   key=lambda kv: -kv[1])),
        "named_count": len(named),
        "driver_count": len(drivers),
        "free_regions": free_regions,
        "machines": machines,
        "files": files[:limit],
        "named_files": [{"name": f["ui_name"], "guid": f["name"],
                         "type": f["type"], "size": f["size"]}
                        for f in named[:limit]],
        "truncated": bool(header.get("truncated")),
    }
    if not files:
        result["warning"] = ("the volume header parsed but no FFS files were found; "
                            "the image may be compressed or this is not an FFS volume")
    return result


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_firmware_volume(path, **kwargs)
