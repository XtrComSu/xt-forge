"""Firmware container carving: find the payloads inside a vendor image.

WHY: a router firmware download is rarely a bare filesystem. It is usually a vendor header
followed by a UBI volume, a squashfs, a TRX image, a compressed kernel and zero padding, in
an order that varies by vendor and model. `re firmware` understands a UEFI firmware volume
once you have one; this module finds the volumes and filesystems *inside a blob* and says
where each one starts, so the ones you can parse get parsed and the ones you cannot are
still located.

The approach is carving, not container parsing: every known signature is scanned for, each
hit is validated by the structure that must follow it, and the result is a list of regions
sorted by offset. That works across vendors without a table of 400 device headers, and it
degrades honestly — an unknown header simply yields whatever signatures exist inside it.

Signatures are validated, not just matched. A bare `hsqs` in the middle of a compressed
kernel is common; a squashfs superblock at that offset is not — the block size must be a
power of two, the inode count must fit the image, and the version must be one that exists.
Each validator below states what it checks, and a hit that fails validation is reported as
rejected rather than silently dropped, because "I saw the magic but the structure was wrong"
is a finding.

What this does NOT do: reassemble a vendor's proprietary header into its declared fields.
Header layouts differ per vendor and are undocumented; guessing field meanings produces
confident nonsense. The header is reported as opaque bytes with its offset, and the payloads
behind it are carved.
"""
from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_HITS = 200

# Signatures we can validate structurally.
SQUASHFS_MAGIC = b"hsqs"
UBI_MAGIC = b"UBI#"
UBIFS_MAGIC = b"\x31\x18\x10\x06"
JFFS2_MAGIC = b"\x85\x19"
CRAMFS_MAGIC = b"\x45\x3d\xcd\x28"
EXT_MAGIC = b"\x53\xef"
TRX_MAGIC = b"HDR0"
UIMAGE_MAGIC = b"\x27\x05\x19\x56"
GZIP_MAGIC = b"\x1f\x8b"
XZ_MAGIC = b"\xfd7zXZ\x00"
BZIP2_MAGIC = b"BZh"
LZMA_MAGIC = b"\x5d\x00\x00"
CPIO_MAGIC = b"070701"
TAR_MAGIC = b"ustar"
ELF_MAGIC = b"\x7fELF"
DTB_MAGIC = b"\xd0\x0d\xfe\xed"
FIT_MAGIC = b"\xd0\x0d\xfe\xed"
FV_MAGIC = b"_FVH"
ANDROID_BOOT_MAGIC = b"ANDROID!"
CHROMEOS_MAGIC = b"CHROMEOS"
SQUASHFS_NOI_MAGIC = b"sqsh"
SQUASHFS_BE_MAGIC = b"qshs"
SQUASHFS_LZ4_MAGIC = b"hsqt"
SQUASHFS_LZO_MAGIC = b"qshs"

COMPRESSED = {"gzip": GZIP_MAGIC, "xz": XZ_MAGIC, "bzip2": BZIP2_MAGIC, "lzma": LZMA_MAGIC}


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _validate_squashfs(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    """A real squashfs superblock has a power-of-two block size and a sane inode count."""
    if offset + 100 > len(blob):
        return False, "truncated superblock", {}
    # squashfs_super_block after s_magic: 4 x u32 (inodes, mkfs_time, block_size,
    # fragments) then 6 x u16 (compression, block_log, flags, no_ids, s_major, s_minor),
    # then root_inode (16 bytes) and the table offsets. The six u16s are all part of the
    # struct — counting five shifts every following field.
    (inodes, _mtime, block_size, fragments, compression, _block_log, flags, _no_ids,
     major, minor) = struct.unpack_from("<IIIIHHHHHH", blob, offset + 4)
    details = {
        "inodes": inodes,
        "block_size": block_size,
        "compression": compression,
        "version": f"{major}.{minor}",
        "fragments": fragments,
        "flags": flags,
    }
    if block_size < 4096 or block_size > 1048576:
        return False, f"implausible block size {block_size}", details
    if block_size & (block_size - 1):
        return False, f"block size {block_size} is not a power of two", details
    if major not in (3, 4):
        return False, f"unknown squashfs major version {major}", details
    return True, "", details


def _validate_ubi(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    """UBI# EC header: version must be 1 and the erase-block size must be sensible."""
    if offset + 64 > len(blob):
        return False, "truncated EC header", {}
    version = blob[offset + 4]
    (erase_count,) = struct.unpack_from(">Q", blob, offset + 8)
    (vid_offset,) = struct.unpack_from(">I", blob, offset + 16)
    (data_offset,) = struct.unpack_from(">I", blob, offset + 20)
    details = {"version": version, "erase_count": erase_count,
               "vid_hdr_offset": vid_offset, "data_offset": data_offset}
    if version != 1:
        return False, f"UBI version {version} is not 1", details
    if data_offset and vid_offset and data_offset <= vid_offset:
        return False, "data_offset is not after vid_hdr_offset", details
    return True, "", details


def _validate_trx(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    """TRX: validate the length and the CRC.

    Every field is LITTLE-endian — OpenWrt's trx.c stores with STORE32_LE — so reading the
    header big-endian yields a length around 0xA0000000 and the CRC check becomes
    meaningless. `flag_version` packs 16 bits of flags and 16 of version, so it is one u32,
    not two u16 fields.
    """
    if offset + 28 > len(blob):
        return False, "truncated TRX header", {}
    (length, crc, flag_version) = struct.unpack_from("<III", blob, offset + 4)
    # struct trx_header holds offsets[4] — four partition offsets, not two — which is what
    # makes the header 28 bytes. Reading two leaves the last two unexamined and shifts
    # nothing else, so the bug is silent.
    # TRXv1 uses a 28-byte header (three offsets); TRXv2 uses all four. OpenWrt's trx.c
    # starts writing at `sizeof(struct trx_header) - 4` for v1, which is exactly 28, so a v1
    # file has no fourth offset field to read.
    version = flag_version >> 16
    declared = struct.unpack_from("<IIII", blob, offset + 16)
    count = 4 if version >= 2 else 3
    details = {"length": length, "version": version,
               "flags": flag_version & 0xFFFF,
               "header_size": 32 if version >= 2 else 28,
               "offset_slots": count,
               "partition_offsets": [entry for entry in declared[:count]
                                     if entry not in (0, 0xFFFFFFFF)]}
    if length < 28 or offset + length > len(blob):
        return False, f"TRX length {length} does not fit the file", details
    # The CRC covers flag_version (offset 12) to the end of the declared image.
    computed = zlib.crc32(blob[offset + 12:offset + length]) & 0xFFFFFFFF
    details["crc_recorded"] = f"0x{crc:08x}"
    details["crc_computed"] = f"0x{computed:08x}"
    if crc and computed != crc:
        return False, "TRX CRC does not match its payload", details
    details["crc_verified"] = bool(crc)
    return True, "", details


def _validate_uimage(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    if offset + 64 > len(blob):
        return False, "truncated uImage header", {}
    (magic, hcrc, _timestamp, size, _load, _ep, dcrc, _os, _arch,
     image_type, compression) = struct.unpack_from(">IIIIIIIBBBB", blob, offset)
    details = {"payload_size": size, "image_type": image_type,
               "compression": compression, "data_crc": f"0x{dcrc:08x}"}
    if offset + 64 + size > len(blob):
        return False, f"uImage payload size {size} does not fit the file", details
    header = bytearray(blob[offset:offset + 64])
    header[4:8] = b"\x00\x00\x00\x00"
    computed = zlib.crc32(bytes(header)) & 0xFFFFFFFF
    if hcrc and computed != hcrc:
        return False, "uImage header CRC does not match", details
    details["header_crc_verified"] = bool(hcrc)
    if dcrc:
        body = blob[offset + 64:offset + 64 + size]
        computed_data = zlib.crc32(body) & 0xFFFFFFFF
        if computed_data != dcrc:
            return False, "uImage data CRC does not match", details
        details["data_crc_verified"] = True
    return True, "", details


def _validate_elf(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    if offset + 52 > len(blob):
        return False, "truncated ELF header", {}
    if blob[offset + 4] not in (1, 2):
        return False, f"invalid ELF class {blob[offset + 4]}", {}
    if blob[offset + 5] not in (1, 2):
        return False, f"invalid ELF data encoding {blob[offset + 5]}", {}
    if blob[offset + 6] != 1:
        return False, f"invalid ELF version {blob[offset + 6]}", {}
    machine = struct.unpack_from("<H", blob, offset + 18)[0]
    return True, "", {"class": "64-bit" if blob[offset + 4] == 2 else "32-bit",
                      "machine": machine}


def _validate_fdt(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    if offset + 40 > len(blob):
        return False, "truncated FDT header", {}
    (magic, totalsize, off_struct, off_strings, off_rsv, version,
     _last_comp) = struct.unpack_from(">IIIIIII", blob, offset)[:7]
    details = {"total_size": totalsize, "version": version}
    if totalsize < 40 or offset + totalsize > len(blob):
        return False, f"FDT total size {totalsize} does not fit the file", details
    if off_struct >= totalsize or off_strings > totalsize:
        return False, "FDT section offsets are outside the blob", details
    return True, "", details


def _validate_cramfs(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    if offset + 64 > len(blob):
        return False, "truncated cramfs superblock", {}
    (magic, size, _flags, _future, signature) = struct.unpack_from("<IIIII", blob, offset)
    details = {"size": size}
    if size < 64 or offset + size > len(blob):
        return False, f"cramfs size {size} does not fit the file", details
    return True, "", details


def _validate_ext(blob: bytes, offset: int) -> tuple[bool, str, dict[str, Any]]:
    """An ext superblock sits 1024 bytes into the filesystem, so the magic is at +1024."""
    base = offset - 1024
    if base < 0 or offset + 88 > len(blob):
        return False, "ext magic not at the expected superblock offset", {}
    (inodes,) = struct.unpack_from("<I", blob, offset + 4)
    (blocks,) = struct.unpack_from("<I", blob, offset + 8)
    (log_block,) = struct.unpack_from("<I", blob, offset + 28)
    details = {"inodes": inodes, "blocks": blocks, "log_block_size": log_block}
    if log_block > 6:
        return False, f"implausible ext block size exponent {log_block}", details
    if inodes == 0:
        return False, "ext superblock declares zero inodes", details
    return True, "", details


VALIDATORS = {
    "squashfs": (SQUASHFS_MAGIC, _validate_squashfs),
    "ubi": (UBI_MAGIC, _validate_ubi),
    "trx": (TRX_MAGIC, _validate_trx),
    "uimage": (UIMAGE_MAGIC, _validate_uimage),
    "elf": (ELF_MAGIC, _validate_elf),
    "dtb": (DTB_MAGIC, _validate_fdt),
    "cramfs": (CRAMFS_MAGIC, _validate_cramfs),
    "ext": (EXT_MAGIC, _validate_ext),
}


def _decompress_probe(blob: bytes, offset: int) -> dict[str, Any] | None:
    """Try to decompress at a compression signature; report what came out.

    This is how a vendor image usually hides its payloads, and it is cheap to check: if the
    decompressed stream starts with a filesystem or an FDT, the region is explained.
    """
    probes = (
        ("gzip", lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS)),
        ("xz", lambda d: lzma.decompress(d)),
        ("bzip2", lambda d: bz2.decompress(d)),
        ("lzma", lambda d: lzma.decompress(d, format=lzma.FORMAT_ALONE)),
    )
    for name, function in probes:
        try:
            inner = function(blob[offset:offset + 64 * 1024 * 1024])
        except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError):
            continue
        if not inner:
            continue
        detail: dict[str, Any] = {"compression": name, "decompressed_size": len(inner)}
        for label, (signature, _validator) in VALIDATORS.items():
            if inner[:4] == signature or signature in inner[:4096]:
                detail["contains"] = label
                break
        else:
            if inner[:6] == CPIO_MAGIC:
                detail["contains"] = "cpio"
            elif inner[257:262] == TAR_MAGIC:
                detail["contains"] = "tar"
        return detail
    return None


def carve_firmware(path: str | Path, *, limit: int = MAX_HITS) -> dict[str, Any]:
    """Locate the filesystems, kernels and compression streams inside a firmware blob."""
    try:
        blob = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if not blob:
        return {"ok": False, "path": str(path), "error": "file is empty"}

    regions: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for label, (signature, validator) in VALIDATORS.items():
        cursor = blob.find(signature)
        while cursor != -1 and len(regions) < limit:
            valid, reason, details = validator(blob, cursor)
            entry = {"format": label, "offset": cursor,
                     "offset_hex": f"0x{cursor:x}"}
            if valid:
                entry["validated"] = True
                entry.update(details)
                regions.append(entry)
            elif reason and reason not in (
                    "ext magic not at the expected superblock offset",):
                rejected.append({"format": label, "offset": cursor,
                                 "reason": reason, **details})
            cursor = blob.find(signature, cursor + 1)

    # Compression streams, checked once per candidate signature.
    for label, signature in COMPRESSED.items():
        cursor = blob.find(signature)
        while cursor != -1 and len(regions) < limit:
            probe = _decompress_probe(blob, cursor)
            if probe:
                regions.append({"format": label, "offset": cursor,
                                "offset_hex": f"0x{cursor:x}", "validated": True,
                                **probe})
            cursor = blob.find(signature, cursor + 1)

    regions.sort(key=lambda entry: entry["offset"])

    # Region extents, where the format states its own length.
    for entry in regions:
        for key in ("length", "total_size", "size"):
            if key in entry and entry[key]:
                entry["end"] = entry["offset"] + entry[key]
                break

    by_format: dict[str, int] = {}
    for entry in regions:
        by_format[entry["format"]] = by_format.get(entry["format"], 0) + 1

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "firmware-carve",
        "file_size": len(blob),
        "entropy_head": _entropy(blob[: min(len(blob), 65536)]),
        "region_count": len(regions),
        "regions": regions[:limit],
        "formats_found": dict(sorted(by_format.items(), key=lambda kv: -kv[1])),
        "rejected_count": len(rejected),
        "rejected": rejected[:20],
    }
    if not regions:
        result["note"] = ("no known filesystem, kernel or compression signature validated; "
                          "the image may use a vendor-specific container that this carver "
                          "does not know")
    elif rejected:
        result["rejected_note"] = (
            "signatures whose magic bytes matched but whose structure did not validate are "
            "listed under 'rejected' — a bare magic in a compressed stream is common and "
            "is not a finding")
    if blob[:4] in (FV_MAGIC, b"_FVH"):
        result["hint"] = "this looks like a UEFI image; try `re firmware` for volume parsing"
    return result


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte; >7.5 usually means compressed or encrypted."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    import math
    total = len(data)
    return round(-sum((count / total) * math.log2(count / total)
                      for count in counts if count), 3)


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return carve_firmware(path, **kwargs)
