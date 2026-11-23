"""Dart AOT snapshots and PNG-embedded ELF images.

WHY: a Flutter app ships its Dart code as an AOT snapshot. On Android it is a compressed
ELF shared object (`libapp.so`) whose sections hold the snapshot; on iOS the App Store
strips ELF but leaves the snapshot *appended to a PNG* — so `App.framework/App` is a PNG
whose IDAT payload is a full ELF image. Finding that is the difference between "iOS apps
contain no readable code" and being able to analyse them at all.

Formats, taken from the Dart VM's own source rather than from memory:

    runtime/vm/snapshot.h   Snapshot header, 20 bytes, LITTLE-ENDIAN:

        +0   i32 magic     0xdcdcf5f5
        +4   i64 length    payload length EXCLUDING the 4 magic bytes
        +12  i64 kind      0 kFull, 1 kFullJIT, 2 kFullAOT, 3 kModule, 4 kInvalid

    A `Snapshot` occupies 20 + length bytes (length already excludes the magic). For a kind
    that IncludesCode (kFullJIT, kFullAOT, kModule) a separate **data image** follows at
    `round_up(length, kObjectStartAlignment)` from the snapshot base — the code and read-only
    data, not the object graph.

Three traps:

  * `length` **excludes** the magic. The snapshot's total size is `length + 4`, and the
    data image is aligned from `round_up(length)`, not from the header size — reading the
    length as the full size overshoots by 16 bytes and the data-image base is wrong.
  * The magic is little-endian in a **big-endian-looking constant**. `0xdcdcf5f5` is
    written as f5 f5 dc dc on disk, so a byte-oriented search for "dcdcf5f5" finds nothing.
  * The PNG wrapper exists because the App Store rejects executables. A reader that looks
    only for `\\x7fELF` at offset 0 sees a PNG and stops.

This reader reports the header, kind, length consistency, the data image bounds, and — for
PNG-embedded images — the recovered ELF offset and size. It does NOT decompress the object
graph: the snapshot's serialisation is version-specific and there is no public stable
schema for it, so anything claimed beyond the header and the ELF envelope would be a guess.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 1024 * 1024 * 1024

DART_MAGIC = 0xDCDCF5F5
DART_MAGIC_BYTES = struct.pack("<I", DART_MAGIC)

SNAPSHOT_KINDS = {
    0: ("kFull", "full snapshot, no code"),
    1: ("kFullJIT", "full snapshot including JIT code"),
    2: ("kFullAOT", "full snapshot including AOT code"),
    3: ("kModule", "module snapshot with code"),
    4: ("kInvalid", "marked invalid"),
}

# Kinds whose data image follows the snapshot.
CODE_KINDS = ("kFullJIT", "kFullAOT", "kModule")

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ELF_MAGIC = b"\x7fELF"
OBJECT_START_ALIGNMENT = 8


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _snapshot_header(blob: bytes, offset: int = 0) -> dict[str, Any] | None:
    """Parse a Dart Snapshot header at `offset`, or None if the magic is absent."""
    if offset < 0 or offset + 20 > len(blob):
        return None
    (magic,) = struct.unpack_from("<I", blob, offset)
    if magic != DART_MAGIC:
        return None
    (length,) = struct.unpack_from("<q", blob, offset + 4)
    (kind,) = struct.unpack_from("<q", blob, offset + 12)
    name, description = SNAPSHOT_KINDS.get(kind, (f"unknown({kind})", "unrecognised kind"))

    # length excludes the magic, so the snapshot's total footprint is length + 4.
    total = length + 4
    header: dict[str, Any] = {
        "offset": offset,
        "magic": f"0x{magic:08x}",
        "kind": name,
        "kind_id": kind,
        "kind_description": description,
        "declared_length": length,
        "snapshot_size": total,
        "includes_code": name in CODE_KINDS,
    }
    available = len(blob) - offset
    if total > available:
        header["truncated"] = True
        header["available"] = available
        header["shortfall"] = total - available
    else:
        header["complete"] = True

    if name in CODE_KINDS:
        # The data image is aligned from round_up(length), measured from the snapshot base.
        aligned = (length + OBJECT_START_ALIGNMENT - 1) // OBJECT_START_ALIGNMENT \
            * OBJECT_START_ALIGNMENT
        data_offset = offset + aligned
        header["data_image_offset"] = data_offset
        if data_offset < len(blob):
            header["data_image_size"] = len(blob) - data_offset
        else:
            header["data_image_size"] = 0
            header["data_image_missing"] = True
    return header


def _png_chunks(blob: bytes) -> list[tuple[str, bytes]]:
    """Walk PNG chunks, returning (type, payload)."""
    chunks: list[tuple[str, bytes]] = []
    cursor = len(PNG_SIGNATURE)
    while cursor + 8 <= len(blob) and len(chunks) < 10000:
        (length,) = struct.unpack_from(">I", blob, cursor)
        kind = blob[cursor + 4:cursor + 8]
        body = blob[cursor + 8:cursor + 8 + length]
        if cursor + 8 + length > len(blob):
            break
        chunks.append((kind.decode("latin-1", "replace"), body))
        cursor += 8 + length + 4  # + CRC
        if kind == b"IEND":
            break
    return chunks


def inspect_dart_snapshot(path: str | Path) -> dict[str, Any]:
    """Read a Dart AOT snapshot, a libapp.so, or a PNG-wrapped iOS App image."""
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if not raw:
        return {"ok": False, "path": str(path), "error": "file is empty"}

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "dart-snapshot",
        "file_size": len(raw),
    }

    # Case 1: the file itself begins with the snapshot magic.
    header = _snapshot_header(raw, 0)
    if header is not None:
        result["container"] = "raw-snapshot"
        result["snapshot"] = header
        return result

    # Case 2: an ELF shared object (Android libapp.so).
    if raw[:4] == ELF_MAGIC:
        result["container"] = "elf"
        search = raw
        index = search.find(DART_MAGIC_BYTES)
        header = _snapshot_header(search, index) if index >= 0 else None
        if header is None:
            result["dart_snapshot_found"] = False
            result["note"] = ("this is an ELF but no Dart snapshot magic was found "
                             "inside it; it is not a Dart AOT image")
            return result
        result["snapshot"] = header
        result["dart_snapshot_found"] = True
        return result

    # Case 3: a PNG whose IDAT payload holds an ELF image (iOS App.framework/App).
    if raw[:8] == PNG_SIGNATURE:
        result["container"] = "png"
        chunks = _png_chunks(raw)
        result["png_chunks"] = [
            {"type": kind, "size": len(body)} for kind, body in chunks
        ]
        idat = b"".join(body for kind, body in chunks if kind == "IDAT")
        result["idat_size"] = len(idat)

        candidates: list[tuple[str, bytes]] = [("raw-idat", idat)]
        # IDAT holds zlib-compressed scanlines; the ELF may be inside the decompressed
        # stream when the image was built by concatenating the binary.
        try:
            inflated = zlib.decompress(idat)
        except zlib.error:
            inflated = b""
        if inflated:
            candidates.append(("inflated-idat", inflated))
            result["inflated_size"] = len(inflated)

        for label, blob in candidates:
            elf_offset = blob.find(ELF_MAGIC)
            if elf_offset == -1:
                continue
            result["elf"] = {
                "recovered_from": label,
                "offset_in_stream": elf_offset,
                "elf_size": len(blob) - elf_offset,
            }
            inner = blob[elf_offset:]
            snap_index = inner.find(DART_MAGIC_BYTES)
            if snap_index != -1:
                snap = _snapshot_header(inner, snap_index)
                if snap is not None:
                    result["snapshot"] = snap
                    result["dart_snapshot_found"] = True
            break

        if "snapshot" not in result:
            result["dart_snapshot_found"] = False
            result["note"] = (
                "PNG wrapper detected but no Dart snapshot was located. On iOS the code "
                "is usually inside the IDAT stream; this reader reports what it found "
                "rather than assuming the image is a snapshot")
        return result

    # Case 4: an arbitrary blob that may contain a snapshot at some offset.
    index = raw.find(DART_MAGIC_BYTES)
    if index != -1:
        header = _snapshot_header(raw, index)
        if header is not None:
            result["container"] = "embedded"
            result["snapshot"] = header
            result["dart_snapshot_found"] = True
            return result

    return {"ok": False, "path": str(path),
            "error": "no Dart snapshot magic and not an ELF or PNG image",
            "hint": "expected an ELF (libapp.so), a PNG-wrapped iOS image, or a raw "
                    "snapshot beginning 0xdcdcf5f5"}


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_dart_snapshot(path, **kwargs)
