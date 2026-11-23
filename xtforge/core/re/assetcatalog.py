"""Apple .car asset catalogs (the BOMStore container).

WHY: a `.car` file is how an iOS or macOS app ships its images, colours and app icons.
For an analyst it answers "what artwork and named assets does this app contain", which
is how you identify an app from a stripped binary, find unreferenced assets, or compare
builds. It looks like an opaque blob because the container is Apple's BOM format, not a
zip and not an image.

The container, confirmed against a real `Assets.car` shipped inside a macOS app:

    "BOMStore"           8-byte magic (the first four bytes alone spell "BOMS")
    u32 version
    u32 block_count
    u32 index_offset     block table: u32 count, then (addr, size) pairs
    u32 index_length
    u32 vars_offset      the name table
    u32 vars_length

    vars:  u32 count
           count * { u32 block_index, u8 name_length, name bytes }

    index: u32 count, then count * { u32 addr, u32 size }   (8 bytes per block)
    block: 4-byte type tag, then type-specific body

Four traps, all of which produce plausible output rather than an error:

  * The magic is **8 bytes** ("BOMStore"). Reading it as 4 and then treating the next
    word as a version puts every subsequent field four bytes early.
  * The BOM container is **big-endian**, but a block's *contents* are little-endian.
    Reading the CARHEADER with the container's byte order reports the CoreUI version
    byte-swapped (972 becomes 3422748672) and still parses fine.
  * The index is an array of **(addr, size) pairs**, not a parallel array of addresses.
    Reading it as count+1 consecutive u32s produces non-monotonic "offsets" and
    negative block sizes; every block then resolves to the wrong bytes.
  * Each block begins with a **4-byte type tag** (`RATC` for the CAR header, `tree` for a
    B-tree index, `tmfk` for a key format, `META` for metadata). The tag is how a block's
    kind is known without guessing from its contents.

The name table is what makes the catalog navigable: CARHEADER, RENDITIONS, FACETKEYS,
KEYFORMAT, EXTENDED_METADATA, BITMAPKEYS. So this reader reports the named blocks and
the rendition keys it can locate, not just "this is a BOM file".
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_NAMES = 10000
MAGIC = b"BOMStore"

# Blocks that carry per-image records rather than metadata.
_RENDITION_BLOCKS = ("RENDITIONS", "BITMAPKEYS", "FACETKEYS")


class BomError(Exception):
    """Raised when a file is not a readable BOMStore container."""


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _bom_header(raw: bytes) -> dict[str, int]:
    if len(raw) < 32:
        raise BomError(f"header truncated ({len(raw)} bytes, need 32)")
    if raw[:8] != MAGIC:
        found = raw[:8]
        raise BomError(f"not a BOMStore container (magic {found!r}, want {MAGIC!r})")
    (version, block_count, index_offset, index_length,
     vars_offset, vars_length) = struct.unpack_from(">IIIIII", raw, 8)
    if block_count > 10_000_000:
        raise BomError(f"implausible block count {block_count}")
    return {
        "version": version,
        "block_count": block_count,
        "index_offset": index_offset,
        "index_length": index_length,
        "vars_offset": vars_offset,
        "vars_length": vars_length,
    }


def _block_table(raw: bytes, header: dict[str, int]) -> list[tuple[int, int]]:
    """Read the block table: u32 count, then count (addr, size) pairs.

    An earlier version read this as block_count+1 consecutive u32 "offsets". On the real
    file that produced non-monotonic values and a negative block size, because the table
    is pairs — an address followed by its own length — not a boundary list.
    """
    start = header["index_offset"]
    if start + 4 > len(raw):
        raise BomError(f"index at {start} is past the end of the file")
    (count,) = struct.unpack_from(">I", raw, start)
    if count == 0 or count > 10_000_000:
        raise BomError(f"implausible block-table count {count}")
    needed = 4 + count * 8
    if start + needed > len(raw):
        raise BomError(f"index at {start} does not hold {count} (addr, size) pairs")
    table: list[tuple[int, int]] = []
    for index in range(count):
        addr, size = struct.unpack_from(">II", raw, start + 4 + index * 8)
        table.append((addr, size))
    return table


_BLOCK_TAGS = {
    "RATC": "car-header",
    "tree": "b-tree-index",
    "tmfk": "key-format",
    "META": "metadata",
    "GLOB": "globals",
    "blob": "blob",
}


def _block_extent(raw: bytes, table: list[tuple[int, int]],
                  index: int) -> tuple[int, int] | None:
    """A block's (start, end) from its own address and size. Size 0 means empty."""
    if index < 0 or index >= len(table):
        return None
    start, size = table[index]
    if start == 0 or size == 0:
        return None
    end = start + size
    if end > len(raw) or end < start:
        return None
    return start, end


def _block_tag(raw: bytes, extent: tuple[int, int] | None) -> str | None:
    """Every BOM block starts with a 4-byte ASCII type tag."""
    if extent is None:
        return None
    start, end = extent
    if end - start < 4:
        return None
    tag = raw[start:start + 4]
    if all(32 <= byte < 127 for byte in tag):
        return tag.decode("latin-1")
    return None


def _name_table(raw: bytes, header: dict[str, int]) -> list[dict[str, Any]]:
    """Parse the variable-name table: u32 count, then (u32 block, u8 len, name)."""
    names: list[dict[str, Any]] = []
    start = header["vars_offset"]
    end = start + header["vars_length"]
    if start <= 0 or end > len(raw) or end - start < 4:
        return names
    (count,) = struct.unpack_from(">I", raw, start)
    if count == 0 or count > MAX_NAMES:
        return names
    cursor = start + 4
    for _ in range(count):
        if cursor + 5 > end:
            break
        block_index = struct.unpack_from(">I", raw, cursor)[0]
        length = raw[cursor + 4]
        cursor += 5
        if length == 0 or cursor + length > end:
            break
        name = raw[cursor:cursor + length].decode("latin-1", "replace")
        cursor += length
        names.append({"name": name, "block": block_index})
    return names


def _carheader(raw: bytes, extent: tuple[int, int] | None) -> dict[str, Any]:
    """The CARHEADER block describes the catalog as a whole.

    Layout: char tag[4] ("RATC"), then little-endian

        u32 coreui_version    e.g. 972 for CoreUI-972.1
        u32 version           catalog format version (17 in current assets)
        u32 flags
        u32 key_count
        char renderer[128]    the CoreUI build string

    The endianness flips here: the BOM container's own fields and block table are
    big-endian, but a block's *contents* follow the platform (little-endian on Apple
    silicon). Reading this block big-endian reports "version 3422748672", which is just
    the CoreUI version byte-swapped — a wrong value that parses without complaint.
    """
    if extent is None:
        return {}
    start, end = extent
    if end - start < 20:
        return {}
    tag = raw[start:start + 4]
    coreui_version, version, flags, key_count = struct.unpack_from(
        "<IIII", raw, start + 4)
    result: dict[str, Any] = {
        "tag": tag.decode("latin-1"),
        "coreui_version": coreui_version,
        "version": version,
        "flags": flags,
        "key_count": key_count,
        "size": end - start,
    }
    renderer = raw[start + 20:min(start + 148, end)].split(b"\x00")[0]
    if renderer and all(32 <= byte < 127 for byte in renderer):
        result["renderer"] = renderer.decode("latin-1")
    return result


def _rendition_keys(raw: bytes, extent: tuple[int, int] | None,
                    limit: int = 200) -> list[str]:
    """Extract plausible rendition names from a key block.

    Rendition keys are length-prefixed ASCII names. They are not in a fixed-width table,
    so this walks the block looking for length-prefixed printable runs and keeps those
    that look like asset names. It is a heuristic and is labelled as one — the count of
    names found is reported alongside, so a caller can see how much was recovered.
    """
    if extent is None:
        return []
    start, end = extent
    found: list[str] = []
    seen: set[str] = set()
    cursor = start
    while cursor < end and len(found) < limit:
        length = raw[cursor]
        if 3 <= length <= 96 and cursor + 1 + length <= end:
            body = raw[cursor + 1:cursor + 1 + length]
            if all(32 <= byte < 127 for byte in body):
                text = body.decode("latin-1")
                # Asset names look like identifiers; require a letter and no spaces.
                if (any(ch.isalpha() for ch in text) and " " not in text
                        and text not in seen):
                    seen.add(text)
                    found.append(text)
                    cursor += 1 + length
                    continue
        cursor += 1
    return found


def inspect_asset_catalog(path: str | Path, *, limit: int = 200) -> dict[str, Any]:
    """Read an Apple .car asset catalog: header, named blocks, rendition keys."""
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    try:
        header = _bom_header(raw)
    except BomError as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    try:
        table = _block_table(raw, header)
    except BomError as exc:
        return {"ok": False, "path": str(path), "error": str(exc),
                "header": header}

    names = _name_table(raw, header)
    named_blocks: dict[str, dict[str, Any]] = {}
    for entry in names:
        extent = _block_extent(raw, table, entry["block"])
        record: dict[str, Any] = {"block": entry["block"]}
        if extent is None:
            record["empty"] = True
            record["size"] = 0
        else:
            record["offset"] = extent[0]
            record["size"] = extent[1] - extent[0]
            tag = _block_tag(raw, extent)
            if tag:
                record["tag"] = tag
                record["tag_kind"] = _BLOCK_TAGS.get(tag, "unknown")
        named_blocks[entry["name"]] = record

    car_header = {}
    if "CARHEADER" in named_blocks:
        car_header = _carheader(raw,
                                _block_extent(raw, table,
                                              named_blocks["CARHEADER"]["block"]))

    renditions: list[str] = []
    rendition_source = None
    for candidate in _RENDITION_BLOCKS:
        if candidate not in named_blocks:
            continue
        extent = _block_extent(raw, table, named_blocks[candidate]["block"])
        keys = _rendition_keys(raw, extent, limit=limit)
        if keys:
            renditions = keys
            rendition_source = candidate
            break

    # Every block, occupied or not, so the count is auditable.
    occupied = sum(1 for index in range(header["block_count"])
                   if _block_extent(raw, table, index) is not None)

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "apple-asset-catalog",
        "container": "BOMStore",
        "version": header["version"],
        "file_size": len(raw),
        "block_count": header["block_count"],
        "index_count": len(table),
        "occupied_blocks": occupied,
        "empty_blocks": header["block_count"] - occupied,
        "named_block_count": len(named_blocks),
        "named_blocks": named_blocks,
        "car_header": car_header,
        "renditions": renditions,
        "rendition_count": len(renditions),
        "rendition_source": rendition_source,
    }
    if rendition_source and rendition_source != "RENDITIONS":
        result["rendition_note"] = (
            f"names recovered from the {rendition_source} block; the RENDITIONS block "
            f"was not readable as a key table")
    if not renditions:
        result["rendition_note"] = (
            "no rendition names recovered; the key blocks use a layout this reader does "
            "not decode, so only the named-block map is reported")
    return result


def inspect(path: str | Path) -> dict[str, Any]:
    return inspect_asset_catalog(path)
