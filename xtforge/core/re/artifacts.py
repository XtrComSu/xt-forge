"""Readers for four more artifact formats: SQLite, Erlang BEAM, EVM, Apple IPS.

WHY these are here: each is a container an analyst meets during host or mobile
triage and each has a published, self-describing layout. REA carries
`inspect_sqlite_database`, `inspect_erlang_beam`, `inspect_evm_interface` and
`inspect_apple_ips`.

The SQLite reader parses the file header and page structure **directly** rather
than opening it with the sqlite3 module. That is deliberate: a database recovered
from a disk image or a seized device is frequently truncated, hot-journalled, or
mid-write, and sqlite3 refuses to open exactly those files. Opening with sqlite3
would answer "not a database" for the case an investigator most needs described.
Header-level parsing always works and says what state the file is in.

Each reader returns {"ok": bool, ...} and never raises.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


# ---------------------------------------------------------------------- sqlite
_SQLITE_MAGIC = b"SQLite format 3\x00"
# Header field offsets, from https://www.sqlite.org/fileformat2.html §1.3.
_SQLITE_OFFSETS = {
    "page_size": 16, "write_version": 18, "read_version": 19, "reserved_space": 20,
    "max_payload_fraction": 21, "min_payload_fraction": 22,
    "leaf_payload_fraction": 23, "file_change_counter": 24, "database_size_pages": 28,
    "first_freelist_trunk": 32, "freelist_page_count": 36, "schema_cookie": 40,
    "schema_format": 44, "default_page_cache_size": 48, "largest_root_bfirst": 52,
    "text_encoding": 56, "user_version": 60, "incremental_vacuum": 64,
    "application_id": 68,
}


def inspect_sqlite(path: str | Path) -> dict[str, Any]:
    """Describe a SQLite database without opening it.

    Reports the header fields, the encoding, whether the file is complete, whether
    a rollback journal or WAL sits beside it (which is how you know a write was in
    flight), and — when the schema table can be walked safely — the object names.

    Deliberately does not use the sqlite3 module: see the module docstring.
    """
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(raw) < 100:
        return {"ok": False, "path": str(path),
                "error": f"file too small for a SQLite header ({len(raw)} bytes)"}
    if raw[:16] != _SQLITE_MAGIC:
        return {"ok": False, "path": str(path),
                "error": "no SQLite header magic",
                "found_magic": raw[:16].hex()}

    # The SQLite database header is BIG-endian for every multi-byte field
    # (fileformat2 §1.3), unlike the b-tree pages inside it, which are also
    # big-endian, and unlike the WAL, which is both. Reading these little-endian
    # produces plausible-looking integers that are all byte-reversed: a 32 KB page
    # size reads as 128, a 7-page database declares 117 million pages, and the
    # text encoding 1 (UTF-8) reads as 16777216.
    def field(name: str, size: int = 4, signed: bool = False) -> int | None:
        offset = _SQLITE_OFFSETS[name]
        if offset + size > len(raw):
            return None
        if size == 2:
            fmt = ">h" if signed else ">H"
        elif size == 4:
            fmt = ">i" if signed else ">I"
        else:
            fmt = ">B"
        return struct.unpack_from(fmt, raw, offset)[0]

    page_size = field("page_size", 2)
    # The value 1 means 65536, which does not fit in the 2-byte field.
    if page_size == 1:
        page_size = 65536
    encoding_id = field("text_encoding")
    encoding = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(encoding_id,
                                                              f"unknown ({encoding_id})")
    declared_pages = field("database_size_pages")
    expected_size = (declared_pages or 0) * (page_size or 0)

    path_obj = Path(path)
    journals = []
    for suffix in ("-journal", "-wal", "-shm"):
        candidate = path_obj.with_name(path_obj.name + suffix)
        if candidate.is_file():
            journals.append({"name": candidate.name,
                             "size": candidate.stat().st_size})

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "page_size": page_size,
        "write_version": field("write_version", 1),
        "read_version": field("read_version", 1),
        "text_encoding": encoding,
        "schema_format": field("schema_format"),
        "schema_cookie": field("schema_cookie"),
        "user_version": field("user_version", signed=True),
        "application_id": field("application_id"),
        "file_change_counter": field("file_change_counter"),
        "declared_pages": declared_pages,
        "declared_size": expected_size,
        "actual_size": len(raw),
        "freelist_pages": field("freelist_page_count"),
        "incremental_vacuum": bool(field("incremental_vacuum")),
        "journals": journals,
        "embedded_image": raw[:16] != _SQLITE_MAGIC and False,
    }
    # A file shorter than its header claims is the normal result of a truncated
    # capture; saying so is the difference between "corrupt" and "incomplete".
    if expected_size and len(raw) < expected_size:
        result["truncated"] = True
        result["truncated_by"] = expected_size - len(raw)
        result["warnings"] = [f"file is {expected_size - len(raw)} bytes shorter than "
                              "its header declares"]
    elif expected_size and len(raw) > expected_size:
        result["warnings"] = ["file is longer than its header declares "
                              "(append or page-size mismatch)"]

    # Walk page 1's schema table for object names. sqlite_master is a b-tree whose
    # records are (type, name, tbl_name, rootpage, sql). Only the name column is
    # decoded here: a damaged database usually still yields names, and inventing a
    # full record decoder for corrupt input is how a reader starts lying.
    objects: list[dict[str, Any]] = []
    try:
        objects = _sqlite_schema_names(raw, page_size or 4096)
    except (struct.error, IndexError, UnicodeDecodeError):
        result.setdefault("warnings", []).append("schema table could not be walked")
    result["objects"] = objects[:200]
    result["object_count"] = len(objects)
    return result


def _sqlite_schema_names(raw: bytes, page_size: int) -> list[dict[str, Any]]:
    """Read sqlite_master cells from page 1 and pull out recorded object names.

    A table b-tree leaf cell is: payload-length varint, rowid varint, then the
    record. Skipping the rowid is the easy mistake — the parser then reads the rowid
    as the record's header size and decodes the serial types from the wrong byte.
    Here it fails consistently enough to look like an empty schema rather than a
    parse error, which is why the object count is asserted against a known database
    in the tests.

    Only the local part of each payload is decoded: a record that spills onto
    overflow pages still yields its leading columns, and the leading columns are
    exactly the ones needed (type, name, tbl_name). Records too large to start
    locally are skipped rather than guessed at.
    """
    if page_size < 512 or page_size > len(raw):
        return []
    page = raw[:page_size]
    header_offset = 100  # page 1 has a 100-byte database header before its b-tree
    if page[header_offset] != 0x0D:
        return []  # not a leaf table page
    cell_count = struct.unpack_from(">H", page, header_offset + 3)[0]
    if cell_count > 10000:
        return []
    objects: list[dict[str, Any]] = []
    for index in range(cell_count):
        pointer_offset = header_offset + 8 + index * 2
        if pointer_offset + 2 > len(page):
            break
        cell_offset = struct.unpack_from(">H", page, pointer_offset)[0]
        if cell_offset + 2 > len(page):
            continue
        try:
            payload_size, cursor = _sqlite_varint(page, cell_offset)
            if payload_size is None or cursor is None:
                continue
            # The rowid varint sits between the length and the record.
            _rowid, record_start = _sqlite_varint(page, cursor)
            if record_start is None:
                continue
            header_size, header_start = _sqlite_varint(page, record_start)
            if header_size is None or header_start is None or header_size < 1:
                continue
            # The header size counts itself.
            header_end = record_start + header_size
            if header_end > len(page):
                continue
            serials: list[int] = []
            position = header_start
            while position < header_end:
                serial, next_position = _sqlite_varint(page, position)
                if serial is None or next_position is None:
                    break
                serials.append(serial)
                position = next_position
            if not serials:
                continue
            offset = header_end
            values: list[Any] = []
            for serial in serials:
                size = _serial_size(serial)
                if offset + size > len(page):
                    values.append(None)
                    break
                chunk = page[offset:offset + size]
                if serial >= 13 and serial % 2 == 1:
                    values.append(chunk.decode("utf-8", "replace"))
                elif serial >= 12 and serial % 2 == 0:
                    values.append(chunk.decode("utf-16-le", "replace"))
                else:
                    values.append(int.from_bytes(chunk, "big", signed=True)
                                  if chunk else None)
                offset += size
            if len(values) >= 2 and isinstance(values[0], str) and isinstance(values[1], str):
                objects.append({
                    "type": values[0],
                    "name": values[1],
                    "table": values[2] if len(values) > 2 else None,
                    "root_page": values[3] if len(values) > 3 else None,
                })
        except (struct.error, IndexError, UnicodeDecodeError, ValueError):
            continue
    return objects


def _sqlite_varint(data: bytes, offset: int) -> tuple[int | None, int | None]:
    """Decode a SQLite variable-length integer: 1-9 bytes, big-endian.

    The ninth byte contributes all 8 bits; the preceding eight contribute 7 each.
    """
    value = 0
    for i in range(9):
        if offset + i >= len(data):
            return None, None
        byte = data[offset + i]
        if i == 8:
            return (value << 8) | byte, offset + 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, offset + i + 1
    return None, None


def _serial_size(serial: int) -> int:
    """Bytes occupied by a value of this serial type (fileformat2 §2.1)."""
    if serial == 0:
        return 0
    if serial <= 4:
        return serial
    if serial == 5:
        return 6
    if serial == 6 or serial == 7:
        return 8
    if serial <= 9:
        return 0
    return (serial - 12) // 2


# ------------------------------------------------------------------------ beam
# BEAM "FOR1" container holding "BEAM" chunks. Chunk ids of interest.
_BEAM_CHUNKS = {
    b"AtU8": "atom_table_utf8", b"Atom": "atom_table_latin1", b"Code": "code",
    b"StrT": "string_table", b"ImpT": "import_table", b"ExpT": "export_table",
    b"LocT": "local_table", b"FunT": "function_table", b"LitT": "literal_table",
    b"Attr": "attributes", b"CInf": "compile_info", b"Dbgi": "debug_info",
    b"Line": "line_table", b"Docs": "docs", b"Type": "type",
}


def inspect_beam(path: str | Path) -> dict[str, Any]:
    """Inventory an Erlang/Elixir BEAM file: chunks, exports, compile info.

    A BEAM file is an IFF-style container: "FOR1", a big-endian length, "BEAM",
    then a sequence of (id, length, payload) chunks with 4-byte alignment. The
    module's own name is the first atom, and the compilation info chunk records the
    compiler version and source path — which is what an analyst wants, since Elixir
    and Erlang ship code this way into releases.
    """
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(raw) < 12:
        return {"ok": False, "path": str(path), "error": "file too small for a BEAM header"}
    if raw[:4] != b"FOR1":
        return {"ok": False, "path": str(path),
                "error": "no FOR1 magic — not a BEAM file",
                "found": raw[:4].hex()}
    declared = struct.unpack_from(">I", raw, 4)[0]
    if raw[8:12] != b"BEAM":
        return {"ok": False, "path": str(path),
                "error": "FOR1 container does not hold a BEAM chunk"}

    chunks: list[dict[str, Any]] = []
    cursor = 12
    limit = min(len(raw), 8 + declared)
    while cursor + 8 <= limit:
        chunk_id = raw[cursor:cursor + 4]
        size = struct.unpack_from(">I", raw, cursor + 4)[0]
        start = cursor + 8
        end = start + size
        if end > len(raw):
            chunks.append({"id": chunk_id.decode("latin-1"), "size": size,
                           "truncated": True})
            break
        chunks.append({
            "id": chunk_id.decode("latin-1"),
            "name": _BEAM_CHUNKS.get(chunk_id, "unknown"),
            "size": size,
            "offset": start,
        })
        cursor = end + ((-(end)) % 4) if False else end
        # IFF chunks are padded to an even length, not 4.
        if size % 2:
            cursor += 1
        if len(chunks) > 500:
            break

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "declared_size": declared,
        "actual_size": len(raw),
        "chunk_count": len(chunks),
        "chunks": chunks,
        "truncated": declared + 8 > len(raw),
    }

    by_id = {c["id"]: c for c in chunks}

    # Module name: the first atom in the atom table.
    atom_chunk = by_id.get("AtU8") or by_id.get("Atom")
    if atom_chunk and "offset" in atom_chunk:
        start = atom_chunk["offset"]
        if start + 2 <= len(raw):
            count = struct.unpack_from(">I", raw, start)[0] if atom_chunk["size"] >= 4 else 0
            name_offset = start + 4
            if count and name_offset < len(raw):
                length = raw[name_offset]
                if 0 < length < 256 and name_offset + 1 + length <= len(raw):
                    result["module"] = raw[name_offset + 1:name_offset + 1 + length].decode(
                        "latin-1", "replace")

    # Exports: chunk is [count:4][[name_len:1][name][arity:4][label:4]]*
    export_chunk = by_id.get("ExpT")
    if export_chunk and "offset" in export_chunk:
        exports = []
        start = export_chunk["offset"]
        if start + 4 <= len(raw):
            count = struct.unpack_from(">I", raw, start)[0]
            pos = start + 4
            for _ in range(min(count, 500)):
                if pos >= len(raw):
                    break
                length = raw[pos]
                pos += 1
                if pos + length + 8 > len(raw):
                    break
                name = raw[pos:pos + length].decode("latin-1", "replace")
                pos += length
                arity, label = struct.unpack_from(">II", raw, pos)
                pos += 8
                exports.append({"function": name, "arity": arity, "label": label})
        result["exports"] = exports
        result["export_count"] = len(exports)

    # Compile info: two NUL-terminated strings, version then source path.
    cinf = by_id.get("CInf")
    if cinf and "offset" in cinf:
        blob = raw[cinf["offset"]:cinf["offset"] + cinf["size"]]
        parts = blob.split(b"\x00")
        if parts and parts[0]:
            result["compiler_version"] = parts[0].decode("utf-8", "replace")
        paths = [p.decode("utf-8", "replace") for p in parts[1:] if p.startswith(b"/")]
        if paths:
            result["source_paths"] = paths[:20]
    return result


# ------------------------------------------------------------------------- evm
# EVM bytecode is a sequence of opcodes; PUSH1..PUSH32 carry immediate data.
_EVM_OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP",
    0x0B: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT",
    0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR", 0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY", 0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH",
    0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO",
    0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
    0x5A: "GAS", 0x5B: "JUMPDEST", 0x5F: "PUSH0", 0xF0: "CREATE", 0xF1: "CALL",
    0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2",
    0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}


def inspect_evm(path: str | Path) -> dict[str, Any]:
    """Disassemble EVM bytecode and list the selectors it dispatches on.

    Accepts raw bytecode or a hex text file, with or without a 0x prefix — a
    contract's bytecode is commonly extracted as hex text, so requiring binary
    would reject the usual form.

    The interesting output is the function selectors: `PUSH4 <4 bytes>` immediately
    followed by EQ inside the dispatcher is how a Solidity contract names its
    external interface (the first 4 bytes of keccak256 of the signature). Reporting
    those gives the same answer as `inspect_evm_interface` without needing an RPC
    endpoint.
    """
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    as_hex = False
    text = None
    if raw[:1] not in (b"\x60", b"\x61", b"\x00") or b"\n" in raw[:200]:
        try:
            text = raw.decode("ascii").strip()
            as_hex = True
        except UnicodeDecodeError:
            as_hex = False
    if as_hex and text:
        cleaned = text[2:] if text[:2].lower() == "0x" else text
        cleaned = "".join(ch for ch in cleaned if ch in "0123456789abcdefABCDEF")
        if len(cleaned) % 2:
            cleaned = cleaned[:-1]
        try:
            code = bytes.fromhex(cleaned)
        except ValueError as exc:
            return {"ok": False, "path": str(path),
                    "error": f"not valid hex bytecode: {exc}"}
    else:
        code = raw

    if not code:
        return {"ok": False, "path": str(path), "error": "empty bytecode"}

    selectors: list[str] = []
    opcodes: dict[str, int] = {}
    cursor = 0
    instruction_count = 0
    while cursor < len(code):
        op = code[cursor]
        instruction_count += 1
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            width = op - 0x5F
            immediate = code[cursor + 1:cursor + 1 + width]
            name = f"PUSH{width}"
            opcodes[name] = opcodes.get(name, 0) + 1
            # A 4-byte push followed by EQ is a selector comparison.
            if width == 4 and len(immediate) == 4:
                following = code[cursor + 5] if cursor + 5 < len(code) else None
                if following == 0x14:  # EQ
                    selectors.append("0x" + immediate.hex())
            cursor += 1 + width
            continue
        name = _EVM_OPCODES.get(op, f"UNKNOWN_0x{op:02x}")
        opcodes[name] = opcodes.get(name, 0) + 1
        cursor += 1

    sorted_ops = sorted(opcodes.items(), key=lambda item: -item[1])[:40]
    return {
        "ok": True,
        "path": str(path),
        "input_form": "hex text" if as_hex else "raw bytecode",
        "bytecode_size": len(code),
        "instruction_count": instruction_count,
        "selectors": selectors,
        "selector_count": len(selectors),
        "has_metadata_suffix": code[-2:] == b"\x00\x33" if len(code) > 2 else False,
        "opcodes": dict(sorted_ops),
        "dispatches": bool(selectors),
    }


# -------------------------------------------------------------------- apple ips
def inspect_apple_ips(path: str | Path) -> dict[str, Any]:
    """Read an Apple crash report in .ips form.

    .ips files are JSON: the first line is a small header object, the remainder is
    the payload object. Older reports are a single JSON document; newer ones are
    two newline-separated objects. Both are handled by attempting the split and
    falling back to a single parse.

    Apple report payloads frequently contain invalid UTF-8 (they embed raw memory
    descriptions), so decoding is lenient — refusing the file because one byte is
    bad would discard an otherwise complete crash report.
    """
    import json
    try:
        raw = _read(path, limit=64 * 1024 * 1024)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return {"ok": False, "path": str(path), "error": "empty report"}

    header: dict[str, Any] = {}
    payload: dict[str, Any] = {}
    parsed = False
    lines = text.split("\n", 1)
    if len(lines) == 2:
        try:
            header = json.loads(lines[0])
            payload = json.loads(lines[1])
            parsed = True
        except json.JSONDecodeError:
            parsed = False
    if not parsed:
        try:
            document = json.loads(text)
            if isinstance(document, dict):
                payload = document
                header = {}
                parsed = True
        except json.JSONDecodeError as exc:
            return {"ok": False, "path": str(path),
                    "error": f"not JSON: {exc}"}
    if not parsed:
        return {"ok": False, "path": str(path), "error": "could not parse the report"}

    # `bug_type` 309 is a crash; others are spindumps, hangs and so on.
    bug_type = header.get("bug_type") or payload.get("bug_type")
    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "bug_type": bug_type,
        "report_kind": {309: "crash", 210: "spindump", 288: "hang", 115: "crash",
                        298: "energy"}.get(_as_int(bug_type), "unknown"),
        "app_name": payload.get("app_name") or payload.get("procName"),
        "app_version": payload.get("app_version"),
        "os_version": payload.get("os_version"),
        "timestamp": header.get("timestamp") or payload.get("captureTime"),
    }
    exception = payload.get("exception") or {}
    if isinstance(exception, dict):
        result["exception"] = {
            "type": exception.get("type"),
            "signal": exception.get("signal"),
            "subtype": exception.get("subtype"),
            "codes": exception.get("codes"),
        }
    faulting = payload.get("faultingThread")
    if isinstance(faulting, int):
        result["faulting_thread"] = faulting
        threads = payload.get("threads") or []
        if 0 <= faulting < len(threads):
            frames = threads[faulting].get("frames") or []
            result["faulting_frames"] = len(frames)
            images = payload.get("usedImages") or []
            top = []
            for frame in frames[:12]:
                image_index = frame.get("imageIndex")
                name = None
                if isinstance(image_index, int) and 0 <= image_index < len(images):
                    name = images[image_index].get("name")
                top.append({"image": name,
                            "symbol": frame.get("symbol"),
                            "offset": frame.get("imageOffset")})
            result["top_frames"] = top
    result["thread_count"] = len(payload.get("threads") or [])
    result["image_count"] = len(payload.get("usedImages") or [])
    return result


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


# ----------------------------------------------------------------------- entry
def inspect(path: str | Path) -> dict[str, Any]:
    """Detect which of these four formats a file is, and read it."""
    try:
        canon = guard.read_guard(path)
        if not canon.is_file():
            return {"ok": False, "path": str(path), "error": "not a regular file"}
        with canon.open("rb") as handle:
            head = handle.read(4096)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if head[:16] == _SQLITE_MAGIC:
        return inspect_sqlite(path)
    if head[:4] == b"FOR1":
        return inspect_beam(path)
    stripped = head.lstrip()
    if stripped[:1] in (b"{", b"["):
        return inspect_apple_ips(path)
    # EVM accepts raw bytes or hex text; try hex only when the content looks like it.
    try:
        text = head.decode("ascii").strip()
        candidate = text[2:] if text[:2].lower() == "0x" else text
        if candidate and all(c in "0123456789abcdefABCDEF\n\r " for c in candidate):
            return inspect_evm(path)
    except UnicodeDecodeError:
        pass
    if head[:1] and head[0] >= 0x00 and all(b in _EVM_OPCODES or 0x60 <= b <= 0x7F
                                             for b in head[:64]):
        return inspect_evm(path)
    return {"ok": False, "path": str(path),
            "error": "unrecognized format (not SQLite, BEAM, EVM or Apple IPS)",
            "checked": ["sqlite", "beam", "evm", "apple-ips"]}
