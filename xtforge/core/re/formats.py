"""Readers for several small, precisely-specified artifact formats.

WHY these live together: each answers one narrow question about a file whose
format is fully specified and small — a plist, a Python .pyc, a desktop entry, a
Go binary's build info, a Rust binary's version markers. They are the kind of
capability REA carries one tool each for
(`inspect_plist`, `inspect_python_pyc`, `inspect_desktop_application`,
`inspect_go_binary`, `inspect_rust_binary`). Separately they are trivial;
together they are five rows of breadth.

Every reader returns {"ok": bool, ...} and never raises on bad input: a file that
is not the expected format is a normal answer ("this is not a plist"), not an
exception. That matters because these verbs are dispatched by an agent that cannot
recover from a traceback.

Where a format has a version-dependent layout — .pyc most of all, since its header
changed four times — the version is read from the file and the layout chosen from
it, rather than assuming the host interpreter's format. Assuming produces
confident nonsense on any other version's output.
"""
from __future__ import annotations

import datetime as _dt
import struct
import zipfile
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 256 * 1024 * 1024


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


# ------------------------------------------------------------------------ plist
def inspect_plist(path: str | Path) -> dict[str, Any]:
    """Read an Apple property list in binary, XML or OpenStep form.

    plistlib handles all three; the value added here is the summary an analyst
    wants — top-level keys, the format actually found, and the container shape —
    rather than a bare dict that can bury a 4000-key asset catalogue.
    """
    import plistlib
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    fmt = "unknown"
    if raw[:8] == b"bplist00":
        fmt = "binary"
    elif raw[:6] in (b"bplist",) or b"<plist" in raw[:512]:
        fmt = "xml"
    elif raw.lstrip()[:1] in (b"{", b"(", b"/", b'"'):
        fmt = "openstep"

    try:
        value = plistlib.loads(raw)
    except Exception as exc:  # noqa: BLE001 - a malformed plist is an answer
        return {"ok": False, "path": str(path), "format_detected": fmt,
                "error": f"not a readable plist: {exc}"}

    if isinstance(value, dict):
        shape = "dictionary"
        keys = list(value.keys())
    elif isinstance(value, list):
        shape = "array"
        keys = []
    else:
        shape = type(value).__name__
        keys = []

    return {
        "ok": True,
        "path": str(path),
        "format_detected": fmt,
        "shape": shape,
        "key_count": len(keys),
        "keys": keys[:200],
        "truncated": len(keys) > 200,
    }


# --------------------------------------------------------------------------- pyc
# The .pyc header changed across CPython releases; each entry is
# (header_size, has_hash_based_invalidation, description).
_PYC_LAYOUTS = {
    16: (12, False, "Python 3.3-3.6 (magic, timestamp, source size)"),
    20: (16, False, "Python 3.7+ (magic, flags, timestamp, source size)"),
    21: (16, True, "Python 3.7+ hash-based (magic, flags, source hash)"),
}


def inspect_pyc(path: str | Path) -> dict[str, Any]:
    """Read a CPython .pyc: magic, target version, and the code object's identity.

    The magic number encodes the interpreter version that wrote the file, which is
    the whole reason a .pyc is interesting in an investigation: it says which
    Python produced it, independent of what the source claims.

    Marshalled code objects are *not* fully decoded — that would be a marshal
    interpreter, and running a decoder over attacker-controlled marshal data is
    the same hazard as unpickling it. The header is parsed and the code object's
    top-level fields are read only as far as the string table, which is safe
    because the marshalled form starts with a fixed layout.
    """
    try:
        raw = _read(path, limit=64 * 1024 * 1024)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}
    if len(raw) < 16:
        return {"ok": False, "path": str(path),
                "error": "file too small to be a .pyc"}

    magic = struct.unpack_from("<H", raw, 0)[0]
    # CPython magic is (MAGIC_NUMBER & 0xFFFF) in the first two bytes.
    major_minor = struct.unpack_from("<H", raw, 2)[0]
    if magic < 3000 or magic > 4000:
        # Not conclusive on its own, but a .pyc whose magic is wildly out of range
        # is far more likely to be something else entirely.
        return {"ok": False, "path": str(path),
                "error": f"unrecognized pyc magic 0x{magic:04x}",
                "magic": f"0x{magic:04x}"}

    flags = struct.unpack_from("<I", raw, 4)[0]
    hash_based = bool(flags & 0x01)
    layout = _PYC_LAYOUTS[21] if hash_based else _PYC_LAYOUTS[20]
    header_size, _, layout_note = layout

    # The magic's low byte is a bytecode version, not a Python minor. Since 3.0 the
    # mapping has been simply minor = low_byte - 29: CPython 3.14 writes 0x0e2b, so
    # low byte 43 means 3.14. An earlier version of this computed low_byte - 10 and
    # reported 3.14's files as "Python 3.33", which is not a version that exists.
    bytecode = magic & 0xFF
    minor = bytecode - 29 if 29 < bytecode < 60 else None
    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "magic": f"0x{magic:04x}",
        "bytecode_version": bytecode,
        "python_version_guess": f"3.{minor}" if minor is not None else None,
        "flags": flags,
        "hash_based": hash_based,
        "header_size": header_size,
        "layout": layout_note,
        "file_size": len(raw),
    }
    if hash_based:
        result["source_hash"] = raw[8:16].hex()
    else:
        timestamp = struct.unpack_from("<I", raw, 4 + 4)[0] if header_size >= 12 else 0
        source_size = struct.unpack_from("<I", raw, 12)[0] if header_size >= 16 else 0
        result["source_timestamp"] = (
            _dt.datetime.fromtimestamp(timestamp, _dt.UTC).isoformat()
            if timestamp else None)
        result["source_size"] = source_size

    result["code_payload_offset"] = header_size
    result["code_payload_bytes"] = len(raw) - header_size

    # The first marshalled object is the module code object; its first field after
    # the type tag is the filename string, when the payload is well-formed.
    payload = raw[header_size:]
    if payload[:1] == b"\xe3":  # 'c' = code object, as marshalled by CPython 3.7+
        length = payload[1]
        if length < 0x80 and 2 + length <= len(payload):
            try:
                result["co_filename"] = payload[2:2 + length].decode("utf-8")
            except UnicodeDecodeError:
                pass
    return result


# ---------------------------------------------------------------------- desktop
def inspect_desktop(path: str | Path) -> dict[str, Any]:
    """Read a freedesktop.org .desktop entry (the Linux equivalent of a shortcut).

    REA has `inspect_windows_shortcut` for .lnk. This is the same analyst question
    on Linux: what program does this launcher actually run, and with what
    arguments? The Exec line is the answer, and it is routinely different from
    what the visible Name claims.
    """
    try:
        raw = _read(path, limit=1024 * 1024)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")

    groups: dict[str, dict[str, str]] = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            groups[current] = {}
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        groups[current][key.strip()] = value.strip()

    if "Desktop Entry" not in groups:
        return {"ok": False, "path": str(path),
                "error": "no [Desktop Entry] group — not a desktop entry",
                "groups_found": sorted(groups)}
    entry = groups["Desktop Entry"]
    exec_line = entry.get("Exec", "")
    # The command is the first token; %f/%u/%F/%U are field codes, not arguments.
    command = exec_line.split()[0] if exec_line.strip() else None
    field_codes = [token for token in exec_line.split()
                   if token.startswith("%") and len(token) == 2]
    return {
        "ok": True,
        "path": str(path),
        "groups": sorted(groups),
        "type": entry.get("Type"),
        "name": entry.get("Name"),
        "generic_name": entry.get("GenericName"),
        "exec": exec_line or None,
        "command": command,
        "arguments": exec_line.split()[1:] if exec_line else [],
        "field_codes": field_codes,
        "terminal": entry.get("Terminal", "false").lower() == "true",
        "categories": [c for c in entry.get("Categories", "").split(";") if c],
        "mimetypes": [m for m in entry.get("MimeType", "").split(";") if m],
        "hidden": entry.get("Hidden", "false").lower() == "true",
        "no_display": entry.get("NoDisplay", "false").lower() == "true",
        "try_exec": entry.get("TryExec"),
        "working_directory": entry.get("Path"),
    }


# --------------------------------------------------------------------------- go
_GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def inspect_go_binary(path: str | Path) -> dict[str, Any]:
    """Read Go build info: toolchain version, module path, and dependency list.

    Go embeds a `\\xff Go buildinf:` record in every binary. Two encodings exist:
    the original stored pointers to the version string and module data, and 1.18+
    stores inline varint-prefixed strings. A reader that only knows the newer form
    reports nothing for any binary older than the reader, so both are handled.

    The pointers in the legacy form are virtual addresses; resolving them needs the
    image base, so when they do not land in the file this reports the toolchain
    from whatever is readable and says the module list is unavailable — a partial
    answer, labelled as one.
    """
    try:
        raw = _read(path, limit=512 * 1024 * 1024)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    index = raw.find(_GO_BUILDINFO_MAGIC)
    if index < 0:
        return {"ok": False, "path": str(path),
                "error": "no Go build info record — not a Go binary (or stripped of it)"}
    if index + 32 > len(raw):
        return {"ok": False, "path": str(path),
                "error": "Go build info record is truncated"}

    pointer_size = raw[index + 14]
    flags = raw[index + 15]
    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "buildinfo_offset": index,
        "pointer_size": pointer_size,
        "inline_strings": bool(flags & 0x02),
        "version": None,
        "module": None,
        "dependencies": [],
    }

    if flags & 0x02:
        # 1.18+ layout: version (varint-prefixed string), then a module-info BLOB
        # (varint-prefixed) that begins with a 16-byte build hash and then
        # newline-separated `key\tvalue...` lines. An earlier version of this read
        # the blob as a second "module name" string, so the module path, every
        # dependency and the VCS revision were all missed — the report said
        # `dependencies: []` for a binary that has them.
        cursor = index + 32
        version_len, cursor = _read_uvarint(raw, cursor)
        if 0 <= version_len and cursor + version_len <= len(raw):
            result["version"] = raw[cursor:cursor + version_len].decode("utf-8", "replace")
            cursor += version_len
        else:
            result.setdefault("warnings", []).append("version string runs past end of file")
            return result

        blob_len, cursor = _read_uvarint(raw, cursor)
        if blob_len < 0 or cursor + blob_len > len(raw):
            result.setdefault("warnings", []).append(
                f"module info blob length {blob_len} runs past end of file")
            return result
        blob = raw[cursor:cursor + blob_len]
        # 16-byte build hash prefix, present in every Go 1.18+ record.
        body = blob[16:] if len(blob) > 16 else blob
        _parse_go_module_info(body, result)
    else:
        # Pre-1.18: two pointers followed by a 16-byte module-data header.
        if index + 32 + 16 <= len(raw):
            version_ptr, module_ptr = struct.unpack_from(
                "<QQ" if pointer_size == 8 else "<II", raw, index + 16)
            result["legacy_pointers"] = {"version": version_ptr, "module": module_ptr}
            # Pointers are virtual addresses. A common case is a non-PIE ELF where
            # the file offset equals the address minus a page-aligned base, so try
            # treating them as file offsets before giving up.
            for field, pointer in (("version", version_ptr), ("module", module_ptr)):
                if 0 < pointer < len(raw):
                    end_offset = raw.find(b"\0", pointer, min(len(raw), pointer + 256))
                    if end_offset > pointer:
                        text = raw[pointer:end_offset].decode("utf-8", "replace")
                        if text:
                            result[field] = text
            if result["version"] is None:
                result.setdefault("warnings", []).append(
                    "legacy build info stores pointers that do not resolve to file "
                    "offsets; the version string is unavailable without the image base")
        else:
            result.setdefault("warnings", []).append("legacy build info is truncated")
    return result


def _read_uvarint(raw: bytes, cursor: int) -> tuple[int, int]:
    """Go's encoding/binary.Uvarint. Returns (-1, cursor) on overflow or truncation."""
    result = 0
    shift = 0
    while cursor < len(raw):
        byte = raw[cursor]
        cursor += 1
        if byte < 0x80:
            return result | (byte << shift), cursor
        result |= (byte & 0x7F) << shift
        shift += 7
        if shift >= 64:
            return -1, cursor
    return -1, cursor


def _parse_go_module_info(body: bytes, result: dict[str, Any]) -> None:
    """Parse Go's module-info text records: `key<TAB>value...` per line.

    Record grammar (cmd/go/internal/modinfo):
      path    <module path>
      mod     <module path> <version> [<sum>]
      dep     <module path> <version> [<sum>]
      build   <build setting>
      (a leading `=>` marks a replacement)
    """
    text = body.decode("utf-8", "replace")
    dependencies: list[dict[str, Any]] = []
    build_settings: dict[str, str] = {}
    for line in text.split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        key = parts[0]
        if key in ("path",) and len(parts) > 1:
            result["module_path"] = parts[1]
        elif key == "mod" and len(parts) > 2:
            result["module"] = parts[1]
            result["module_version"] = parts[2]
            if len(parts) > 3 and parts[3]:
                result["module_sum"] = parts[3]
            if parts[1].startswith("=>") or (len(parts) > 4 and parts[4] == "=>"):
                result["module_replaced"] = True
        elif key == "dep" and len(parts) > 2:
            dependencies.append({
                "path": parts[1],
                "version": parts[2],
                "sum": parts[3] if len(parts) > 3 and parts[3] else None,
            })
        elif key == "build" and len(parts) > 1:
            setting = parts[1]
            name, _, value = setting.partition("=")
            build_settings[name] = value
    result["dependencies"] = dependencies
    result["dependency_count"] = len(dependencies)
    result["build_settings"] = build_settings
    # Surface the four settings an analyst checks first, if present.
    for key, field in (("vcs.revision", "vcs_revision"), ("vcs.time", "vcs_time"),
                       ("GOOS", "goos"), ("GOARCH", "goarch"),
                       ("vcs.modified", "vcs_modified")):
        if key in build_settings:
            result[field] = build_settings[key]
    # The module line often carries the real path in `path`, which the `mod` record
    # repeats without the binary name; prefer the first.
    if "module_path" in result and "module" not in result:
        result["module"] = result["module_path"]


# ------------------------------------------------------------------------- rust
_RUST_MARKERS = (
    b"/rustc/", b"rustc version", b"library/std/src/", b"RUST_BACKTRACE",
    b"src/main.rs", b"core::panicking",
)


def inspect_rust_binary(path: str | Path) -> dict[str, Any]:
    """Find Rust build fingerprints in a native binary.

    Rust binaries do not embed a structured version record the way Go does, so this
    reports evidence rather than an identity: which rustc source paths appear, any
    crate names visible in symbols or panic strings, and whether the binary looks
    like a Rust build at all. Saying "Rust, with these markers" is honest; deriving
    a rustc version from a source path hash would not be.
    """
    try:
        raw = _read(path, limit=512 * 1024 * 1024)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    markers = [m.decode("utf-8", "replace") for m in _RUST_MARKERS if m in raw]
    if not markers:
        return {"ok": False, "path": str(path),
                "error": "no Rust markers found",
                "markers_checked": [m.decode() for m in _RUST_MARKERS]}

    # rustc embeds paths like /rustc/<40-hex-commit>/library/std/src/...
    import re
    commits = sorted({m.decode("ascii") for m in
                      re.findall(rb"/rustc/([0-9a-f]{40})/", raw)})
    # Crate names show up in panic messages and symbol names as `name::module`.
    crates = sorted({m.decode("utf-8", "replace") for m in
                     re.findall(rb"\b([a-z][a-z0-9_]{2,30})::[a-z][a-z0-9_:]{2,60}\b",
                                raw)})[:100]
    return {
        "ok": True,
        "path": str(path),
        "markers": markers,
        "rustc_commit": commits[0] if commits else None,
        "rustc_commits": commits,
        "crate_candidates": crates,
        "crate_candidate_count": len(crates),
        "note": "Rust embeds source paths, not a version record; crate candidates "
                "are inferred from symbol and panic strings",
    }


# ------------------------------------------------------------------------ entry
def inspect(path: str | Path) -> dict[str, Any]:
    """Detect which of these formats a file is, and read it.

    Detection is by content, not by extension: an investigator's file rarely has
    the extension the format implies.
    """
    # Sniff a head slice, but never pass the truncated bytes to a parser: the
    # first version of this function capped the read at 4096 and then handed that
    # slice to the same readers, so every real file failed with "file too large"
    # against its own limit. Detection needs a prefix; parsing needs the file.
    try:
        canon = guard.read_guard(path)
        if not canon.is_file():
            return {"ok": False, "path": str(path), "error": "not a regular file"}
        with canon.open("rb") as handle:
            raw = handle.read(4096)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if raw[:8] == b"bplist00" or b"<plist" in raw[:512]:
        return inspect_plist(path)
    if len(raw) >= 16:
        magic, crlf = struct.unpack_from("<HH", raw, 0)
        # A .pyc's third and fourth bytes are a literal CRLF (0x0D 0x0A) on every
        # platform — CPython writes them unconditionally so that a text-mode
        # transfer is detectable. That, plus a plausible magic, identifies a pyc
        # without guessing at the first byte.
        if crlf == 0x0A0D and 3000 <= magic <= 4000:
            return inspect_pyc(path)
    if b"[Desktop Entry]" in raw:
        return inspect_desktop(path)
    if _GO_BUILDINFO_MAGIC in raw:
        return inspect_go_binary(path)
    if raw[:4] == b"\x7fELF" or raw[:2] == b"MZ":
        # A native executable is not one of the four container formats; only the
        # Rust marker scan can still say something useful about it.
        return inspect_rust_binary(path)

    # Last: the Rust check needs a full read, so only run it once the cheap
    # signature checks have failed.
    rust = inspect_rust_binary(path)
    if rust.get("ok"):
        return rust
    return {"ok": False, "path": str(path),
            "error": "unrecognized format (not plist, pyc, desktop entry, Go or Rust)",
            "checked": ["plist", "pyc", "desktop", "go", "rust"]}
