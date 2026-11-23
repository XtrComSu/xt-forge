"""WebAssembly module identification and inventory.

Reads the core module header and section table straight from the bytes: magic,
version, section list, entry counts, and the import/export name tables. This is
the identification layer, not a disassembler — function bodies are skipped by
design. Every structural fault raises ValueError with the byte offset involved;
nothing here executes or interprets module code.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

MAGIC_HEX = "0061736d"
HEADER_BYTES = 8

# WebAssembly core section ids (0 = custom, 12 = data count, 13 = tag).
SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "data_count", 13: "tag",
}

EXTERNAL_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}

# Section id -> key in the returned counts map.
COUNT_SECTIONS = {1: "types", 2: "imports", 3: "functions",
                  7: "exports", 10: "code", 11: "data"}
# Sections whose header carries an entry count that must be read correctly even
# though the inventory does not surface it in `counts`.
COUNT_ONLY_SECTIONS = frozenset({4, 5, 6, 9, 12})

MAX_SECTIONS = 4096
MAX_ENTRIES = 1000
MAX_NAME_BYTES = 4096
U32_BYTES = 5
U64_BYTES = 10


def _read_uleb(data: bytes, pos: int, end: int, *, max_bytes: int = U32_BYTES,
               max_bits: int = 32, label: str = "u32") -> tuple[int, int]:
    """Decode an unsigned LEB128 within [pos, end), refusing overflow and overrun."""
    value = 0
    for index in range(max_bytes):
        if pos >= end:
            raise ValueError(f"truncated {label} LEB128 at offset {pos}")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            if value >= (1 << max_bits):
                raise ValueError(f"{label} LEB128 overflow at offset {pos - 1}")
            return value, pos
    raise ValueError(f"{label} LEB128 exceeds {max_bytes} bytes at offset {pos}")


def _read_u64(data: bytes, pos: int, end: int) -> tuple[int, int]:
    """64-bit variant of the bounded LEB128 decoder (10-byte ceiling)."""
    return _read_uleb(data, pos, end, max_bytes=U64_BYTES,
                      max_bits=64, label="u64")


class _Parser:
    """Bounded cursor over a module, with the inventory accumulated as it reads."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.end = len(data)
        self.sections: list[dict[str, Any]] = []
        self.counts: dict[str, int] = {key: 0 for key in COUNT_SECTIONS.values()}
        self.imports: list[dict[str, Any]] = []
        self.exports: list[dict[str, Any]] = []
        self.truncated = False

    def u32(self) -> int:
        value, self.pos = _read_uleb(self.data, self.pos, self.end)
        return value

    def take(self, size: int, what: str) -> bytes:
        end = self.pos + size
        if end > self.end:
            raise ValueError(
                f"{what} at offset {self.pos} runs past section end at offset {self.end}")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def name(self) -> str:
        length = self.u32()
        if self.pos + length > self.end:
            raise ValueError(
                f"name at offset {self.pos} declares {length} bytes past section "
                f"end at offset {self.end}")
        if length > MAX_NAME_BYTES:
            self.truncated = True
        raw = self.data[self.pos:self.pos + min(length, MAX_NAME_BYTES)]
        self.pos += length
        return raw.decode("utf-8", "replace")


def _skip_limits(parser: _Parser) -> None:
    flags = parser.u32()
    parser.u32()  # minimum
    if flags & 0x01:
        parser.u32()  # maximum


def _parse_imports(parser: _Parser, count: int) -> None:
    for _ in range(count):
        if len(parser.imports) >= MAX_ENTRIES:
            parser.truncated = True
            return
        module = parser.name()
        name = parser.name()
        kind_code = parser.take(1, "import kind")[0]
        if kind_code == 0:          # func: type index
            parser.u32()
        elif kind_code == 1:        # table: element type + limits
            parser.take(1, "table element type")
            _skip_limits(parser)
        elif kind_code == 2:        # memory: limits
            _skip_limits(parser)
        elif kind_code == 3:        # global: value type + mutability
            parser.take(2, "global type")
        else:
            raise ValueError(f"unknown import kind {kind_code} at offset {parser.pos - 1}")
        parser.imports.append({"module": module, "name": name,
                               "kind": EXTERNAL_KINDS[kind_code]})


def _parse_exports(parser: _Parser, count: int) -> None:
    for _ in range(count):
        if len(parser.exports) >= MAX_ENTRIES:
            parser.truncated = True
            return
        name = parser.name()
        kind_code = parser.take(1, "export kind")[0]
        index = parser.u32()
        parser.exports.append({"name": name,
                               "kind": EXTERNAL_KINDS.get(kind_code, "unknown"),
                               "index": index})


def _parse_body(parser: _Parser, section_id: int) -> None:
    if section_id in COUNT_SECTIONS:
        count = parser.u32()
        parser.counts[COUNT_SECTIONS[section_id]] = count
        if section_id == 2:
            _parse_imports(parser, count)
        elif section_id == 7:
            _parse_exports(parser, count)
    elif section_id in COUNT_ONLY_SECTIONS:
        parser.u32()
    # custom (0) and start (8) bodies carry no entry count to inventory.


def _parse_sections(parser: _Parser) -> None:
    data = parser.data
    total = len(data)
    parser.pos = HEADER_BYTES
    while parser.pos < total:
        offset = parser.pos
        if total - offset < 2:
            raise ValueError(f"trailing bytes at offset {offset}: incomplete section header")
        section_id = data[offset]
        parser.pos = offset + 1
        section_size, parser.pos = _read_uleb(data, parser.pos, total)
        body_start = parser.pos
        body_end = body_start + section_size
        if body_end > total:
            raise ValueError(
                f"section at offset {offset}: declared size {section_size} runs past "
                f"end of file at offset {body_end} (file size {total})")
        if len(parser.sections) >= MAX_SECTIONS:
            parser.truncated = True
        else:
            parser.sections.append({"id": section_id,
                                    "name": SECTION_NAMES.get(section_id, "unknown"),
                                    "offset": offset, "size": section_size})

        parser.pos, parser.end = body_start, body_end
        _parse_body(parser, section_id)
        # Unparsed tails of other section bodies are deliberately skipped, but
        # bounds were enforced by the cursor while reading the entry count.
        parser.end, parser.pos = total, body_end


def inspect(path: str | Path) -> dict[str, Any]:
    """Inventory a WebAssembly module at `path`.

    Raises ValueError for a non-wasm magic, a short header, a malformed LEB128,
    a section running past the file, or trailing bytes after the last section.
    """
    data = Path(path).read_bytes()
    found = data[:4].hex()
    if found != MAGIC_HEX:
        raise ValueError(
            f"not a WebAssembly module: expected magic {MAGIC_HEX}, found {found}")
    if len(data) < HEADER_BYTES:
        raise ValueError(
            f"truncated WebAssembly header at offset {len(data)}: "
            f"expected {HEADER_BYTES} bytes")
    version = int.from_bytes(data[4:8], "little")

    parser = _Parser(data)
    _parse_sections(parser)
    return {
        "ok": True,
        "path": str(path),
        "format": "wasm",
        "version": version,
        "size": len(data),
        "magic_ok": True,
        "sections": parser.sections,
        "counts": parser.counts,
        "imports": parser.imports,
        "exports": parser.exports,
        "truncated": parser.truncated,
    }


def compare(left: str | Path, right: str | Path) -> dict[str, Any]:
    """Compare two WebAssembly modules' public interfaces.

    WHY this is separate from `inspect`: the question a caller asks about a WASM
    artifact is usually "did the interface change", which is a set difference over
    exports (and, for a host ABI, imports), not a second inventory. REA exposes
    `compare_wasm_interfaces`; this answers it without diffing bytes, because a
    recompiled module differs in every byte while its interface is identical.

    Both sides are inventoried first, so a malformed module on either side is
    reported as an error rather than compared as an empty interface — an empty
    comparison would read as "nothing changed", which is the wrong conclusion.
    """
    def load(target: str | Path) -> tuple[dict[str, Any] | None, str | None]:
        try:
            return inspect(target), None
        except (OSError, ValueError) as exc:
            return None, str(exc)

    left_report, left_error = load(left)
    right_report, right_error = load(right)
    if left_error or right_error:
        return {
            "ok": False,
            "error": f"cannot compare: {left_error or right_error}",
            "left_error": left_error,
            "right_error": right_error,
        }

    def export_map(report: dict[str, Any]) -> dict[str, str]:
        return {e["name"]: e.get("kind") for e in report["exports"]}

    def import_map(report: dict[str, Any]) -> dict[tuple[str, str], str]:
        return {(i["module"], i["name"]): i.get("kind") for i in report["imports"]}

    left_exports, right_exports = export_map(left_report), export_map(right_report)
    added = sorted(set(right_exports) - set(left_exports))
    removed = sorted(set(left_exports) - set(right_exports))
    common = sorted(set(left_exports) & set(right_exports))
    changed = [
        {"name": name, "left_kind": left_exports[name],
         "right_kind": right_exports[name]}
        for name in common if left_exports[name] != right_exports[name]
    ]

    left_imports, right_imports = import_map(left_report), import_map(right_report)
    imports_added = sorted(
        [f"{module}.{name}" for (module, name) in set(right_imports) - set(left_imports)])
    imports_removed = sorted(
        [f"{module}.{name}" for (module, name) in set(left_imports) - set(right_imports)])

    identical = (not added and not removed and not changed
                 and not imports_added and not imports_removed)
    return {
        "ok": True,
        "left": {"path": str(left), "exports": len(left_exports),
                 "imports": len(left_imports)},
        "right": {"path": str(right), "exports": len(right_exports),
                  "imports": len(right_imports)},
        "interface_identical": identical,
        "exports_added": added,
        "exports_removed": removed,
        "exports_common": len(common),
        "exports_kind_changed": changed,
        "imports_added": imports_added,
        "imports_removed": imports_removed,
        "summary": ("interfaces are identical" if identical else
                    f"{len(added)} added, {len(removed)} removed, "
                    f"{len(changed)} kind-changed, "
                    f"{len(imports_added) + len(imports_removed)} import changes"),
    }
