"""Header-only inspection of GGUF and safetensors model files.

This was excluded from the breadth matrix as "different product surface (ML artifacts)". The
exclusion does not survive reading what the REA tool actually does: it parses the GGUF v2/v3
header and the safetensors JSON declaration without a model runtime. Those are documented
binary formats — the same work as every container format this engine already handles — and
there is nothing ML-specific about reading a length-prefixed string table.

Header-only is not a shortcut here, it is the requirement. The artifacts on this host run to
2 GB and the useful facts (architecture, quantisation, tensor list, parameter count) are all in
the first few kilobytes. Nothing in this module reads tensor weights unless explicitly asked,
and `full_hash` streams rather than loading.

Where a field is unknown this reports the raw value instead of guessing a name, because an
invented architecture label is worse than `general.architecture=99`.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

MAX_HEADER_BYTES = 64 * 1024 * 1024
MAX_TENSORS = 4096
GGUF_MAGIC = b"GGUF"
# GGUF v1 is byte-incompatible with v2/v3 (uint32 counts, no alignment field) and is not
# reported as if it were readable — an honest refusal beats a wrong parse.
GGUF_SUPPORTED = (2, 3)

# GGUF metadata value types, from the format specification. type -> (name, struct format).
_GGUF_SCALARS = {
    0: ("uint8", "<B"), 1: ("int8", "<b"), 2: ("uint16", "<H"), 3: ("int16", "<h"),
    4: ("uint32", "<I"), 5: ("int32", "<i"), 6: ("float32", "<f"), 7: ("bool", "<?"),
    10: ("uint64", "<Q"), 11: ("int64", "<q"), 12: ("float64", "<d"),
}
_GGUF_STRING = 8
_GGUF_ARRAY = 9


class _Reader:
    """A bounds-checked cursor over the file header.

    Every read is length-checked against the bytes actually loaded. The alternative — trusting
    declared counts — is how a 4-byte header turns into a 40 GB allocation when a file is
    truncated or hostile.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise ValueError(f"truncated header: wanted {count} byte(s) at "
                             f"offset {self.offset}, have {len(self.data) - self.offset}")
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    def scalar(self, fmt: str) -> Any:
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.take(size))[0]

    def string(self) -> str:
        length = self.scalar("<Q")
        if length > MAX_HEADER_BYTES:
            raise ValueError(f"declared string length {length} exceeds the header budget")
        return self.take(length).decode("utf-8", "replace")


def _gguf_value(reader: _Reader, value_type: int, depth: int = 0) -> Any:
    if depth > 4:
        raise ValueError("metadata nesting deeper than 4 levels")
    if value_type == _GGUF_STRING:
        return reader.string()
    if value_type == _GGUF_ARRAY:
        item_type = reader.scalar("<I")
        count = reader.scalar("<Q")
        if count > 1_000_000:
            raise ValueError(f"declared array length {count} is implausible")
        # Preview long arrays: the whole embedding vocabulary is not useful, and materialising
        # it would defeat the point of a header read.
        preview = [_gguf_value(reader, item_type, depth + 1) for _ in range(min(count, 8))]
        for _ in range(max(0, count - 8)):
            _gguf_value(reader, item_type, depth + 1)
        return {"count": count, "preview": preview,
                "truncated": count > len(preview)}
    entry = _GGUF_SCALARS.get(value_type)
    if entry is None:
        raise ValueError(f"unknown metadata value type {value_type}")
    return reader.scalar(entry[1])


def _tensor_element_size(kind: int) -> int | None:
    """Bytes per element for the quantisation types in the GGUF spec.

    Returns None for types this build does not know, and the caller reports the type number
    rather than inventing a size — a fabricated element size turns into a fabricated parameter
    count.
    """
    table = {
        0: 4, 1: 2, 2: 18 / 32, 3: 20 / 32, 6: 22 / 32, 7: 24 / 32, 8: 34 / 32, 9: 36 / 32,
        10: 26 / 32, 11: 28 / 32, 12: 28 / 32, 13: 30 / 32, 14: 32 / 32, 15: 34 / 32,
        16: 36 / 32, 17: 38 / 32, 18: 40 / 32, 19: 42 / 32, 20: 20 / 32, 21: 22 / 32,
        22: 24 / 32, 23: 26 / 32, 24: 1, 25: 2, 26: 4, 27: 8, 28: 8, 29: 8, 30: 2,
    }
    return table.get(kind)


def _quantisation_name(kind: int) -> str:
    names = {
        0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1", 8: "Q8_0",
        9: "Q8_1", 10: "Q2_K", 11: "Q3_K", 12: "Q4_K", 13: "Q5_K", 14: "Q6_K",
        15: "Q8_K", 16: "IQ2_XXS", 17: "IQ2_XS", 18: "IQ3_XXS", 19: "IQ1_S",
        20: "IQ4_NL", 21: "IQ3_S", 22: "IQ2_S", 23: "IQ4_XS", 24: "I8", 25: "I16",
        26: "I32", 27: "I64", 28: "F64", 29: "IQ1_M", 30: "BF16",
    }
    return names.get(kind, f"type-{kind}")


def inspect_gguf(path: Path, *, full_hash: bool = False) -> dict[str, Any]:
    """Parse the GGUF v2/v3 header without reading tensor weights."""
    with path.open("rb") as handle:
        # 4 magic + 4 version + 8 tensor count + 8 kv count is the fixed prefix.
        head = handle.read(24)
        if len(head) < 24:
            return {"ok": False, "format": "gguf",
                    "error": f"file is too short for a GGUF header ({len(head)} bytes)"}
        magic, version = struct.unpack("<4sI", head[:8])
        if magic != GGUF_MAGIC:
            return {"ok": False, "format": "gguf",
                    "error": f"not a GGUF file: magic is {magic!r}"}
        if version not in GGUF_SUPPORTED:
            # v1 uses uint32 counts and no alignment field; v4 does not exist. Parsing either
            # with the v2/v3 layout would produce plausible nonsense.
            return {"ok": False, "format": "gguf", "version": version,
                    "error": f"GGUF v{version} is not supported (v2 and v3 are)"}
        tensor_count, kv_count = struct.unpack("<QQ", head[8:24])
        if tensor_count > MAX_TENSORS:
            return {"ok": False, "format": "gguf", "version": version,
                    "error": f"declared tensor count {tensor_count} exceeds the "
                             f"{MAX_TENSORS} limit"}

        header = handle.read(MAX_HEADER_BYTES)
    reader = _Reader(head + header)
    reader.offset = 24

    metadata: dict[str, Any] = {}
    try:
        for _ in range(kv_count):
            key = reader.string()
            value_type = reader.scalar("<I")
            metadata[key] = _gguf_value(reader, value_type)
    except ValueError as exc:
        return {"ok": False, "format": "gguf", "version": version, "error": str(exc)}

    tensors: list[dict[str, Any]] = []
    try:
        for _ in range(min(tensor_count, MAX_TENSORS)):
            name = reader.string()
            dimensions = reader.scalar("<I")
            if dimensions > 8:
                raise ValueError(f"tensor {name!r} declares {dimensions} dimensions")
            shape = [reader.scalar("<Q") for _ in range(dimensions)]
            kind = reader.scalar("<I")
            offset = reader.scalar("<Q")
            element = _tensor_element_size(kind)
            parameters = 1
            for extent in shape:
                parameters *= extent
            tensors.append({
                "name": name, "shape": shape, "type": _quantisation_name(kind),
                "type_id": kind, "offset": offset,
                "parameters": parameters,
                "bytes": int(parameters * element) if element is not None else None,
            })
    except ValueError as exc:
        return {"ok": False, "format": "gguf", "version": version, "error": str(exc)}

    total = sum(item["parameters"] for item in tensors)
    counted = sum(1 for item in tensors if item["bytes"] is not None)
    report: dict[str, Any] = {
        "ok": True, "format": "gguf", "version": version, "path": str(path),
        "size_bytes": path.stat().st_size,
        "alignment": metadata.get("general.alignment", 32),
        "tensor_count": len(tensors),
        "tensor_count_declared": tensor_count,
        "metadata_count": len(metadata),
        "parameter_count": total,
        "quantisations": sorted({item["type"] for item in tensors}),
        "tensors": tensors[:80],
        "tensors_truncated": len(tensors) > 80,
        "metadata": {key: value for key, value in list(metadata.items())[:80]},
        "metadata_truncated": len(metadata) > 80,
        "note": "header only; tensor weights were not read",
    }
    if counted < len(tensors):
        # Say so rather than reporting a total that silently ignores unknown quantisation types.
        report["note"] += (f"; {len(tensors) - counted} tensor(s) use a quantisation type this "
                          "build does not size, so bytes and parameter totals are partial")
        report["byte_totals_complete"] = False
    else:
        report["byte_totals_complete"] = True
    if metadata.get("general.architecture"):
        report["architecture"] = metadata["general.architecture"]
    if metadata.get("general.name"):
        report["name"] = metadata["general.name"]
    if full_hash:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                digest.update(block)
        report["sha256"] = digest.hexdigest()
    return report


def inspect_safetensors(path: Path, *, full_hash: bool = False) -> dict[str, Any]:
    """Parse the safetensors JSON header: tensor names, dtypes, shapes and offsets."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        prefix = handle.read(8)
        if len(prefix) < 8:
            return {"ok": False, "format": "safetensors",
                    "error": "file is too short to hold a header length"}
        declared = struct.unpack("<Q", prefix)[0]
        if declared == 0:
            return {"ok": False, "format": "safetensors",
                    "error": "declared header length is zero"}
        if declared > MAX_HEADER_BYTES:
            return {"ok": False, "format": "safetensors",
                    "error": f"declared header length {declared} exceeds the budget"}
        if 8 + declared > size:
            return {"ok": False, "format": "safetensors",
                    "error": f"declared header length {declared} runs past the end of a "
                             f"{size}-byte file"}
        raw = handle.read(declared)
    try:
        header = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"ok": False, "format": "safetensors",
                "error": f"header is not valid JSON: {exc}"}
    if not isinstance(header, dict):
        return {"ok": False, "format": "safetensors",
                "error": "header JSON is not an object"}

    # `__metadata__` is the one non-tensor key by the format's contract.
    declared_metadata = header.get("__metadata__") or {}
    tensors: list[dict[str, Any]] = []
    problems: list[str] = []
    for name, entry in list(header.items())[:MAX_TENSORS]:
        if name == "__metadata__":
            continue
        if not isinstance(entry, dict):
            problems.append(f"{name}: entry is not an object")
            continue
        offsets = entry.get("data_offsets")
        shape = entry.get("shape")
        dtype = entry.get("dtype")
        if not (isinstance(offsets, list) and len(offsets) == 2):
            problems.append(f"{name}: data_offsets missing or malformed")
            continue
        begin, end = offsets
        tensors.append({
            "name": name, "dtype": dtype, "shape": shape,
            "begin": begin, "end": end,
            "bytes": (end - begin) if isinstance(begin, int) and isinstance(end, int) else None,
        })

    data_start = 8 + declared
    overrun = [item["name"] for item in tensors
               if item["bytes"] is not None and data_start + item["end"] > size]
    report: dict[str, Any] = {
        "ok": True, "format": "safetensors", "path": str(path),
        "size_bytes": size,
        "header_bytes": declared,
        "data_offset": data_start,
        "tensor_count": len(tensors),
        "dtypes": sorted({item["dtype"] for item in tensors if item["dtype"]}),
        "metadata": declared_metadata,
        "tensors": tensors[:80],
        "tensors_truncated": len(tensors) > 80,
        "note": "header only; tensor data was not read",
    }
    if problems:
        report["problems"] = problems[:20]
        report["problem_count"] = len(problems)
    if overrun:
        # A declaration that points past EOF means the file was truncated or the header lies.
        report["truncated_tensors"] = overrun[:10]
        report["truncated_count"] = len(overrun)
    if full_hash:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                digest.update(block)
        report["sha256"] = digest.hexdigest()
    return report


def inspect(path: str | Path, *, full_hash: bool = False, **_: Any) -> dict[str, Any]:
    """Detect the model format from its first bytes and dispatch."""
    target = Path(str(path))
    if not target.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    try:
        with target.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    if magic == GGUF_MAGIC:
        return inspect_gguf(target, full_hash=full_hash)
    if len(magic) == 4:
        with target.open("rb") as handle:
            length = struct.unpack("<Q", handle.read(8))[0]
        # A safetensors header is JSON and therefore starts with `{`. Checking the declared
        # length alone would accept almost any file whose first eight bytes happen to be small.
        if 0 < length < MAX_HEADER_BYTES and 8 + length <= target.stat().st_size:
            with target.open("rb") as handle:
                handle.seek(8)
                if handle.read(1) == b"{":
                    return inspect_safetensors(target, full_hash=full_hash)
    return {"ok": False, "error": f"not a GGUF or safetensors model: {path}",
            "magic": magic.hex(), "hint": "GGUF files start with 'GGUF'"}


def inspect_gpu_code(path: str | Path, **_: Any) -> dict[str, Any]:
    """Look for GPU code objects inside a container.

    GPU blobs are architecture-specific machine code (PTX, SASS, AMDGPU) and differ in ways a
    header cannot settle; this reports the sections that look like code objects and their sizes,
    and says plainly that it has not decoded them.
    """
    target = Path(str(path))
    if not target.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    try:
        with target.open("rb") as handle:
            head = handle.read(4 * 1024 * 1024)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    markers = {
        "ptx": b".version ",
        "amdgpu": b"\x7fELF",
        "cubin": b"\x7fELF",
        "fatbin": b"\x50\xed\x55\xba",
    }
    found = []
    for name, needle in markers.items():
        index = head.find(needle)
        if index >= 0:
            found.append({"kind": name, "offset": index})
    return {"ok": True, "path": str(target), "size_bytes": target.stat().st_size,
            "candidates": found,
            "note": ("markers only; GPU code objects are not decoded. "
                     "an ELF match may be a host binary rather than device code")}
