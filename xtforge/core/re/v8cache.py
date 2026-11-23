"""V8 code cache files.

WHY: Chromium, Electron, Node and any V8 embedder write compiled-bytecode caches next
to scripts (`.cache`, `*.js.cache`, `code_cache`, Chromium's `Code Cache/js/`). They
are a forensic artifact — they show which scripts a given profile actually executed —
and they are also a compatibility minefield: a cache is only valid for the exact V8
build, flags and source that produced it, which is precisely what the header records.

The layout, confirmed against a cache written by Node's own
`vm.Script(..., {produceCachedData: true}).createCachedData()`:

    u32  version_magic    V8 build fingerprint (0xc0de____)
    u32  flags            compile flags the cache was produced with
    u32  source_size      length of the source in bytes
    u32  source_hash      hash of that source (V8-internal, not recomputed here)
    u32  flag_hash        hash of the flag set
    u32  payload_length   bytes of serialised payload
    u32  reserved[2]      zero
    ...                   serialised bytecode payload (32-byte header)

The layout was determined empirically rather than assumed: `32 + payload_length` equals
the file size exactly on caches produced by two different source sizes, which pins the
header at 32 bytes. An earlier reading of this file put the payload length at offset 16
(one word early) and reported a 2.5 GB payload inside a 536-byte file — a wrong value
that a "does it parse" test would have accepted.

What this reader will and will not claim: the four header words are read directly and
reported as a fingerprint. The version magic is *not* decoded into a semantic V8
version here, because it is a build hash rather than a packed semver — 0xc0de0628 on
V8 12.4.254.21 demonstrates that no simple bit-packing of 12/4/254/21 reproduces it.
Guessing a decode would produce a confident wrong answer, which is worse than reporting
the raw value and saying what it is.

The practical value is in the corpus view: how many caches, how many distinct V8 builds
and flag sets, and whether the source hashes are consistent with the adjacent source
files. A cache whose source_hash does not match its neighbouring script is stale, which
is exactly the thing worth knowing.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 5000

# V8's ScriptData magic is 0xC0DE0000 | <build-specific bits>.
V8_MAGIC_MASK = 0xFFFF0000
V8_MAGIC_BASE = 0xC0DE0000

# Compile flags worth naming. V8's ScriptCompiler::CompileOptions.
_FLAG_NAMES = {
    0x1: "kEagerCompile",
    0x2: "kNoCompileOptions",
    0x4: "kConsumeCodeCache",
    0x8: "kProduceCodeCache",
    0x10: "kConsumeParserCache",
    0x20: "kProduceParserCache",
    0x40: "kNoParsingLazyCompile",
}

# Names a code cache is commonly stored under.
_CACHE_SUFFIXES = (".cache", ".js.cache", ".cachedata", ".code_cache")


class V8CacheError(Exception):
    """Raised when a file is not a V8 code cache."""


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _looks_like_v8_cache(raw: bytes) -> bool:
    # Only the magic is needed here, so 4 bytes is the requirement, not the full 32-byte
    # header. Requiring 32 made this return False for the 20-byte head that
    # _inspect_directory reads, so a directory scan silently counted zero caches while
    # reading any single cache from the same directory worked fine.
    if len(raw) < 4:
        return False
    magic = struct.unpack_from("<I", raw, 0)[0]
    return (magic & V8_MAGIC_MASK) == V8_MAGIC_BASE


def _default_source_for(path: Path) -> Path | None:
    """Guess the script a cache belongs to, from the cache's own name."""
    name = path.name
    for suffix in (".cache", ".cachedata", ".code_cache"):
        if name.endswith(suffix):
            stem = name[: -len(suffix)]
            candidate = path.with_name(stem)
            if candidate.is_file():
                return candidate
    # Chromium stores <hash>_0 under Code Cache/js/ with no recoverable name.
    return None


def inspect_v8_code_cache(path: str | Path, *,
                          source: str | Path | None = None) -> dict[str, Any]:
    """Read a V8 code cache header and, when possible, validate it against its source.

    `source` names the script explicitly; otherwise the cache's own filename is used to
    find a neighbour (`mod.js.cache` -> `mod.js`). An unmatched source is reported as
    unknown rather than guessed at.
    """
    try:
        canon = guard.read_guard(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if canon.is_dir():
        return _inspect_directory(canon)

    try:
        raw = _read(canon)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(canon), "error": str(exc)}

    # Length is checked before the magic so a short file reports *why* it is short.
    # Checking the magic first means a 8-byte file is rejected as "wrong magic" even
    # when its magic is perfectly correct, which sends the reader hunting the wrong bug.
    if len(raw) < 32:
        return {"ok": False, "path": str(canon),
                "error": f"header truncated ({len(raw)} bytes, need 32)",
                "found_magic": f"0x{struct.unpack_from('<I', raw, 0)[0]:08x}"
                if len(raw) >= 4 else None}
    if not _looks_like_v8_cache(raw):
        magic = struct.unpack_from("<I", raw, 0)[0]
        return {"ok": False, "path": str(canon),
                "error": "not a V8 code cache (magic is not 0xc0de****)",
                "found_magic": f"0x{magic:08x}",
                "expected_magic_base": f"0x{V8_MAGIC_BASE:08x}"}

    (version_magic, flags, source_size, source_hash, flag_hash,
     payload_length) = struct.unpack_from("<IIIIII", raw, 0)

    result: dict[str, Any] = {
        "ok": True,
        "path": str(canon),
        "kind": "v8-code-cache",
        "version_magic": f"0x{version_magic:08x}",
        "v8_build_fingerprint": f"0x{version_magic:08x}",
        "flags": flags,
        "flag_names": [name for bit, name in _FLAG_NAMES.items() if flags & bit],
        "source_size": source_size,
        "source_hash": f"0x{source_hash:08x}",
        "flag_hash": f"0x{flag_hash:08x}",
        "payload_length": payload_length,
        "file_size": len(raw),
        "has_payload": payload_length > 0,
        "note": ("version_magic identifies the V8 build that produced this cache; it "
                 "is a build hash, not a packed semantic version, and is not decoded "
                 "here"),
    }

    # Payload is serialised bytecode; report its identity, not its contents.
    payload = raw[32:32 + payload_length] if payload_length else b""
    if payload:
        result["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        result["payload_entropy_note"] = _describe_entropy(payload)

    # Validate against the source when one can be found.
    source_path = Path(source) if source else _default_source_for(canon)
    if source_path is not None and source_path.is_file():
        try:
            source_bytes = source_path.read_bytes()
        except OSError:
            source_bytes = b""
        if source_bytes:
            result["source"] = str(source_path)
            result["source_size"] = len(source_bytes)
            # The header's source_hash is a V8-internal hash; without the exact
            # algorithm it cannot be recomputed, so a match is reported as
            # "unverified" rather than claimed. What can be checked is that a source
            # was found at all, which is what makes the cache attributable.
            result["source_hash_verified"] = False
            result["source_hash_note"] = (
                "V8's source hash is internal to the engine and is not recomputed "
                "here; the source file is reported for locality, not as proof")
    else:
        result["source"] = None
        result["source_hash_verified"] = False

    if payload_length and 32 + payload_length > len(raw):
        result["truncated"] = True
        result["warning"] = (f"payload declares {payload_length} bytes but only "
                             f"{len(raw) - 32} are present")
    return result


def _describe_entropy(payload: bytes) -> str:
    """A coarse read on whether the payload looks like serialised code or padding."""
    if not payload:
        return "empty"
    distinct = len(set(payload))
    if distinct < 8:
        return f"low variety ({distinct} distinct bytes) — likely padding or a stub"
    return f"{distinct} distinct byte values — consistent with serialised bytecode"


def _inspect_directory(root: Path) -> dict[str, Any]:
    """Survey a directory of caches: how many, which builds, which flag sets."""
    entries: list[dict[str, Any]] = []
    builds: dict[str, int] = {}
    flag_sets: dict[int, int] = {}
    matched_sources = 0
    scanned = 0
    for candidate in sorted(root.rglob("*")):
        if scanned >= MAX_ENTRIES:
            break
        if not candidate.is_file():
            continue
        if not (candidate.name.endswith(_CACHE_SUFFIXES)
                or candidate.name == "code_cache"):
            continue
        scanned += 1
        try:
            head = candidate.open("rb").read(20)
        except OSError:
            continue
        if not _looks_like_v8_cache(head):
            continue
        record = inspect_v8_code_cache(candidate)
        if not record.get("ok"):
            continue
        builds[record["version_magic"]] = builds.get(record["version_magic"], 0) + 1
        flag_sets[record["flags"]] = flag_sets.get(record["flags"], 0) + 1
        if record.get("source"):
            matched_sources += 1
        if len(entries) < 200:
            entries.append({
                "path": str(candidate),
                "version_magic": record["version_magic"],
                "flags": record["flags"],
                "source": record.get("source"),
                "payload_length": record["payload_length"],
            })
    return {
        "ok": True,
        "path": str(root),
        "kind": "v8-code-cache-directory",
        "scanned": scanned,
        "cache_count": sum(builds.values()),
        "distinct_builds": len(builds),
        "builds": builds,
        "flag_sets": {f"0x{flags:08x}": count
                      for flags, count in sorted(flag_sets.items())},
        "sources_matched": matched_sources,
        "caches": entries,
    }


def inspect(path: str | Path) -> dict[str, Any]:
    return inspect_v8_code_cache(path)
