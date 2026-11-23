"""Pattern search across a binary's file bytes — the `re search` verb.

Why this exists
---------------
`re strings` answers "what text is in here" and `re symbols` answers "what is
named here". Neither answers the question that comes *before* a patch, a
signature or a "find the comparison against 0x2a": **where is this byte
sequence**. The engine had no equivalent of REA's `search_bytes`/`read_bytes`.

What a match reports
--------------------
A file offset always, and a virtual address when a section table maps that
offset. A match in bytes no section maps keeps ``va: null`` rather than
inventing an address — the same rule the rest of the engine uses for
file-backed ranges.

Pattern modes
-------------
* ``text`` (default) — literal bytes of the pattern, UTF-8 encoded.
* ``hex`` (``--hex``) — hex bytes, ``??`` matches any single byte.
* ``regex`` (``--regex``) — a Python **bytes** regex, so ``\\x48.{2}\\xc3``
  works and the caller owns the backtracking cost.

Nibble wildcards (``4?``) are deliberately refused instead of half-supported:
expressing them needs a byte-class regex assembled from raw bytes, and a
wildcard that silently matches the wrong nibble is worse than none. ``??``
covers the byte-level case that matters.

An empty result is an answer
----------------------------
No match returns ``ok: true, count: 0``. "This string is not in the binary" is
exactly the fact that was asked for; turning it into an error would hide it.

Overlaps
--------
The scan resumes one byte after each match, so ``aa`` in ``aaaa`` reports three
matches, not two. ``re.finditer`` would under-report, and under-reporting a
signature hit is the failure mode that matters.
"""
from __future__ import annotations

import contextlib
import mmap
import re
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

DEFAULT_LIMIT = 50
DEFAULT_CONTEXT = 16
MAX_LIMIT = 10_000
MAX_CONTEXT = 256
MAX_PATTERN_BYTES = 8_192
# Below this, a full read is cheaper than setting up a mapping.
_MMAP_MIN_BYTES = 1 << 20

_MODES = ("text", "hex", "regex")


class SearchError(ValueError):
    """A pattern or input the search refuses, with a reason the caller can act on."""


def _hex_regex(pattern: str) -> bytes:
    """Compile a hex pattern such as ``48 8b ?? c3`` into a bytes regex.

    Literal bytes are escaped: appending raw bytes to a pattern would let a
    value like ``0x28`` (``(``) act as regex syntax.
    """
    raw = re.sub(r"[\s:_,-]", "", pattern or "")
    if raw[:2].lower() == "0x":
        raw = raw[2:]
    if not raw:
        raise SearchError("empty hex pattern")
    if len(raw) % 2:
        raise SearchError(
            f"hex pattern has an odd number of digits ({len(raw)}): pairs are bytes, "
            f"so '4' is not a pattern — write '04' or '40'")
    parts: list[bytes] = []
    for index in range(0, len(raw), 2):
        pair = raw[index:index + 2]
        if pair == "??":
            parts.append(b".")
            continue
        if "?" in pair:
            raise SearchError(
                f"nibble wildcard {pair!r} at digit {index} is not supported; use '??' "
                f"for a whole wildcard byte, or --regex for a byte class")
        try:
            parts.append(re.escape(bytes([int(pair, 16)])))
        except ValueError:
            raise SearchError(
                f"invalid hex pair {pair!r} at digit {index}") from None
    return b"".join(parts)


def compile_pattern(pattern: str, mode: str = "text", *, ignore_case: bool = False) -> re.Pattern:
    """Return a bytes regex for one of the three modes, refusing the unusable."""
    if mode not in _MODES:
        raise SearchError(f"unknown search mode {mode!r}; expected one of {', '.join(_MODES)}")
    if not pattern:
        raise SearchError(
            "search needs a pattern: --pattern <text>, or --hex with --pattern '48 8b ?? c3'")
    if mode == "hex":
        source = _hex_regex(pattern)
    elif mode == "regex":
        source = pattern.encode("utf-8")
    else:
        source = re.escape(pattern.encode("utf-8"))
    if len(source) > MAX_PATTERN_BYTES:
        raise SearchError(
            f"pattern is {len(source)} bytes; the cap is {MAX_PATTERN_BYTES} "
            f"(a longer pattern is a description of a file, not a search)")
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    try:
        compiled = re.compile(source, flags)
    except re.error as exc:
        raise SearchError(f"invalid pattern: {exc}") from None
    empty = compiled.search(b"")
    if empty is not None and empty.end() == empty.start():
        raise SearchError(
            "pattern can match an empty string, which would match at every offset; "
            "anchor it or add a literal")
    return compiled


def _printable(window: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in window)


def _as_int(value: Any) -> int | None:
    """Parse an int that a JSON boundary may have handed us as hex text."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _map_offset(sections: Iterable[dict[str, Any]], offset: int) -> tuple[int | None, str]:
    """Map a file offset to a virtual address using a section table.

    Two details decide between a correct address and an invented one:

    * the engine reports ``offset`` and ``addr`` as hex **strings** ("0x388"),
      so they are parsed as such rather than with ``int()``;
    * ``file_size`` is what bounds the file-backed bytes. ``.bss`` is
      ``SHT_NOBITS``: it occupies memory, has no bytes in the file, yet reports a
      size and an offset that can overlap a neighbouring section. Trusting
      ``size`` there would attribute a match to a section that cannot contain it,
      which is the same class of bug as the ``.bss`` reads fixed earlier.
    """
    for section in sections:
        kind = str(section.get("type") or "").upper()
        if kind in ("NOBITS", "NULL", "BSS"):
            continue
        start = _as_int(section.get("offset"))
        address = _as_int(section.get("addr"))
        file_size = _as_int(section.get("file_size"))
        if file_size is None:
            file_size = _as_int(section.get("size"))
        if start is None or address is None or file_size is None:
            continue
        if file_size > 0 and start <= offset < start + file_size:
            return address + (offset - start), str(section.get("name") or "")
    return None, ""


@contextlib.contextmanager
def _mapped(path: Path) -> Iterator[Any]:
    """Expose file bytes without loading a 100 MB binary into memory."""
    size = path.stat().st_size
    if size == 0:
        yield b""
        return
    if size < _MMAP_MIN_BYTES:
        yield path.read_bytes()
        return
    with path.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapping:
            yield mapping


def search_file(
    path: str | Path,
    pattern: str,
    *,
    mode: str = "text",
    limit: int = DEFAULT_LIMIT,
    context: int = DEFAULT_CONTEXT,
    ignore_case: bool = False,
    sections: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Scan ``path`` for ``pattern`` and return bounded, address-mapped matches."""
    target = Path(path)
    if not target.exists():
        raise SearchError(f"no such file: {target}")
    if target.is_dir():
        raise SearchError(f"{target} is a directory; search takes one file")
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    context = max(0, min(int(context if context is not None else DEFAULT_CONTEXT), MAX_CONTEXT))
    regex = compile_pattern(pattern, mode, ignore_case=ignore_case)

    started = time.perf_counter()
    rows: list[dict[str, Any]] = []
    truncated = False
    scanned = 0
    with _mapped(target) as data:
        scanned = len(data)
        position = 0
        # The loop ends either by `break` (no further match) or by reaching the
        # limit, which is what the `else` distinguishes: a limit stop is
        # "truncated", a clean end is not.
        while len(rows) < limit:
            match = regex.search(data, position)
            if match is None:
                break
            start, end = match.span()
            if end == start:  # unreachable: empty matches are refused at compile time
                break
            low = max(0, start - context)
            high = min(len(data), end + context)
            window = bytes(data[low:high])
            address, section = _map_offset(sections or (), start)
            rows.append({
                "offset": start,
                "offset_hex": hex(start),
                "va": hex(address) if address is not None else None,
                "section": section or None,
                "length": end - start,
                "window_offset": low,
                "hex": window.hex(" "),
                "ascii": _printable(window),
            })
            position = start + 1
        else:
            if regex.search(data, position) is not None:
                truncated = True

    return {
        "ok": True,
        "path": str(target),
        "mode": mode,
        "pattern": pattern,
        "count": len(rows),
        "truncated": truncated,
        "scanned": scanned,
        "addresses_mapped": bool(list(sections or ())),
        "matches": rows,
        "ms": round((time.perf_counter() - started) * 1000, 2),
    }
