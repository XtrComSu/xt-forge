"""Atomic batch renames for the RE annotation overlay.

WHY: REA exposes ``set_addresses_names`` (rename many addresses in one call), but
this engine's ``annotate()`` commits after every single rename. A batch that dies
halfway therefore leaves a half-renamed binary with no way to tell which edits
landed. Both helpers here validate the entire batch *before* opening the
database and write it inside one transaction, so a merge is all-or-nothing:
either every name is visible through ``annotate(action="list")`` or none are.
"""
from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .annotate import _connect, binary_sha256, parse_rva

MAX_RENAMES = 5000
KIND = "rename"


def rename_many(
    binary: str | Path,
    mapping: Mapping[str | int, str] | Iterable[tuple[str | int, str]],
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Apply a batch of address renames in a single all-or-nothing transaction.

    WHY: validate everything first, then write once. Rejecting a duplicate
    address or a blank name after the first INSERT would leave earlier renames
    committed, which is exactly the partial-edit failure this module exists to
    prevent. The rollback on write errors gives the same guarantee for database
    failures.

    Args:
        binary: Path whose SHA-256 keys the overlay row.
        mapping: ``{address: name}`` or an iterable of ``(address, name)`` pairs.
        db_path: Overlay database, defaulting to the engine's overlay path.

    Returns:
        ``{"ok": True, "sha256": ..., "count": n, "applied": [...], "engine": "python"}``.

    Raises:
        ValueError: If the batch is too large, an address does not parse, a name
            is blank, an address repeats, or a name repeats. The message names
            the offending value and how to fix it.
    """
    if isinstance(mapping, Mapping):
        raw_items: list[tuple[Any, Any]] = list(mapping.items())
    else:
        raw_items = []
        for position, pair in enumerate(mapping):
            try:
                address, name = pair
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"invalid rename pair at position {position}: {pair!r}; "
                    f"use (address, name) two-tuples, e.g. (0x1130, 'handler')"
                ) from exc
            raw_items.append((address, name))

    if len(raw_items) > MAX_RENAMES:
        raise ValueError(
            f"too many renames: {len(raw_items)} requested, maximum is {MAX_RENAMES}; "
            f"split the batch into calls of at most {MAX_RENAMES} renames"
        )

    # Normalise and validate the whole batch before touching the database.
    normalized: list[tuple[int, str]] = []
    seen_addresses: dict[int, Any] = {}
    seen_names: dict[str, int] = {}
    for position, (address, name) in enumerate(raw_items):
        try:
            rva = parse_rva(address)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"invalid address {address!r} at position {position}: {exc}; "
                f"use an integer or a 0x-prefixed hex string such as 0x1130"
            ) from exc

        if rva in seen_addresses:
            raise ValueError(
                f"duplicate address {address!r} ({hex(rva)}); an address may be "
                f"renamed only once per call, so merge the names or split into "
                f"two calls (first seen as {seen_addresses[rva]!r})"
            )

        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError(
                f"empty name for address {address!r} ({hex(rva)}); supply a "
                f"non-empty name or drop this rename from the batch"
            )
        if clean_name in seen_names:
            raise ValueError(
                f"duplicate name {clean_name!r} for addresses "
                f"{hex(seen_names[clean_name])} and {hex(rva)}; give every rename "
                f"a distinct name or split them into separate calls"
            )

        seen_addresses[rva] = address
        seen_names[clean_name] = rva
        normalized.append((rva, clean_name))

    # One transaction: the binaries upsert and every annotation row commit
    # together, and any failure unwinds all of them.
    canon, sha, sniff, size = binary_sha256(binary)
    conn = _connect(db_path)
    try:
        ts = int(time.time())
        conn.execute(
            "INSERT INTO binaries(sha256,name,format,size,updated) VALUES(?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET updated=excluded.updated",
            (sha, canon.name, sniff, size, ts),
        )
        for rva, name in normalized:
            conn.execute(
                "INSERT INTO annotations(sha256,rva,kind,orig_name,new_name,type_decl,comment,confidence,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(sha256,rva,kind) DO UPDATE SET "
                "new_name=excluded.new_name, orig_name=excluded.orig_name, "
                "type_decl=excluded.type_decl, comment=excluded.comment, "
                "confidence=excluded.confidence, updated=excluded.updated",
                (sha, rva, KIND, "", name, "", "", 1.0, ts),
            )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "ok": True,
        "sha256": sha,
        "count": len(normalized),
        "applied": [{"rva": hex(rva), "name": name} for rva, name in normalized],
        "engine": "python",
    }


def rename_from_csv(
    binary: str | Path,
    csv_text: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Parse ``0x1130,name`` rows, then delegate to :func:`rename_many`.

    WHY: ``rename_many`` reports problems by address, but a CSV author needs the
    1-based source line to find the typo. This wrapper keeps that line number in
    scope for structural errors while leaving uniqueness, blank-name and size
    checks to the single authoritative validator below it.
    """
    pairs: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(csv_text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        address, sep, name = line.partition(",")
        address, name = address.strip(), name.strip()
        if not sep or not address or not name:
            raise ValueError(
                f"malformed CSV line {line_number}: {raw_line!r}; expected "
                f"'0xADDRESS,name' with both fields non-empty, or start the "
                f"line with '#' to comment it out"
            )
        try:
            parse_rva(address)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"malformed CSV line {line_number}: invalid address {address!r} "
                f"({exc}); use an integer or a 0x-prefixed hex string such as 0x1130"
            ) from exc
        pairs.append((address, name))

    return rename_many(binary, pairs, db_path=db_path)
