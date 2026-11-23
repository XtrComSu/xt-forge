"""Address bookmarks for RE sessions: navigation state, not analysis results."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from .annotate import binary_sha256, overlay_db_path, parse_rva
from ..route.guard import Denied

SCHEMA = """
CREATE TABLE IF NOT EXISTS bookmarks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL,
  rva INTEGER NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL,
  updated INTEGER NOT NULL,
  UNIQUE(sha256,rva)
);
CREATE INDEX IF NOT EXISTS idx_bm_sha ON bookmarks(sha256);
"""

_MAX_LIMIT = 1000


def _binary_sha(binary: str | Path) -> str:
    """Turn an unreadable binary into an actionable error instead of a raw OS failure."""
    try:
        return binary_sha256(binary)[1]
    except (OSError, Denied) as exc:
        raise ValueError(
            f"binary must be a readable file path (got {binary!r}: {exc}); "
            "point it at an existing file inside an allowlisted root"
        ) from exc


def _parse_address(value: str | int, what: str) -> int:
    """Give malformed addresses a message that says what a valid address looks like."""
    try:
        addr = parse_rva(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{what} must be an address: an integer or a '0x' hex string such as "
            f"0x1200 (got {value!r})"
        ) from exc
    if addr < 0:
        raise ValueError(
            f"{what} must be a non-negative address (got {addr}); "
            "use 0 or a positive offset"
        )
    return addr


def _require_text(value: str, what: str) -> str:
    """Keep the NOT NULL text columns honest before SQLite sees them."""
    if not isinstance(value, str):
        raise ValueError(f"{what} must be text (got {value!r}); pass a string or omit it")
    return value


def _coerce_limit(limit: int) -> int:
    """Bound every page so a caller can never ask for unbounded work."""
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"limit must be an integer from 1 to {_MAX_LIMIT} (got {limit!r})"
        ) from exc
    if value < 1:
        raise ValueError(f"limit must be at least 1 (got {value}); pass a positive integer")
    return min(value, _MAX_LIMIT)


def _row_item(row: sqlite3.Row) -> dict[str, Any]:
    """Share one projection so list/next/prev return the same bookmark shape."""
    return {
        "rva": hex(row["rva"]),
        "rva_int": row["rva"],
        "label": row["label"],
        "note": row["note"],
        "updated": row["updated"],
    }


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Live beside the other RE overlays so marks survive process restarts."""
    p = Path(db_path) if db_path is not None else overlay_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def set_bookmark(
    binary: str | Path,
    rva: str | int,
    label: str = "",
    note: str = "",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Mark an address once so it can be found later without re-running analysis."""
    sha = _binary_sha(binary)
    addr = _parse_address(rva, "rva")
    label = _require_text(label, "label")
    note = _require_text(note, "note")
    ts = int(time.time())
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO bookmarks(sha256,rva,label,note,created,updated) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(sha256,rva) DO UPDATE SET "
            "label=excluded.label, note=excluded.note, updated=excluded.updated",
            (sha, addr, label, note, ts, ts),
        )
        conn.commit()
        return {"ok": True, "sha256": sha, "rva": hex(addr), "label": label, "note": note}
    finally:
        conn.close()


def list_bookmarks(
    binary: str | Path,
    after: str | int | None = None,
    limit: int = 200,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Walk marks in address order a page at a time instead of loading them all."""
    sha = _binary_sha(binary)
    addr = None if after is None else _parse_address(after, "after")
    lim = _coerce_limit(limit)
    conn = _connect(db_path)
    try:
        if addr is None:
            sql = ("SELECT rva,label,note,updated FROM bookmarks WHERE sha256=? "
                   "ORDER BY rva ASC LIMIT ?")
            params: tuple[Any, ...] = (sha, lim + 1)
        else:
            sql = ("SELECT rva,label,note,updated FROM bookmarks "
                   "WHERE sha256=? AND rva>? ORDER BY rva ASC LIMIT ?")
            params = (sha, addr, lim + 1)
        rows = conn.execute(sql, params).fetchall()
        truncated = len(rows) > lim
        items = [_row_item(r) for r in rows[:lim]]
        return {
            "ok": True, "sha256": sha, "count": len(items),
            "bookmarks": items, "truncated": truncated,
        }
    finally:
        conn.close()


def next_bookmark(
    binary: str | Path,
    after: str | int,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Jump forward to the next mark; having none ahead is a normal outcome."""
    sha = _binary_sha(binary)
    addr = _parse_address(after, "after")
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT rva,label,note,updated FROM bookmarks "
            "WHERE sha256=? AND rva>? ORDER BY rva ASC LIMIT 1",
            (sha, addr),
        ).fetchone()
        return {"ok": True, "bookmark": _row_item(row) if row is not None else None}
    finally:
        conn.close()


def prev_bookmark(
    binary: str | Path,
    before: str | int,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Jump back to the last mark so navigation works in both directions."""
    sha = _binary_sha(binary)
    addr = _parse_address(before, "before")
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT rva,label,note,updated FROM bookmarks "
            "WHERE sha256=? AND rva<? ORDER BY rva DESC LIMIT 1",
            (sha, addr),
        ).fetchone()
        return {"ok": True, "bookmark": _row_item(row) if row is not None else None}
    finally:
        conn.close()


def unset_bookmark(
    binary: str | Path,
    rva: str | int,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Make removal idempotent so tidying up never fails on an already-gone mark."""
    sha = _binary_sha(binary)
    addr = _parse_address(rva, "rva")
    conn = _connect(db_path)
    try:
        cur = conn.execute("DELETE FROM bookmarks WHERE sha256=? AND rva=?", (sha, addr))
        conn.commit()
        return {"ok": True, "removed": cur.rowcount > 0, "rva": hex(addr)}
    finally:
        conn.close()
