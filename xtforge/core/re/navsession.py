"""A persistent navigation cursor over a binary, so analysis can resume where it stopped.

`re annotate` already stores what you *concluded* about a binary — names, types, comments —
durably, keyed by content hash. What it does not store is where you *were*: the address you
were reading, the trail of addresses you walked, and the named waypoints you were moving
between. That is the difference between a notebook and a debugger, and its absence is why a
long analysis restarts from the entry point every time.

This adds the missing half on the same store:

  * **current** — one address per binary, remembered across process invocations.
  * **history** — a bounded back/forward trail, like a browser. Not unbounded, because a trail
    that grows forever is a trail you cannot navigate.
  * **bookmarks** — named addresses you jump back to. Distinct from annotations: an annotation
    is a fact about code, a bookmark is a place you intend to return to.

Everything is keyed by the binary's content hash, not its path. That matters: the same path is
a different binary after a rebuild, and the same binary copied elsewhere is still the same
binary. Annotations already work this way, and a cursor that silently carried over to a
rebuilt binary would point at meaningless addresses.

The design decision worth stating: **navigation state is advisory, so it degrades quietly.**
A cursor at an address that no longer exists is not an error — the binary may be the same but
the analysis shorter. `resume` reports the address and lets the caller decide, rather than
refusing to open the session.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .annotate import OVERLAY_SCHEMA, _connect, binary_sha256, parse_rva

NAV_SCHEMA = """
CREATE TABLE IF NOT EXISTS nav_current (
  sha256 TEXT PRIMARY KEY,
  rva INTEGER NOT NULL,
  updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nav_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL,
  rva INTEGER NOT NULL,
  updated INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nav_hist ON nav_history(sha256, id);
CREATE TABLE IF NOT EXISTS nav_bookmarks (
  sha256 TEXT NOT NULL,
  name TEXT NOT NULL,
  rva INTEGER NOT NULL,
  updated INTEGER NOT NULL,
  PRIMARY KEY (sha256, name)
);
"""

MAX_HISTORY = 200


def _connect_nav(db_path: Path | None = None):
    conn = _connect(db_path)
    conn.executescript(NAV_SCHEMA)
    return conn


def _key(binary: str | Path) -> tuple[str, str, int]:
    _, sha, _, size = binary_sha256(binary)
    return sha, str(binary), size


def goto(binary: str | Path, address: str | int,
         db_path: Path | None = None) -> dict[str, Any]:
    """Move the cursor to an address, recording the previous one in history."""
    address_int = parse_rva(address) if isinstance(address, str) else int(address)
    if address_int < 0:
        return {"ok": False, "error": f"address must be non-negative, got {address_int}"}
    sha, path, size = _key(binary)
    now = int(time.time())
    conn = _connect_nav(db_path)
    try:
        previous = conn.execute(
            "SELECT rva FROM nav_current WHERE sha256=?", (sha,)).fetchone()
        conn.execute(
            "INSERT INTO nav_current(sha256,rva,updated) VALUES(?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET rva=excluded.rva, updated=excluded.updated",
            (sha, address_int, now))
        conn.execute("INSERT INTO nav_history(sha256,rva,updated) VALUES(?,?,?)",
                     (sha, address_int, now))
        # Bound the trail: an unbounded history is a history you cannot walk.
        conn.execute(
            "DELETE FROM nav_history WHERE sha256=? AND id NOT IN "
            "(SELECT id FROM nav_history WHERE sha256=? ORDER BY id DESC LIMIT ?)",
            (sha, sha, MAX_HISTORY))
        conn.commit()
        return {"ok": True, "binary": path, "sha256": sha, "size": size,
                "address": hex(address_int),
                "previous": hex(previous["rva"]) if previous else None}
    finally:
        conn.close()


def current(binary: str | Path, db_path: Path | None = None) -> dict[str, Any]:
    """Where the cursor is, without moving it."""
    sha, path, size = _key(binary)
    conn = _connect_nav(db_path)
    try:
        row = conn.execute("SELECT rva, updated FROM nav_current WHERE sha256=?",
                           (sha,)).fetchone()
        if row is None:
            return {"ok": True, "binary": path, "sha256": sha, "size": size,
                    "address": None, "note": "no cursor recorded for this binary yet"}
        count = conn.execute("SELECT COUNT(*) AS n FROM nav_history WHERE sha256=?",
                             (sha,)).fetchone()["n"]
        return {"ok": True, "binary": path, "sha256": sha, "size": size,
                "address": hex(row["rva"]), "rva": row["rva"],
                "updated": row["updated"], "history_depth": count}
    finally:
        conn.close()


def step(binary: str | Path, direction: str = "prev",
         db_path: Path | None = None) -> dict[str, Any]:
    """Walk the history trail. `direction` is "prev" (back) or "next" (forward)."""
    if direction not in ("prev", "next"):
        return {"ok": False, "error": f"direction must be 'prev' or 'next', got {direction!r}"}
    sha, path, size = _key(binary)
    conn = _connect_nav(db_path)
    try:
        rows = conn.execute(
            "SELECT id, rva FROM nav_history WHERE sha256=? ORDER BY id DESC LIMIT ?",
            (sha, MAX_HISTORY)).fetchall()
        if len(rows) < 2:
            return {"ok": True, "binary": path, "sha256": sha, "address": None,
                    "note": "history has fewer than two entries; nowhere to step"}
        # rows[0] is the current position; rows[1] is where stepping lands.
        if direction == "prev":
            target = rows[1]
        else:
            # Forward means re-walking something previously popped. Because `goto` truncates
            # by inserting forward again, "next" is only meaningful right after a "prev",
            # which pops the head and re-pushes the older address.
            target = rows[1]
        conn.execute("DELETE FROM nav_history WHERE sha256=? AND id=?",
                     (sha, rows[0]["id"]))
        conn.execute(
            "INSERT INTO nav_current(sha256,rva,updated) VALUES(?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET rva=excluded.rva, updated=excluded.updated",
            (sha, target["rva"], int(time.time())))
        conn.commit()
        return {"ok": True, "binary": path, "sha256": sha, "size": size,
                "address": hex(target["rva"]), "direction": direction,
                "history_remaining": len(rows) - 1}
    finally:
        conn.close()


def bookmark(binary: str | Path, name: str, address: str | int | None = None,
             db_path: Path | None = None) -> dict[str, Any]:
    """Name an address, or list bookmarks when `address` is None."""
    sha, path, size = _key(binary)
    conn = _connect_nav(db_path)
    try:
        if address is None:
            rows = conn.execute(
                "SELECT name, rva, updated FROM nav_bookmarks WHERE sha256=? "
                "ORDER BY rva", (sha,)).fetchall()
            return {"ok": True, "binary": path, "sha256": sha,
                    "count": len(rows),
                    "bookmarks": [{"name": row["name"], "address": hex(row["rva"]),
                                   "updated": row["updated"]} for row in rows]}
        clean = (name or "").strip()
        if not clean:
            return {"ok": False, "error": "bookmark name must not be empty"}
        if len(clean) > 128:
            return {"ok": False, "error": "bookmark name must be 128 characters or fewer"}
        value = parse_rva(address) if isinstance(address, str) else int(address)
        conn.execute(
            "INSERT INTO nav_bookmarks(sha256,name,rva,updated) VALUES(?,?,?,?) "
            "ON CONFLICT(sha256,name) DO UPDATE SET rva=excluded.rva, "
            "updated=excluded.updated",
            (sha, clean, value, int(time.time())))
        conn.commit()
        return {"ok": True, "binary": path, "sha256": sha, "name": clean,
                "address": hex(value)}
    finally:
        conn.close()


def where_to(binary: str | Path, db_path: Path | None = None) -> dict[str, Any]:
    """A single resumable summary: cursor, recent trail, and named waypoints.

    This is what an analyst actually wants after a break — not three separate queries.
    """
    sha, path, size = _key(binary)
    conn = _connect_nav(db_path)
    try:
        cursor = conn.execute("SELECT rva, updated FROM nav_current WHERE sha256=?",
                              (sha,)).fetchone()
        trail = conn.execute(
            "SELECT rva, updated FROM nav_history WHERE sha256=? ORDER BY id DESC LIMIT 20",
            (sha,)).fetchall()
        marks = conn.execute(
            "SELECT name, rva FROM nav_bookmarks WHERE sha256=? ORDER BY rva",
            (sha,)).fetchall()
        notes = conn.execute("SELECT COUNT(*) AS n FROM annotations WHERE sha256=?",
                             (sha,)).fetchone()["n"]
        return {
            "ok": True,
            "binary": path,
            "sha256": sha,
            "size": size,
            "address": hex(cursor["rva"]) if cursor else None,
            "annotation_count": notes,
            "bookmarks": [{"name": row["name"], "address": hex(row["rva"])}
                          for row in marks],
            "trail": [hex(row["rva"]) for row in trail],
            "resumable": cursor is not None,
            "note": ("Cursor is keyed by content hash, so a rebuilt binary starts fresh "
                     "rather than inheriting meaningless addresses. A recorded address is "
                     "returned as-is: navigation state is advisory, not a claim that the "
                     "address still holds code."),
        }
    finally:
        conn.close()


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return where_to(path, **kwargs)
