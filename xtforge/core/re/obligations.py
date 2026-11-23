"""Obligation ledger: what the analysis has NOT established.

WHY THIS EXISTS: a reverse-engineering result is a set of claims, and the dangerous ones
are the claims the tool did not make. "No imports found" reads identically whether the
import table was empty or the parser did not understand the format. Without a place to
record "this was not determined", a gap silently becomes an absence — and an analyst
reports a clean binary that was never actually examined.

So this is the complement of every other verb: where they record what was found, this
records what was **not**, why, and whether it is still open. Each entry is an
obligation — something that must be resolved or explicitly waived before a conclusion
is trusted.

Entry states:

    open      nobody has resolved it (the default)
    waived    consciously set aside, with a reason — "not in scope for this question"
    resolved  since determined, with the finding that closed it

The distinction that matters is `open` versus `waived`. An open obligation is a hole in
the analysis; a waived one is a decision. Both are honest; conflating them is not, so a
waiver without a reason is rejected rather than silently accepted.

Entries are keyed to a binary's sha256 (like bookmarks), so the ledger travels with the
artifact rather than with a session.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from .annotate import overlay_db_path
from .bookmarks import _binary_sha, _coerce_limit, _require_text

SCHEMA = """
CREATE TABLE IF NOT EXISTS obligations(
    sha256      TEXT NOT NULL,
    topic       TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'open',
    resolution  TEXT NOT NULL DEFAULT '',
    created     INTEGER NOT NULL,
    updated     INTEGER NOT NULL,
    PRIMARY KEY(sha256, topic)
);
CREATE INDEX IF NOT EXISTS obligations_state ON obligations(sha256, state);
"""

VALID_STATES = ("open", "waived", "resolved")


def _require_topic(value: str) -> str:
    """Reject a blank topic before it reaches SQLite.

    The table is keyed on (sha256, topic), so an empty topic is not merely useless — it
    collides with every other empty topic, meaning the second blank record silently
    overwrites the first and one obligation disappears without a trace.
    """
    text = _require_text(value, "topic")
    if not text.strip():
        raise ValueError("topic must not be empty; name the thing that is undetermined")
    return text.strip()


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    p = Path(db_path) if db_path is not None else overlay_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def record_unknown(
    binary: str | Path,
    topic: str,
    reason: str = "",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Declare that something about this binary has not been determined.

    Re-recording an existing open topic refreshes its reason rather than creating a
    duplicate. Recording over a resolved topic moves it back to open, because a new
    declaration is new information — silently keeping it resolved would hide the
    regression.
    """
    sha = _binary_sha(binary)
    topic = _require_topic(topic)
    reason = _require_text(reason, "reason")
    now = int(time.time())
    conn = _connect(db_path)
    try:
        existing = conn.execute(
            "SELECT state FROM obligations WHERE sha256=? AND topic=?",
            (sha, topic)).fetchone()
        if existing is not None and existing["state"] == "resolved":
            conn.execute(
                "UPDATE obligations SET state='open', reason=?, resolution='', "
                "updated=? WHERE sha256=? AND topic=?",
                (reason, now, sha, topic))
        else:
            conn.execute(
                "INSERT INTO obligations(sha256,topic,reason,state,resolution,"
                "created,updated) VALUES(?,?,?,'open','',?,?) "
                "ON CONFLICT(sha256,topic) DO UPDATE SET "
                "reason=excluded.reason, updated=excluded.updated",
                (sha, topic, reason, now, now))
        conn.commit()
        row = conn.execute(
            "SELECT topic,reason,state,resolution,updated FROM obligations "
            "WHERE sha256=? AND topic=?", (sha, topic)).fetchone()
        return {"ok": True, "sha256": sha, **_row(row)}
    finally:
        conn.close()


def resolve_unknown(
    binary: str | Path,
    topic: str,
    resolution: str,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Close an obligation with the finding that settled it."""
    sha = _binary_sha(binary)
    topic = _require_topic(topic)
    resolution = _require_text(resolution, "resolution")
    now = int(time.time())
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "UPDATE obligations SET state='resolved', resolution=?, updated=? "
            "WHERE sha256=? AND topic=?", (resolution, now, sha, topic))
        conn.commit()
        if cursor.rowcount == 0:
            return {"ok": False, "sha256": sha, "topic": topic,
                    "error": "no such obligation is recorded; nothing to resolve"}
        row = conn.execute(
            "SELECT topic,reason,state,resolution,updated FROM obligations "
            "WHERE sha256=? AND topic=?", (sha, topic)).fetchone()
        return {"ok": True, "sha256": sha, **_row(row)}
    finally:
        conn.close()


def waive_unknown(
    binary: str | Path,
    topic: str,
    reason: str,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Set an obligation aside deliberately — which requires saying why.

    A waiver without a reason is refused: "waived" and "open" mean different things to
    whoever reads this later, and an unexplained waiver is indistinguishable from
    forgetting about it.
    """
    sha = _binary_sha(binary)
    topic = _require_topic(topic)
    reason = _require_text(reason, "reason")
    if not reason.strip():
        return {"ok": False, "sha256": sha, "topic": topic,
                "error": "a waiver requires a reason; use resolve to close it instead"}
    now = int(time.time())
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "UPDATE obligations SET state='waived', reason=?, updated=? "
            "WHERE sha256=? AND topic=?", (reason, now, sha, topic))
        conn.commit()
        if cursor.rowcount == 0:
            return {"ok": False, "sha256": sha, "topic": topic,
                    "error": "no such obligation is recorded; nothing to waive"}
        row = conn.execute(
            "SELECT topic,reason,state,resolution,updated FROM obligations "
            "WHERE sha256=? AND topic=?", (sha, topic)).fetchone()
        return {"ok": True, "sha256": sha, **_row(row)}
    finally:
        conn.close()


def _row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "topic": row["topic"],
        "reason": row["reason"],
        "state": row["state"],
        "resolution": row["resolution"],
        "updated": row["updated"],
    }


def list_unknowns(
    binary: str | Path,
    state: str = "",
    limit: int = 200,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """List obligations, grouped by state, with the open ones first.

    The summary counts are the point: a caller can assert `open_count == 0` before
    trusting a conclusion, which is only possible if openness is reported rather than
    left to be inferred from an empty list.
    """
    sha = _binary_sha(binary)
    lim = _coerce_limit(limit)
    if state and state not in VALID_STATES:
        return {"ok": False, "sha256": sha,
                "error": f"unknown state {state!r}; expected one of "
                         f"{', '.join(VALID_STATES)}"}
    conn = _connect(db_path)
    try:
        if state:
            rows = conn.execute(
                "SELECT topic,reason,state,resolution,updated FROM obligations "
                "WHERE sha256=? AND state=? ORDER BY topic ASC LIMIT ?",
                (sha, state, lim)).fetchall()
        else:
            # open before waived before resolved, then by topic
            rows = conn.execute(
                "SELECT topic,reason,state,resolution,updated FROM obligations "
                "WHERE sha256=? ORDER BY "
                "CASE state WHEN 'open' THEN 0 WHEN 'waived' THEN 1 ELSE 2 END, "
                "topic ASC LIMIT ?", (sha, lim)).fetchall()
        counts = {name: 0 for name in VALID_STATES}
        for count_row in conn.execute(
                "SELECT state, COUNT(*) AS n FROM obligations WHERE sha256=? "
                "GROUP BY state", (sha,)).fetchall():
            if count_row["state"] in counts:
                counts[count_row["state"]] = count_row["n"]
        entries = [_row(row) for row in rows]
        return {
            "ok": True,
            "sha256": sha,
            "entries": entries,
            "count": len(entries),
            "counts": counts,
            "open_count": counts["open"],
            "waived_count": counts["waived"],
            "resolved_count": counts["resolved"],
            "clean": counts["open"] == 0,
        }
    finally:
        conn.close()


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return list_unknowns(path, **kwargs)
