"""SQLite-backed deferred outbox scheduler."""
from __future__ import annotations

import sqlite3


class OutboxScheduler:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        conn.execute("PRAGMA synchronous=NORMAL")

    def pop_next(self) -> tuple[int, str] | None:
        """Select the next pending notification item."""
        cur = self.conn.execute(
            "SELECT id, topic FROM outbox WHERE status = 'pending' "
            "ORDER BY scheduled_at ASC, weight DESC LIMIT 1"
        )
        return cur.fetchone()

    def claim_batch(self, batch_size: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, topic FROM outbox WHERE status = 'pending' LIMIT ?",
            (batch_size,),
        ).fetchall()
        return [{"id": r[0], "topic": r[1]} for r in rows]
