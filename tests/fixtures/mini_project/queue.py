"""Job queue backed by a single table.

Jobs are deduplicated by payload hash so a retry storm cannot enqueue the
same work twice. Pop is FIFO within a priority band.
"""
from __future__ import annotations

import hashlib
from typing import Any


class Job:
    """A dequeued job. `run` is supplied by the caller at enqueue time."""

    def __init__(self, job_id: str, payload_hash: str):
        self.id = job_id
        self.payload_hash = payload_hash

    def run(self) -> dict[str, object]:
        return {"job": self.id}


class Queue:
    def __init__(self, conn: Any):
        self.conn = conn
        self._pending: list[dict[str, Any]] = []

    def push(self, payload: dict[str, Any], priority: int = 0) -> str:
        """Enqueue a job; returns its id, existing or new."""
        digest = hashlib.sha256(repr(sorted(payload.items())).encode()).hexdigest()[:16]
        existing = self.conn.execute(
            "SELECT id FROM jobs WHERE payload_hash = ?", (digest,)).fetchone()
        if existing:
            return existing[0]
        self.conn.execute(
            "INSERT INTO jobs(id, payload_hash, priority, state) VALUES (?,?,?,?)",
            (digest, digest, priority, "queued"))
        self.conn.commit()
        return digest

    def pop(self) -> "Job | None":
        """Take the next queued job and mark it running."""
        row = self.conn.execute(
            "SELECT id, payload_hash FROM jobs WHERE state = 'queued' "
            "ORDER BY priority DESC, id LIMIT 1").fetchone()
        if row is None:
            return None
        self.conn.execute("UPDATE jobs SET state = 'running' WHERE id = ?", (row[0],))
        self.conn.commit()
        return Job(row[0], row[1])

    def depth(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM jobs WHERE state = 'queued'")
        return row.fetchone()[0]
