"""Readiness and liveness probe payload builders."""
from __future__ import annotations


def readiness_status(db_ok: bool, queue_depth: int, limit: int = 1000) -> dict:
    healthy = db_ok and queue_depth < limit
    return {
        "ready": healthy,
        "db": "ok" if db_ok else "down",
        "backlog": queue_depth,
    }
