"""Database schema revisions for outbox tables."""
from __future__ import annotations

SCHEMA_REV = 3

DDL_STATEMENTS = (
    "CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, topic TEXT, scheduled_at REAL, weight INTEGER, status TEXT)",
    "CREATE TABLE IF NOT EXISTS deliveries (id INTEGER PRIMARY KEY, outbox_id INTEGER, code INTEGER, created_at REAL)",
)


def apply_schema(conn) -> int:
    for stmt in DDL_STATEMENTS:
        conn.execute(stmt)
    return SCHEMA_REV
