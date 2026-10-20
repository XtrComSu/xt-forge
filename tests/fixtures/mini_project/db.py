"""SQLite storage layer.

A single connection pool, schema migration and a tiny query helper. WAL mode
is enabled so readers never block the writer.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 3
POOL_SIZE = 4


class MigrationError(Exception):
    """Raised when the stored schema is newer than this code understands."""


def open_pool(path: str | Path) -> list[sqlite3.Connection]:
    """Open POOL_SIZE connections in WAL mode with foreign keys on.

    Connections are cheap here because SQLite is embedded; the pool exists so
    concurrent readers do not share a single handle.
    """
    pool = []
    for _ in range(POOL_SIZE):
        conn = sqlite3.connect(str(path), timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        pool.append(conn)
    return pool


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations in order; returns the resulting version."""
    current = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] or 0
    if current > SCHEMA_VERSION:
        raise MigrationError(f"schema {current} is newer than {SCHEMA_VERSION}")
    for version in range(current + 1, SCHEMA_VERSION + 1):
        conn.execute("INSERT INTO schema_migrations(version) VALUES (?)", (version,))
    conn.commit()
    return SCHEMA_VERSION


def fetch(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Run a read query and return rows as dicts."""
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]
