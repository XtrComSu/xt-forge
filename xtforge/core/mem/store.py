"""Universal memory store (F2): SQLite WAL + FTS5 with LIKE fallback.

Schema emitted verbatim as migration 001 (see MIGRATION_001 docstring).
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from . import scopes as sc
from . import links as linkmod
from .write_policy import body_hash, jaccard, redact, tokenize

SCHEMA_VERSION = 1

MIGRATION_001 = """
CREATE TABLE IF NOT EXISTS mem(
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  created INT NOT NULL,
  updated INT NOT NULL,
  last_used INT NOT NULL DEFAULT 0,
  uses INT NOT NULL DEFAULT 0,
  pin INT NOT NULL DEFAULT 0,
  ttl INT,
  confidence REAL NOT NULL DEFAULT 1.0,
  supersedes TEXT,
  body_hash TEXT NOT NULL DEFAULT '',
  pending INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mem_scope ON mem(scope);
CREATE INDEX IF NOT EXISTS idx_mem_kind ON mem(kind);
CREATE INDEX IF NOT EXISTS idx_mem_bh ON mem(body_hash);
CREATE INDEX IF NOT EXISTS idx_mem_pending ON mem(pending);
CREATE TABLE IF NOT EXISTS links(src TEXT, dst TEXT, rel TEXT);
CREATE INDEX IF NOT EXISTS idx_links_src ON links(src);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS mem_fts USING fts5(
  title, body, tags, content='mem', content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON mem BEGIN
  INSERT INTO mem_fts(rowid,title,body,tags) VALUES(new.rowid,new.title,new.body,new.tags);
END;
CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON mem BEGIN
  INSERT INTO mem_fts(mem_fts,rowid,title,body,tags)
    VALUES('delete',old.rowid,old.title,old.body,old.tags);
END;
CREATE TRIGGER IF NOT EXISTS mem_au AFTER UPDATE ON mem BEGIN
  INSERT INTO mem_fts(mem_fts,rowid,title,body,tags)
    VALUES('delete',old.rowid,old.title,old.body,old.tags);
  INSERT INTO mem_fts(rowid,title,body,tags) VALUES(new.rowid,new.title,new.body,new.tags);
END;
"""

LIKE_FALLBACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS mem_trgm(id TEXT PRIMARY KEY, trigrams TEXT NOT NULL);
"""

# links() used to accept free-text relations and could store duplicates; this
# normalizes the table before the unique index goes on. Idempotent.
LINKS_MIGRATION = """
UPDATE links SET rel='relates_to' WHERE rel IS NULL OR trim(lower(rel)) NOT IN (
  'relates_to','supersedes','derived_from','part_of','caused_by','fixes',
  'contradicts','see_also');
DELETE FROM links WHERE rowid NOT IN (
  SELECT MIN(rowid) FROM links GROUP BY src, dst, rel);
CREATE UNIQUE INDEX IF NOT EXISTS idx_links_unique ON links(src, dst, rel);
"""


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def now() -> int:
    return int(time.time())


def has_fts5(conn: sqlite3.Connection) -> bool:
    try:
        opts = [r[0] for r in conn.execute("PRAGMA compile_options")]
        if any("ENABLE_FTS5" in o for o in opts):
            return True
        conn.execute("CREATE VIRTUAL TABLE temp.__fts_probe USING fts5(x)")
        conn.execute("DROP TABLE temp.__fts_probe")
        return True
    except sqlite3.Error:
        return False


def trigrams(text: str) -> str:
    t = "  " + "".join(ch.lower() if ch.isalnum() else " " for ch in text) + "  "
    return " ".join(t[i:i + 3] for i in range(len(t) - 2))


class Store:
    """Harness-independent memory store. Thread-unsafe; one instance per process."""

    def __init__(self, path: str | Path, use_fts: bool | None = None):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=15.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(MIGRATION_001)
        self.conn.executescript(LINKS_MIGRATION)
        self.fts = has_fts5(self.conn) if use_fts is None else use_fts
        if self.fts:
            self.conn.executescript(FTS_SCHEMA)
            self._rebuild_fts()
        else:
            self.conn.executescript(LIKE_FALLBACK_SCHEMA)
        self.conn.execute(
            "INSERT INTO meta(k,v) VALUES('schema_version',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(SCHEMA_VERSION),))
        self.conn.execute(
            "INSERT INTO meta(k,v) VALUES('fts_mode',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            ("fts5" if self.fts else "like_trigram",))
        self.conn.commit()

    # ---------- internals ----------

    def _rebuild_fts(self) -> None:
        try:
            self.conn.execute(
                "INSERT INTO mem_fts(mem_fts) VALUES('rebuild')")
        except sqlite3.Error:
            pass

    def _index(self, rec_id: str, title: str, body: str, tags: str) -> None:
        """FTS index is trigger-maintained; only the trigram fallback is manual."""
        if self.fts:
            return
        self.conn.execute("INSERT INTO mem_trgm(id,trigrams) VALUES(?,?) "
                          "ON CONFLICT(id) DO UPDATE SET trigrams=excluded.trigrams",
                          (rec_id, trigrams(f"{title} {body} {tags}")))

    def _drop_index(self, rec_id: str) -> None:
        if self.fts:
            return
        self.conn.execute("DELETE FROM mem_trgm WHERE id=?", (rec_id,))

    # ---------- write policy ----------

    def _policy(self, body: str, title: str, scope: str, kind: str,
                near_dup_threshold: float = 0.8) -> tuple[str, list[str]]:
        """Apply redaction + dedupe. Returns (final_body, notes)."""
        clean_body, kinds = redact(body or "")
        clean_title, t_kinds = redact(title or "")
        redact_kinds = kinds + [k for k in t_kinds if k not in kinds]
        notes = [f"redacted:{k}" for k in redact_kinds]
        if not clean_body.strip() and redact_kinds:
            clean_body = "[REDACTED]"
        bh = body_hash(clean_body)
        exact = self.conn.execute(
            "SELECT id FROM mem WHERE body_hash=? AND scope=? LIMIT 1", (bh, scope)).fetchone()
        if exact:
            return clean_body, notes + [f"dedupe_exact:{exact['id']}"]
        toks = tokenize(clean_body)
        rows = self.conn.execute(
            "SELECT id, body FROM mem WHERE scope=? AND kind=? AND pending=0 LIMIT 200",
            (scope, kind)).fetchall()
        for r in rows:
            if jaccard(toks, tokenize(r["body"])) >= near_dup_threshold:
                return clean_body, notes + [f"near_dup:{r['id']}"]
        return clean_body, notes

    # ---------- public API ----------

    def put(self, *, scope: str, kind: str, title: str = "", body: str = "",
            tags: Iterable[str] = (), source: str = "", confidence: float = 1.0,
            pin: bool = False, ttl: int | None = None, pending: bool = False,
            id: str | None = None) -> dict[str, Any]:
        if not sc.is_valid_kind(kind):
            raise ValueError(f"invalid kind {kind!r}; expected one of {list(sc.KINDS)}")
        clean_body, notes = self._policy(body, title, scope, kind)
        tag_str = ",".join(sorted({str(t).strip() for t in tags if str(t).strip()}))
        rec_id = id or new_id()
        ts = now()
        dedupe = next((n for n in notes if n.startswith("dedupe_exact:")), None)
        near = next((n for n in notes if n.startswith("near_dup:")), None)
        if dedupe or near:
            target = (dedupe or near).split(":", 1)[1]
            # A pending candidate must never rewrite promoted memory: report
            # the collision and let review decide.
            if pending:
                row = self.conn.execute("SELECT pending FROM mem WHERE id=?",
                                        (target,)).fetchone()
                if row is not None and not row["pending"]:
                    self.conn.commit()
                    return {"id": target, "action": "dup_of_promoted",
                            "notes": notes}
            self.conn.execute(
                "UPDATE mem SET body=?, title=CASE WHEN ?='' THEN title ELSE ? END, updated=?, "
                "confidence=MAX(confidence,?), supersedes=? WHERE id=?",
                (clean_body, title, title, ts, confidence, target, target))
            self._index(target, title, clean_body, tag_str)
            self.conn.commit()
            return {"id": target, "action": "superseded", "notes": notes}
        self.conn.execute(
            "INSERT INTO mem(id,scope,kind,title,body,tags,source,created,updated,"
            "last_used,uses,pin,ttl,confidence,supersedes,body_hash,pending) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rec_id, scope, kind, title, clean_body, tag_str, source, ts, ts,
             0, 0, 1 if pin else 0, ttl, confidence, None, body_hash(clean_body),
             1 if pending else 0))
        self._index(rec_id, title, clean_body, tag_str)
        self.conn.commit()
        return {"id": rec_id, "action": "inserted", "notes": notes}

    def get(self, rec_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM mem WHERE id=?", (rec_id,)).fetchone()
        return dict(row) if row else None

    def forget(self, rec_id: str) -> bool:
        self._drop_index(rec_id)
        self.conn.execute("DELETE FROM links WHERE src=? OR dst=?", (rec_id, rec_id))
        cur = self.conn.execute("DELETE FROM mem WHERE id=?", (rec_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def touch(self, rec_id: str) -> None:
        ts = now()
        self.conn.execute("UPDATE mem SET uses=uses+1, last_used=? WHERE id=?", (ts, rec_id))
        self.conn.commit()

    def set_pin(self, rec_id: str, pin: bool) -> bool:
        cur = self.conn.execute("UPDATE mem SET pin=?, updated=? WHERE id=?",
                                (1 if pin else 0, now(), rec_id))
        self.conn.commit()
        return cur.rowcount > 0

    def review(self, action: str, rec_id: str | None = None) -> dict[str, Any]:
        if action == "promote":
            cur = self.conn.execute(
                "UPDATE mem SET pending=0, confidence=MAX(confidence,0.9), updated=? "
                "WHERE id=? AND pending=1", (now(), rec_id))
        elif action == "drop":
            cur = self.conn.execute("DELETE FROM mem WHERE id=? AND pending=1", (rec_id,))
        else:
            raise ValueError("action must be 'promote' or 'drop'")
        self.conn.commit()
        return {"action": action, "id": rec_id, "changed": cur.rowcount}

    def pending(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM mem WHERE pending=1 ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def list(self, scope: str | None = None, limit: int = 50,
             kind: str | None = None, pending: bool | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM mem WHERE 1=1"
        args: list[Any] = []
        if scope:
            q += " AND scope=?"
            args.append(scope)
        if kind:
            q += " AND kind=?"
            args.append(kind)
        if pending is not None:
            q += " AND pending=?"
            args.append(1 if pending else 0)
        q += " ORDER BY pin DESC, updated DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(q, args)]

    def purge_expired(self) -> int:
        ts = now()
        rows = self.conn.execute("SELECT id FROM mem WHERE ttl IS NOT NULL AND ttl > 0 AND ttl < ?",
                                 (ts,)).fetchall()
        for r in rows:
            self._drop_index(r["id"])
        cur = self.conn.execute("DELETE FROM mem WHERE ttl IS NOT NULL AND ttl > 0 AND ttl < ?", (ts,))
        self.conn.commit()
        return cur.rowcount

    # ---------- typed links ----------

    def link(self, src: str, dst: str, rel: str | None = None) -> dict[str, Any]:
        """Typed, deduped edge between two records. Raises on bad input."""
        if not src or not dst:
            raise ValueError("link requires both src and dst ids")
        if src == dst:
            raise ValueError("cannot link a record to itself")
        if not linkmod.is_valid_relation(rel or ""):
            raise ValueError(f"invalid relation {rel!r}; expected one of "
                             f"{sorted(linkmod.RELATIONS)}")
        relation = linkmod.normalize_relation(rel)
        for rec_id in (src, dst):
            if self.conn.execute("SELECT 1 FROM mem WHERE id=?",
                                 (rec_id,)).fetchone() is None:
                raise ValueError(f"unknown record: {rec_id}")
        cur = self.conn.execute("INSERT OR IGNORE INTO links(src,dst,rel) "
                                "VALUES(?,?,?)", (src, dst, relation))
        self.conn.commit()
        return {"src": src, "dst": dst, "rel": relation,
                "meaning": linkmod.describe(relation),
                "action": "linked" if cur.rowcount else "unchanged"}

    def unlink(self, src: str, dst: str, rel: str | None = None) -> int:
        if rel:
            cur = self.conn.execute("DELETE FROM links WHERE src=? AND dst=? AND rel=?",
                                    (src, dst, linkmod.normalize_relation(rel)))
        else:
            cur = self.conn.execute("DELETE FROM links WHERE src=? AND dst=?",
                                    (src, dst))
        self.conn.commit()
        return cur.rowcount

    def links(self, rec_id: str, include_titles: bool = True) -> dict[str, Any]:
        """Outgoing and incoming edges for one record."""
        def fetch(sql: str, arg: str) -> list[dict[str, Any]]:
            rows = self.conn.execute(sql, (arg,)).fetchall()
            out = []
            for row in rows:
                edge = dict(row)
                if include_titles:
                    title = self.conn.execute(
                        "SELECT title FROM mem WHERE id=?",
                        (edge.get("other"),)).fetchone()
                    edge["title"] = title["title"] if title else ""
                out.append(edge)
            return out

        out_rows = fetch(
            "SELECT dst AS other, rel FROM links WHERE src=? ORDER BY rel, dst", rec_id)
        in_rows = fetch(
            "SELECT src AS other, rel FROM links WHERE dst=? ORDER BY rel, src", rec_id)
        return {
            "id": rec_id,
            "out": linkmod.shape(out_rows, "out"),
            "in": linkmod.shape(in_rows, "in"),
            "count": len(out_rows) + len(in_rows),
        }

    def neighbors(self, rec_id: str, depth: int = 1) -> list[str]:
        """Linked record ids, walking edges in both directions (deduped)."""
        seen = {rec_id}
        frontier = [rec_id]
        for _ in range(max(1, depth)):
            nxt: list[str] = []
            for current in frontier:
                rows = self.conn.execute(
                    "SELECT dst AS other FROM links WHERE src=? "
                    "UNION SELECT src AS other FROM links WHERE dst=?", (current, current))
                for row in rows:
                    other = row["other"]
                    if other not in seen:
                        seen.add(other)
                        nxt.append(other)
            if not nxt:
                break
            frontier = nxt
        return sorted(seen - {rec_id})

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass