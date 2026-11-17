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

SCHEMA_VERSION = 3


KNOWLEDGE_COLUMNS = (
    ("status", "TEXT"), ("evidence", "TEXT"), ("verification", "TEXT"),
    ("author", "TEXT"), ("target", "TEXT"), ("project", "TEXT"),
    ("versions", "TEXT"), ("environment", "TEXT"),
    ("error_sig", "TEXT"), ("outcome", "TEXT"),
)


def _ensure_columns(conn) -> None:
    """Add the knowledge columns to an existing database.

    SQLite has no `ADD COLUMN IF NOT EXISTS`, and a migration that throws on
    re-run would make every open fail once the columns exist. So inspect
    PRAGMA table_info and add only what is missing. Purely additive: no row is
    rewritten and a v1 database keeps working untouched.
    """
    have = {row[1] for row in conn.execute("PRAGMA table_info(mem)")}
    for name, decl in KNOWLEDGE_COLUMNS:
        if name in have:
            continue
        try:
            conn.execute(f"ALTER TABLE mem ADD COLUMN {name} {decl}")
        except Exception:  # noqa: BLE001 - concurrent open already added it
            pass
    conn.commit()


def _body_identity(body: str) -> str | None:
    """The machine identity a record declares, or None for prose records.

    Records written by an agent layer (error patterns, task records) carry a
    `signature` or `identity` field that names exactly which thing they describe.
    When present, two records are only the same when those match - structural
    similarity is not evidence of sameness for this class of record.
    """
    if not body or not body.strip().startswith("{"):
        return None
    try:
        import json as _json
        data = _json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    for key in ("signature", "identity"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # A record may scope its identity to a project or target without carrying a
    # signature (a finding, say). Treat the pair as the identity rather than
    # letting structural similarity merge two projects' findings together.
    target = data.get("target")
    project = data.get("project")
    if isinstance(target, str) and target.strip():
        scope = project.strip() if isinstance(project, str) and project.strip() else ""
        return f"target:{scope}:{target.strip()}"
    if isinstance(project, str) and project.strip():
        return f"project:{project.strip()}"
    return None

MIGRATION_002 = """
-- Additive: knowledge records carry lifecycle status, scope identity, evidence
-- and relations. Existing rows keep NULL and behave exactly as before, so this
-- migration is safe to run on a live database.
ALTER TABLE mem ADD COLUMN status TEXT;
ALTER TABLE mem ADD COLUMN evidence TEXT;
ALTER TABLE mem ADD COLUMN verification TEXT;
ALTER TABLE mem ADD COLUMN author TEXT;
ALTER TABLE mem ADD COLUMN target TEXT;
ALTER TABLE mem ADD COLUMN project TEXT;
ALTER TABLE mem ADD COLUMN versions TEXT;
ALTER TABLE mem ADD COLUMN environment TEXT;
"""

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
        _ensure_columns(self.conn)
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
        """Apply redaction + dedupe. Returns (final_body, notes).

        Near-duplicate detection compares body tokens with Jaccard. That is the
        right test for prose records, where two bodies being 80% similar means
        they really are the same note.

        It is the wrong test for records that carry a machine identity. Two
        error patterns from *different* tools share almost all their tokens -
        the same JSON keys, the same guidance wording - and score ~0.86, so a
        distinct signature was silently superseded into an unrelated record and
        its recovery history was lost. When a body declares a `signature` (or
        `identity`), structural similarity no longer implies sameness: the
        identity must match too.
        """
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

        own_identity = _body_identity(clean_body)
        toks = tokenize(clean_body)
        rows = self.conn.execute(
            "SELECT id, body FROM mem WHERE scope=? AND kind=? AND pending=0 LIMIT 200",
            (scope, kind)).fetchall()
        for r in rows:
            if own_identity is not None:
                # Identity-bearing record: only the same identity may merge.
                if _body_identity(r["body"]) != own_identity:
                    continue
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

    def record_failure(self, *, scope: str = "global", title: str = "failed attempt",
                       body: str, error_sig: str = "", outcome: str = "failed",
                       tags: list[str] | tuple[str, ...] = (),
                       source: str = "cli") -> dict[str, Any]:
        """Store an indexed negative constraint (`failed_attempt`) with error signature."""
        clean_sig, _ = redact(error_sig)
        out_val = outcome.strip() or "failed"
        res = self.put(scope=scope, kind="failed_attempt", title=title, body=body,
                       tags=tags, source=source, confidence=1.0, pending=False)
        rec_id = res["id"]
        self.conn.execute(
            "UPDATE mem SET error_sig=?, outcome=? WHERE id=?",
            (clean_sig, out_val, rec_id))
        self.conn.commit()
        return {**res, "kind": "failed_attempt", "error_sig": clean_sig, "outcome": out_val}

    def consolidate(self, *, scope: str | None = None, threshold: float = 0.55,
                    dry_run: bool = False, limit: int = 250) -> dict[str, Any]:
        """Cluster near-similar active notes in a scope and write summary records."""
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS consolidation_log("
            "id TEXT PRIMARY KEY, ts INT NOT NULL, scope TEXT NOT NULL DEFAULT '', "
            "merged INT NOT NULL DEFAULT 0, created INT NOT NULL DEFAULT 0, "
            "notes TEXT NOT NULL DEFAULT '')")
        sql = (
            "SELECT id, scope, kind, title, body, tags, updated FROM mem "
            "WHERE kind IN ('fact','snippet','procedure','error_pattern') "
            "AND (supersedes IS NULL OR supersedes='') AND source != 'consolidate'"
        )
        args: list[Any] = []
        if scope and scope != "*":
            sql += " AND scope=?"
            args.append(scope)
        sql += " ORDER BY updated DESC LIMIT ?"
        args.append(max(2, int(limit)))
        rows = [dict(r) for r in self.conn.execute(sql, args).fetchall()]
        toks = [tokenize(f"{r.get('title', '')} {r.get('body', '')}") for r in rows]

        used = [False] * len(rows)
        clusters: list[list[int]] = []
        for i in range(len(rows)):
            if used[i] or not toks[i]:
                continue
            grp = [i]
            for j in range(i + 1, len(rows)):
                if used[j] or rows[i]["scope"] != rows[j]["scope"]:
                    continue
                if jaccard(toks[i], toks[j]) >= threshold:
                    grp.append(j)
                    used[j] = True
            if len(grp) >= 2:
                used[i] = True
                clusters.append(grp)

        summaries: list[dict[str, Any]] = []
        merged_count = 0
        created_count = 0
        for grp in clusters:
            primary = rows[grp[0]]
            grp_scope = primary["scope"]
            grp_kind = primary["kind"]
            base_title = primary.get("title") or "consolidated"
            member_ids = [rows[idx]["id"] for idx in grp]
            lines: list[str] = []
            seen_lines: set[str] = set()
            tags: set[str] = {"consolidated"}
            for idx in grp:
                for t in (rows[idx].get("tags") or "").split(","):
                    if t.strip():
                        tags.add(t.strip())
                b = (rows[idx].get("body") or "").strip()
                if b and b not in seen_lines:
                    seen_lines.add(b)
                    lines.append(b)
            sum_title = f"{base_title} [consolidated]"
            merged_body = "\n---\n".join(lines)
            if dry_run:
                summaries.append({
                    "scope": grp_scope, "kind": grp_kind,
                    "title": sum_title, "members": member_ids,
                })
                merged_count += len(member_ids)
                created_count += 1
                continue

            sum_id = new_id()
            ts = now()
            clean_body, _ = redact(merged_body)
            tag_str = ",".join(sorted(tags))
            self.conn.execute(
                "INSERT INTO mem(id,scope,kind,title,body,tags,source,created,updated,"
                "last_used,uses,pin,ttl,confidence,supersedes,body_hash,pending) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (sum_id, grp_scope, grp_kind, sum_title, clean_body, tag_str,
                 "consolidate", ts, ts, 0, 0, 0, None, 1.0,
                 member_ids[0], body_hash(clean_body)))
            self._index(sum_id, sum_title, clean_body, tag_str)
            for mid in member_ids:
                self.link(sum_id, mid, "derived_from")
                self.conn.execute(
                    "UPDATE mem SET supersedes=?, updated=? WHERE id=?",
                    (sum_id, ts, mid))
            merged_count += len(member_ids)
            created_count += 1
            summaries.append({
                "id": sum_id, "scope": grp_scope,
                "title": sum_title, "members": member_ids,
            })

        if not dry_run and created_count > 0:
            self.conn.execute(
                "INSERT INTO consolidation_log(id,ts,scope,merged,created,notes) VALUES(?,?,?,?,?,?)",
                (new_id(), now(), scope or "*", merged_count, created_count,
                 f"threshold={threshold:.2f}"))
        self.conn.commit()
        return {
            "dry_run": dry_run, "scope": scope or "*", "threshold": threshold,
            "clusters": len(clusters), "merged": merged_count,
            "created": created_count, "summaries": summaries,
        }

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass