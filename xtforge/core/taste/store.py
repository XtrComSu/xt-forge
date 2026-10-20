"""Taste store: SQLite state plus a human-editable markdown mirror.

SQLite is the source of truth; the markdown export is what a person reviews,
diffs and edits. Import merges by learning id and **never overwrites**: an
imported statement that disagrees raises `beta`, so the disagreement shows up
as a conflict instead of silently replacing what was learned.
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from . import learn as learnmod
from .schema import CATEGORIES, Learning, Signal, learning_id, normalize_key

SCHEMA_VERSION = 1

MIGRATION = """
CREATE TABLE IF NOT EXISTS taste_learning(
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  category TEXT NOT NULL,
  key TEXT NOT NULL,
  statement TEXT NOT NULL,
  polarity INTEGER NOT NULL,
  alpha REAL NOT NULL,
  beta REAL NOT NULL,
  evidence INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'weak',
  first_seen INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0,
  retired INTEGER NOT NULL DEFAULT 0,
  UNIQUE(scope, category, key)
);
CREATE INDEX IF NOT EXISTS idx_taste_scope ON taste_learning(scope);
CREATE INDEX IF NOT EXISTS idx_taste_status ON taste_learning(status);
CREATE TABLE IF NOT EXISTS taste_signal(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  learning_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  weight REAL NOT NULL,
  polarity INTEGER NOT NULL,
  quote TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tsignal_learning ON taste_signal(learning_id);
CREATE TABLE IF NOT EXISTS taste_meta(k TEXT PRIMARY KEY, v TEXT);
"""

_BULLET = re.compile(r"^\s*[-*]\s+(.*?)\s*<!--\s*id:\s*([0-9a-f]{6,64})\s*-->\s*$")
_FRONT = re.compile(r"^(category|confidence|status|evidence|updated):\s*(.+)$")


class TasteStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False,
                                    timeout=15.0)
        self.conn.row_factory = sqlite3.Row
        self._ensure_wal()
        self.conn.executescript(MIGRATION)
        self.conn.execute(
            "INSERT INTO taste_meta(k,v) VALUES('schema_version',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(SCHEMA_VERSION),))
        self.conn.commit()

    def _ensure_wal(self) -> None:
        """Put the store in WAL mode, tolerating a concurrent writer.

        Switching journal modes needs a brief exclusive lock. Another
        process that is mid-write holds it, and the pragma would fail with
        "database is locked" — which must not stop this process from
        opening the store it was asked to open.
        """
        for attempt in range(5):
            try:
                mode = self.conn.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() == "wal":
                    return
                self.conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError:
                if attempt == 4:
                    return          # the store still works without WAL
                time.sleep(0.1 * (attempt + 1))

    @contextlib.contextmanager
    def _write_txn(self):
        """A write transaction that takes the write lock *before* the read.

        Absorbing a signal is a read-modify-write: read the learning, add to
        it, write it back. Under SQLite's default deferred transaction the
        read happens outside the write lock, so two processes can both read
        the same row and both write it back — the second write overwrites the
        first's counter and a piece of evidence is lost. A rule stated by
        three concurrent sessions then never reaches `enforced`, and is never
        injected.

        `BEGIN IMMEDIATE` takes the lock first: the second writer waits for
        the first to commit, then reads the committed state.
        """
        if self.conn.in_transaction:
            yield                      # already in one: join it
            return
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    # ---------------------------- internals ----------------------------
    def _row(self, row) -> Learning:
        data = dict(row)
        data["retired"] = bool(data["retired"])
        return Learning.from_dict(data)

    def _load(self, rec_id: str) -> Learning | None:
        row = self.conn.execute("SELECT * FROM taste_learning WHERE id=?",
                                (rec_id,)).fetchone()
        return self._row(row) if row else None

    def _save(self, learning: Learning) -> None:
        self.conn.execute(
            "INSERT INTO taste_learning(id,scope,category,key,statement,"
            "polarity,alpha,beta,evidence,status,first_seen,last_seen,retired) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET statement=excluded.statement,"
            "polarity=excluded.polarity, alpha=excluded.alpha, "
            "beta=excluded.beta, evidence=excluded.evidence, "
            "status=excluded.status, last_seen=excluded.last_seen, "
            "retired=excluded.retired",
            (learning.id, learning.scope, learning.category, learning.key,
             learning.statement, learning.polarity, learning.alpha,
             learning.beta, learning.evidence, learning.status,
             learning.first_seen, learning.last_seen,
             1 if learning.retired else 0))

    def _record_signal(self, learning_id_: str, signal: Signal, created: int) -> None:
        self.conn.execute(
            "INSERT INTO taste_signal(learning_id,kind,weight,polarity,quote,"
            "source,created) VALUES(?,?,?,?,?,?,?)",
            (learning_id_, signal.kind, signal.weight, signal.polarity,
             signal.quote, signal.source, created))

    # ----------------------------- writes ------------------------------
    def ingest(self, signals: Iterable[Signal], scope: str = "global",
               now: int | None = None) -> list[dict[str, Any]]:
        """Fold signals into learnings. Returns one delta per signal.

        The whole batch is one write transaction: the read of the learning
        and the write of the result must not be separable, or two writers
        overwrite each other's counters.

        What stays arrival-ordered: the *statement* of a learning is the one
        its first piece of evidence carried, so two writers that race still
        disagree about the wording of the rule — the key, the polarity, the
        counters and the status do not depend on who won.
        """
        ts = int(now if now is not None else time.time())
        deltas = []
        with self._write_txn():
            for signal in signals:
                rec_id = learning_id(scope, signal.category, signal.key)
                learning = self._load(rec_id) or learnmod.new_learning(
                    signal, scope, ts)
                delta = learnmod.absorb(learning, signal, ts)
                delta["category"] = learning.category
                delta["statement"] = learning.statement
                self._save(learning)
                self._record_signal(learning.id, signal, ts)
                deltas.append(delta)
        return deltas

    def learn(self, statement: str, scope: str = "global",
              source: str = "manual", now: int | None = None) -> dict[str, Any]:
        """A human-authored learning: weight 1.0, first-class evidence."""
        from .extract import extract_one
        return self.ingest([extract_one(statement, source=source, scope=scope)],
                           scope=scope, now=now)[0]

    def forget(self, rec_id: str) -> bool:
        cur = self.conn.execute("UPDATE taste_learning SET retired=1, "
                                "status='retired' WHERE id=?", (rec_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def purge(self, rec_id: str) -> bool:
        self.conn.execute("DELETE FROM taste_signal WHERE learning_id=?", (rec_id,))
        cur = self.conn.execute("DELETE FROM taste_learning WHERE id=?", (rec_id,))
        self.conn.commit()
        return cur.rowcount > 0

    # ----------------------------- reads -------------------------------
    def get(self, rec_id: str) -> dict[str, Any] | None:
        learning = self._load(rec_id)
        return learning.to_dict() if learning else None

    def evidence(self, rec_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT kind, weight, polarity, quote, source, created "
            "FROM taste_signal WHERE learning_id=? ORDER BY id DESC LIMIT ?",
            (rec_id, limit)).fetchall()
        return [dict(row) for row in rows]

    def search(self, query: str = "", scope: str | None = None,
               category: str | None = None, status: str | None = None,
               limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM taste_learning WHERE 1=1"
        args: list[Any] = []
        if scope:
            sql += " AND scope=?"
            args.append(scope)
        if category:
            sql += " AND category=?"
            args.append(category)
        if status:
            sql += " AND status=?"
            args.append(status)
        rows = self.conn.execute(sql, args).fetchall()
        wanted = normalize_key(query)
        out = []
        for row in rows:
            learning = self._row(row)
            if wanted and wanted not in normalize_key(
                    f"{learning.key} {learning.statement} {learning.category}"):
                continue
            out.append(learning)
        out.sort(key=lambda l: (-l.confidence, -l.evidence, l.category, l.key))
        return [learning.to_dict() for learning in out[:limit]]

    def review(self, limit: int = 50) -> dict[str, Any]:
        """Conflicts and weak hints: what a human should look at."""
        rows = self.conn.execute(
            "SELECT * FROM taste_learning WHERE status IN ('conflict','weak','hint') "
            "ORDER BY status, category, key LIMIT ?", (limit,)).fetchall()
        conflicts, hints, weak = [], [], []
        for row in rows:
            learning = self._row(row)
            item = learning.to_dict()
            item["evidence_log"] = self.evidence(learning.id, limit=5)
            if learning.status == "conflict":
                conflicts.append(item)
            elif learning.status == "hint":
                hints.append(item)
            else:
                weak.append(item)
        return {"conflicts": conflicts, "hints": hints, "weak": weak}

    def enforced(self, scope: str | None = None,
                 limit: int = 50) -> list[dict[str, Any]]:
        return self.search(scope=scope, status="enforced", limit=limit)

    def stats(self) -> dict[str, Any]:
        rows = self.conn.execute("SELECT * FROM taste_learning").fetchall()
        learnings = [self._row(row) for row in rows]
        summary = learnmod.summarize(learnings)
        categories = {}
        for learning in learnings:
            categories[learning.category] = categories.get(learning.category, 0) + 1
        signals = self.conn.execute("SELECT COUNT(*) AS n FROM taste_signal").fetchone()
        return {**summary, "signals": signals["n"],
                "by_category": dict(sorted(categories.items())),
                "db": self.path}

    def all(self) -> list[Learning]:
        rows = self.conn.execute(
            "SELECT * FROM taste_learning ORDER BY category, key").fetchall()
        return [self._row(row) for row in rows]

    def prunable(self, limit: int = 100) -> list[dict[str, Any]]:
        """Learnings the current extractor would not produce any more.

        Rules change. A profile learned under looser rules keeps the keys
        those rules invented, and a key nobody can reproduce is noise that
        still counts as evidence. This re-runs the extractor over each
        learning's own evidence and reports the ones that no longer come
        out. Hand-written (`manual`) learnings are never prunable: they are
        not extractor output, they are the user.
        """
        from .extract import extract as extract_text
        out: list[dict[str, Any]] = []
        for learning in self.all():
            if learning.retired:
                continue
            log = self.evidence(learning.id, limit=20)
            if not log:
                continue
            if any(row.get("kind") == "manual" for row in log):
                continue
            keys: set[tuple[str, int]] = set()
            for row in log:
                for signal in extract_text(row.get("quote", "") or "",
                                           source=row.get("source", ""),
                                           scope=learning.scope):
                    keys.add((signal.key, signal.polarity))
            if (learning.key, learning.polarity) not in keys:
                item = learning.to_dict()
                item["evidence_log"] = log[:3]
                out.append(item)
            if len(out) >= limit:
                break
        return out

    # --------------------------- markdown ------------------------------
    def export(self, root: str | Path, scope: str | None = None) -> dict[str, Any]:
        """Write one `taste.md` per category. Returns the file list."""
        base = Path(root) / "taste" / (scope or "global")
        written: list[str] = []
        for category in CATEGORIES:
            rows = self.conn.execute(
                "SELECT * FROM taste_learning WHERE category=? AND scope=? "
                "ORDER BY key", (category, scope or "global")).fetchall()
            if not rows:
                continue
            learnings = [self._row(row) for row in rows]
            updated = max((learning.last_seen for learning in learnings), default=0)
            enforced = [learning for learning in learnings
                        if learning.status == "enforced"]
            body = [
                "---",
                f"category: {category}",
                f"confidence: {round(sum(l.confidence for l in learnings) / len(learnings), 2)}",
                f"status: {enforced and 'enforced' or learnings[0].status}",
                f"evidence: {sum(l.evidence for l in learnings)}",
                f"updated: {updated}",
                "---",
                f"# {category.title()}",
                "",
            ]
            for learning in sorted(learnings, key=lambda l: -l.confidence):
                body.append(f"- {learning.statement} <!-- id: {learning.id} -->")
            body.append("")
            path = base / f"{category}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(body), encoding="utf-8")
            written.append(str(path))
        return {"scope": scope or "global", "files": written,
                "count": len(written)}

    def import_markdown(self, path: str | Path, scope: str = "global",
                        now: int | None = None) -> dict[str, Any]:
        """Merge a package. Disagreement raises beta; it never overwrites."""
        import os
        ts = int(now if now is not None else time.time())
        text = Path(path).read_text(encoding="utf-8")
        category = "architecture"
        for line in text.splitlines():
            match = _FRONT.match(line.strip())
            if match and match.group(1) == "category":
                category = match.group(2).strip()
                break
        merged = disagreed = 0
        with self._write_txn():
            for line in text.splitlines():
                match = _BULLET.match(line)
                if not match:
                    continue
                statement, rec_id = match.group(1), match.group(2)
                existing = self._load(rec_id)
                if existing is None:
                    signal = Signal(kind="manual", polarity=1,
                                    category=category,
                                    key=normalize_key(statement),
                                    statement=statement, quote=statement,
                                    source=f"import:{os.path.basename(str(path))}")
                    learning = learnmod.new_learning(signal, scope, ts)
                    learning.id = rec_id
                    learnmod.absorb(learning, signal, ts)
                    self._save(learning)
                    self._record_signal(rec_id, signal, ts)
                    merged += 1
                    continue
                if normalize_key(existing.statement) == normalize_key(statement):
                    merged += 1
                    continue
                # Same id, different wording: treat as contradicting evidence.
                signal = Signal(kind="manual", polarity=-existing.polarity,
                                category=existing.category, key=existing.key,
                                statement=statement, quote=statement,
                                source=f"import:{os.path.basename(str(path))}")
                learnmod.absorb(existing, signal, ts)
                self._save(existing)
                self._record_signal(existing.id, signal, ts)
                disagreed += 1
        return {"merged": merged, "disagreed": disagreed, "path": str(path)}

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass
