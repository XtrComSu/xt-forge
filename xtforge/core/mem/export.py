"""Versioned JSONL export/import + merge-by-updated sync (F2 interop).

Header line: {"xt_export":1,"schema_version":N,"ts":...,"records":K}
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .scopes import is_valid_kind
from .store import Store, now

EXPORT_MAGIC = "xt_export"
EXPORT_VERSION = 1
COLUMNS = ("id", "scope", "kind", "title", "body", "tags", "source", "created",
           "updated", "last_used", "uses", "pin", "ttl", "confidence",
           "supersedes", "body_hash", "pending")


def export_jsonl(store: Store, path: str | Path, scopes: Iterable[str] | None = None) -> dict[str, Any]:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    from ...atomicio import atomic_write_text
    lines = [json.dumps({"xt_export": EXPORT_VERSION, "schema_version": 1,
                         "ts": now(), "records": 0}, sort_keys=True)]
    q = "SELECT * FROM mem"
    args: list[Any] = []
    if scopes:
        q += " WHERE scope IN (%s)" % ",".join("?" * len(list(scopes)))
        args = list(scopes)
    rows = store.conn.execute(q, args).fetchall()
    for r in rows:
        rec = {c: r[c] for c in COLUMNS}
        lines.append(json.dumps(rec, ensure_ascii=False, sort_keys=True))
    lines[0] = json.dumps({"xt_export": EXPORT_VERSION, "schema_version": 1,
                            "ts": now(), "records": len(rows)}, sort_keys=True)
    atomic_write_text(p, "\n".join(lines) + "\n")
    return {"path": str(p), "records": len(rows)}


def _parse(path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    header: dict[str, Any] = {}
    recs: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if lineno == 1 and isinstance(obj, dict) and obj.get("xt_export"):
                header = obj
                continue
            if isinstance(obj, dict):
                recs.append(obj)
    return header, recs


def import_jsonl(store: Store, path: str | Path, on_conflict: str = "newer") -> dict[str, Any]:
    """Merge records. on_conflict: newer (skip if store copy is newer) | overwrite."""
    header, recs = _parse(path)
    if not header:
        raise ValueError(f"{path}: missing xt_export header line")
    stats = {"inserted": 0, "updated": 0, "skipped": 0, "rejected": 0, "records": len(recs)}
    for rec in recs:
        if not rec.get("id") or not rec.get("kind") or not is_valid_kind(rec.get("kind", "")):
            stats["rejected"] += 1
            continue
        existing = store.get(rec["id"])
        if existing:
            if on_conflict == "newer" and (existing.get("updated") or 0) >= (rec.get("updated") or 0):
                stats["skipped"] += 1
                continue
            cols = {c: rec.get(c) for c in COLUMNS if c != "id"}
            sets = ",".join(f"{c}=?" for c in cols)
            store.conn.execute(f"UPDATE mem SET {sets} WHERE id=?",
                               (*cols.values(), rec["id"]))
            store._index(rec["id"], cols["title"], cols["body"], cols["tags"])
            stats["updated"] += 1
        else:
            cols = {c: rec.get(c) for c in COLUMNS}
            store.conn.execute(
                f"INSERT INTO mem({','.join(COLUMNS)}) VALUES({','.join('?' * len(COLUMNS))})",
                tuple(cols[c] for c in COLUMNS))
            store._index(rec["id"], cols["title"], cols["body"], cols["tags"])
            stats["inserted"] += 1
    store.conn.commit()
    return stats


def sync(store: Store, path: str | Path, conflict_log: str | Path | None = None) -> dict[str, Any]:
    header, recs = _parse(path)
    conflicts: list[dict[str, Any]] = []
    stats = {"inserted": 0, "updated": 0, "skipped": 0, "rejected": 0}
    for rec in recs:
        if not rec.get("id") or not is_valid_kind(rec.get("kind", "")):
            stats["rejected"] += 1
            continue
        existing = store.get(rec["id"])
        if existing and (existing.get("updated") or 0) != (rec.get("updated") or 0):
            conflicts.append({"id": rec["id"], "local_updated": existing.get("updated"),
                              "remote_updated": rec.get("updated")})
    if conflict_log:
        from ...atomicio import atomic_write_json
        atomic_write_json(conflict_log, {"ts": now(), "conflicts": conflicts})
    result = import_jsonl(store, path, on_conflict="newer")
    result["conflicts"] = len(conflicts)
    result["conflict_log"] = str(conflict_log) if conflict_log else None
    return result