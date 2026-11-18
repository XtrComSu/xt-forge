"""Route tools (F6): tree / find / grep / peek / du / recent / where / index.

Every tool returns the standard envelope:
  {"ok":bool,"data":…,"err":null|str,"ms":int,"truncated":bool}
"""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from ...version import cache_dir
from . import caps, guard, reference as ref

TOKEN_CAP = 4000


def envelope(ok: bool, data: Any = None, err: str | None = None, ms: int = 0,
             truncated: bool = False) -> dict[str, Any]:
    return {"ok": ok, "data": data, "err": err, "ms": ms, "truncated": truncated}


def _clip(obj: Any, cap: int = TOKEN_CAP) -> tuple[Any, bool]:
    text = repr(obj)
    if len(text) <= cap * 4:
        return obj, False
    return {"_clipped": True, "_preview": text[:cap * 2],
            "_note": f"output exceeded {cap} tokens"}, True


def route_tree(path: str, depth: int = 2, max_items: int = 200) -> dict[str, Any]:
    try:
        canon = guard.read_guard(path)
    except guard.Denied as d:
        return envelope(False, err=f"{d.code}: {d.reason}")
    if not canon.exists():
        return envelope(False, err=f"not_found: {canon}")
    res = caps.pick("xtscan", ["--tree", str(canon), "--depth", str(depth),
                               "--max", str(max_items)],
                    lambda: ref.tree_py(canon, depth=depth, max_items=max_items))
    data, trunc = _clip(res["data"])
    return envelope(True, data, ms=res["ms"], truncated=trunc)


def route_find(root: str, name: str | None = None, regex: str | None = None,
               type_: str | None = None, min_size: int = -1,
               limit: int = 50) -> dict[str, Any]:
    try:
        canon = guard.read_guard(root)
    except guard.Denied as d:
        return envelope(False, err=f"{d.code}: {d.reason}")
    args = ["--find", str(canon), "--limit", str(limit)]
    if name:
        args += ["--name", name]
    if regex:
        args += ["--regex", regex]
    if type_:
        args += ["--type", type_]
    if min_size >= 0:
        args += ["--minsize", str(min_size)]
    res = caps.pick("xtscan", args,
                    lambda: {"root": str(canon), "results": ref.find_py(
                        canon, name=name, regex=regex, type_=type_,
                        min_size=min_size, limit=limit)})
    data, trunc = _clip(res["data"])
    return envelope(True, data, ms=res["ms"], truncated=trunc)


def route_grep(root: str, pattern: str, glob: str | None = None, context: int = 1,
               limit: int = 50) -> dict[str, Any]:
    try:
        canon = guard.read_guard(root)
    except guard.Denied as d:
        return envelope(False, err=f"{d.code}: {d.reason}")
    args = ["--grep", str(canon), "--pattern", pattern, "--context", str(context),
            "--limit", str(limit)]
    if glob:
        args += ["--glob", glob]
    res = caps.pick("xtscan", args,
                    lambda: {"root": str(canon), "pattern": pattern,
                             "matches": ref.grep_py(canon, pattern, glob=glob,
                                                   context=context, limit=limit)})
    data, trunc = _clip(res["data"])
    return envelope(True, data, ms=res["ms"], truncated=trunc)


def route_peek(path: str, mode: str = "head", start: int = 1, count: int = 50) -> dict[str, Any]:
    try:
        canon = guard.read_guard(path)
    except guard.Denied as d:
        return envelope(False, err=f"{d.code}: {d.reason}")
    if not canon.exists():
        return envelope(False, err=f"not_found: {canon}")
    if canon.is_dir():
        return route_tree(str(canon), depth=1)
    args = ["--outline", str(canon)] if mode == "outline" else \
           ["--lines", str(canon), "--start", str(start), "--count", str(count)]
    res = caps.pick("xtdigest", args,
                    lambda: ref.outline_py(canon) if mode == "outline" else
                    {"path": str(canon), "start": start,
                     "lines": [{"line": i, "text": l} for i, l in
                               enumerate(_slice(canon, start, count), start)]})
    data, trunc = _clip(res["data"])
    return envelope(True, data, ms=res["ms"], truncated=trunc)


def _slice(path: Path, start: int, count: int) -> list[str]:
    try:
        lines = ref.split_lines(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    s = max(1, start) - 1
    return lines[s:s + max(0, count)]


def route_du(path: str, top: int = 15) -> dict[str, Any]:
    try:
        canon = guard.read_guard(path)
    except guard.Denied as d:
        return envelope(False, err=f"{d.code}: {d.reason}")
    res = caps.pick("xtscan", ["--du", str(canon), "--top", str(top)],
                    lambda: {"path": str(canon), "top": ref.du_py(canon, top=top)})
    data, trunc = _clip(res["data"])
    return envelope(True, data, ms=res["ms"], truncated=trunc)


def route_recent(roots: list[str], minutes: int = 60, limit: int = 30) -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    t0 = time.perf_counter()
    for r in roots:
        try:
            canon = guard.read_guard(r)
        except guard.Denied as d:
            out.append({"root": r, "error": d.reason})
            continue
        res = caps.pick("xtscan", ["--recent", str(canon), "--minutes", str(minutes),
                                   "--limit", str(limit)],
                        lambda c=canon: {"root": str(c), "recent": ref.recent_py(
                            c, minutes=minutes, limit=limit)})
        out.append(res["data"])
    data, trunc = _clip(out)
    return envelope(True, data, ms=int((time.perf_counter() - t0) * 1000),
                    truncated=trunc)


# ---------- persistent index (route_where) ----------

def index_db() -> Path:
    return cache_dir() / "index.sqlite"


def build_index(roots: list[str], incremental: bool = True) -> dict[str, Any]:
    db = index_db()
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS files("
                 "path TEXT PRIMARY KEY, name TEXT, size INT, mtime INT, root TEXT)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_name ON files(name)")
    conn.commit()
    seen = 0
    added = 0
    seen_paths: set[str] = set()
    canon_roots: list[str] = []
    for r in roots:
        try:
            canon = guard.read_guard(r)
        except guard.Denied:
            continue
        canon_roots.append(str(canon))
        for e in ref.walk_py(canon, limit=200_000):
            seen += 1
            seen_paths.add(e["path"])
            row = conn.execute("SELECT mtime FROM files WHERE path=?",
                               (e["path"],)).fetchone()
            if incremental and row and row[0] == e["mtime"]:
                continue
            conn.execute("INSERT INTO files(path,name,size,mtime,root) VALUES(?,?,?,?,?) "
                         "ON CONFLICT(path) DO UPDATE SET size=excluded.size,"
                         "mtime=excluded.mtime", (e["path"], os.path.basename(e["path"]),
                                                  e["size"], e["mtime"], str(canon)))
            added += 1
            if added % 5000 == 0:
                conn.commit()
    for (p,) in list(conn.execute("SELECT path FROM files")):
        under = any(p == cr or p.startswith(cr.rstrip("/\\") + os.sep) for cr in canon_roots)
        if p not in seen_paths and (under or not os.path.exists(p)):
            conn.execute("DELETE FROM files WHERE path=?", (p,))
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    conn.close()
    return {"ok": True, "db": str(db), "scanned": seen, "changed": added, "total": total}


def route_where(filename: str, limit: int = 20) -> dict[str, Any]:
    db = index_db()
    if not db.exists():
        return envelope(False, err="index missing; run `xt-forge route index` first")
    t0 = time.perf_counter()
    conn = sqlite3.connect(str(db))
    rows = conn.execute("SELECT path,size,mtime FROM files WHERE name LIKE ? "
                        "ORDER BY mtime DESC LIMIT ?", (f"%{filename}%", limit * 2)).fetchall()
    data = []
    stale = []
    for p, s, m in rows:
        if os.path.exists(p):
            data.append({"path": p, "size": s, "mtime": m})
            if len(data) >= limit:
                break
        else:
            stale.append(p)
    if stale:
        conn.executemany("DELETE FROM files WHERE path=?", [(s,) for s in stale])
        conn.commit()
    conn.close()
    return envelope(True, {"matches": data, "count": len(data)},
                    ms=int((time.perf_counter() - t0) * 1000))