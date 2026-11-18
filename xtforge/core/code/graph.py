"""Multi-language regex symbol & call/import graph (`code_graph.db`) mirroring Rust `code_graph.rs`."""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
from collections import deque
from pathlib import Path
from typing import Any

from ..route import guard
from ...version import xt_home

GRAPH_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
  path TEXT PRIMARY KEY,
  lang TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  mtime INTEGER NOT NULL,
  loc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS symbols (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_path TEXT NOT NULL,
  name TEXT NOT NULL,
  fqname TEXT NOT NULL,
  kind TEXT NOT NULL,
  line INTEGER NOT NULL,
  signature TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sym_file ON symbols(file_path);
CREATE INDEX IF NOT EXISTS idx_sym_name ON symbols(name);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src_name TEXT NOT NULL,
  dst_name TEXT NOT NULL,
  rel TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line INTEGER NOT NULL,
  UNIQUE(src_name, dst_name, rel, file_path, line)
);
CREATE INDEX IF NOT EXISTS idx_edge_src ON edges(src_name);
CREATE INDEX IF NOT EXISTS idx_edge_dst ON edges(dst_name);
"""

EXT_LANG = {
    ".py": "python", ".rs": "rust", ".go": "go",
    ".js": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
}
SKIP_DIRS = {"target", "node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".xt-forge"}
KEYWORDS = {
    "if", "for", "while", "switch", "catch", "match", "return", "sizeof", "typeof",
    "new", "fn", "def", "func", "class", "struct", "enum", "import", "from", "use",
    "print", "len", "str", "int", "float", "bool", "list", "dict", "set", "tuple",
}
RE_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RE_PY_CLS = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_RS_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_GO_FN = re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RE_JS_FN = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
RE_JS_CLS = re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)")
RE_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")


def default_graph_db() -> Path:
    return xt_home() / "code_graph.db"


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    p = db_path or default_graph_db()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(GRAPH_SCHEMA)
    return conn


def _parse_source(lang: str, text: str) -> tuple[list[tuple[str, str, int, str]], list[tuple[str, str, str, int]]]:
    syms: list[tuple[str, str, int, str]] = []
    edges: list[tuple[str, str, str, int]] = []
    current_fn = "<module>"
    for idx, line in enumerate(text.splitlines(), start=1):
        decl: tuple[str, str] | None = None
        if lang == "python":
            m = RE_PY_DEF.match(line)
            if m:
                decl = ("function", m.group(1))
            elif (m := RE_PY_CLS.match(line)):
                decl = ("class", m.group(1))
        elif lang == "rust":
            if (m := RE_RS_FN.match(line)):
                decl = ("function", m.group(1))
        elif lang == "go":
            if (m := RE_GO_FN.match(line)):
                decl = ("function", m.group(1))
        elif lang in ("javascript", "typescript"):
            if (m := RE_JS_FN.match(line)):
                decl = ("function", m.group(1))
            elif (m := RE_JS_CLS.match(line)):
                decl = ("class", m.group(1))

        if decl:
            kind, name = decl
            syms.append((kind, name, idx, line.strip()[:160]))
            if kind == "function":
                current_fn = name
            continue

        for cm in RE_CALL.finditer(line):
            callee = cm.group(1)
            if callee not in KEYWORDS and callee != current_fn:
                edges.append((current_fn, callee, "calls", idx))
    return syms, edges


def index_workspace(root: str | Path = ".", *, db_path: Path | None = None) -> dict[str, Any]:
    t0 = time.monotonic()
    canon = guard.read_guard(root)
    conn = _connect(db_path)
    try:
        existing = {r["path"]: r["sha256"] for r in conn.execute("SELECT path, sha256 FROM files")}
        files: list[Path] = []
        if canon.is_file():
            files = [canon]
        else:
            def walk(cur: Path) -> None:
                if len(files) >= 1500:
                    return
                try:
                    entries = sorted(cur.iterdir())
                except OSError:
                    return
                for e in entries:
                    if e.is_dir():
                        if e.name not in SKIP_DIRS and not e.name.startswith("."):
                            walk(e)
                    elif e.suffix.lower() in EXT_LANG:
                        files.append(e)
            walk(canon)

        updated = 0
        cached = 0
        removed = 0
        new_syms = 0
        new_edges = 0
        seen_paths: set[str] = set()
        for f in files:
            lang = EXT_LANG.get(f.suffix.lower())
            if not lang:
                continue
            try:
                raw = f.read_bytes()
            except OSError:
                continue
            if len(raw) > 1_000_000:
                continue
            sha = hashlib.sha256(raw).hexdigest()
            fstr = str(f)
            seen_paths.add(fstr)
            if existing.get(fstr) == sha:
                cached += 1
                continue
            text = raw.decode("utf-8", errors="replace")
            syms, edges = _parse_source(lang, text)
            mtime = int(f.stat().st_mtime)
            loc = text.count("\n") + (1 if text else 0)
            conn.execute("DELETE FROM symbols WHERE file_path=?", (fstr,))
            conn.execute("DELETE FROM edges WHERE file_path=?", (fstr,))
            conn.execute(
                "INSERT INTO files(path,lang,sha256,mtime,loc) VALUES(?,?,?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET lang=excluded.lang, sha256=excluded.sha256, mtime=excluded.mtime, loc=excluded.loc",
                (fstr, lang, sha, mtime, loc),
            )
            for kind, name, ln, sig in syms:
                conn.execute(
                    "INSERT INTO symbols(file_path,name,fqname,kind,line,signature) VALUES(?,?,?,?,?,?)",
                    (fstr, name, name, kind, ln, sig),
                )
                new_syms += 1
            for src, dst, rel, ln in edges:
                conn.execute(
                    "INSERT OR IGNORE INTO edges(src_name,dst_name,rel,file_path,line) VALUES(?,?,?,?,?)",
                    (src, dst, rel, fstr, ln),
                )
                new_edges += 1
            updated += 1
        canon_str = str(canon)
        canon_prefix = canon_str.rstrip("/\\") + os.sep
        for stale in list(existing.keys()):
            under_root = stale == canon_str or stale.startswith(canon_prefix)
            if stale not in seen_paths and (under_root or not Path(stale).exists()):
                conn.execute("DELETE FROM symbols WHERE file_path=?", (stale,))
                conn.execute("DELETE FROM edges WHERE file_path=?", (stale,))
                conn.execute("DELETE FROM files WHERE path=?", (stale,))
                removed += 1
        conn.commit()
        tot_s = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        tot_e = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        return {
            "ok": True, "root": str(canon),
            "files_seen": len(files), "files_updated": updated, "files_cached": cached,
            "files_removed": removed,
            "new_symbols": new_syms, "new_edges": new_edges,
            "total_symbols": tot_s, "total_edges": tot_e,
            "ms": int((time.monotonic() - t0) * 1000),
            "engine": "python",
        }
    finally:
        conn.close()


def query_graph(symbol: str, *, root: str | Path = ".", depth: int = 2,
                db_path: Path | None = None) -> dict[str, Any]:
    t0 = time.monotonic()
    index_workspace(root, db_path=db_path)
    conn = _connect(db_path)
    try:
        defs = [dict(r) for r in conn.execute(
            "SELECT file_path AS file, name, kind, line, signature FROM symbols WHERE name=? LIMIT 20",
            (symbol,),
        )]
        callers: list[dict[str, Any]] = []
        callees: list[dict[str, Any]] = []
        seen = {symbol}
        q: deque[tuple[str, int]] = deque([(symbol, 0)])
        while q:
            cur, d = q.popleft()
            if d >= depth:
                continue
            for r in conn.execute("SELECT src_name, rel, file_path, line FROM edges WHERE dst_name=? LIMIT 40", (cur,)):
                callers.append({"caller": r["src_name"], "target": cur, "rel": r["rel"],
                                "file": r["file_path"], "line": r["line"], "hop": d + 1})
                if r["src_name"] not in seen and d + 1 < depth:
                    seen.add(r["src_name"])
                    q.append((r["src_name"], d + 1))
            for r in conn.execute("SELECT dst_name, rel, file_path, line FROM edges WHERE src_name=? LIMIT 40", (cur,)):
                callees.append({"caller": cur, "target": r["dst_name"], "rel": r["rel"],
                                "file": r["file_path"], "line": r["line"], "hop": d + 1})
                if r["dst_name"] not in seen and d + 1 < depth:
                    seen.add(r["dst_name"])
                    q.append((r["dst_name"], d + 1))
        return {
            "ok": True, "symbol": symbol, "depth": depth,
            "definitions": defs, "callers": callers, "callees": callees,
            "ms": int((time.monotonic() - t0) * 1000), "engine": "python",
        }
    finally:
        conn.close()
