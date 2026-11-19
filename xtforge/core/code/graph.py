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


def default_graph_db(root: str | Path = ".") -> Path:
    try:
        canon = guard.read_guard(root)
    except Exception:
        canon = Path(root).resolve()
    dig = hashlib.sha256(str(canon).encode("utf-8", errors="replace")).hexdigest()[:16]
    return xt_home() / "code_graphs" / f"{dig}.db"


def _connect(db_path: Path | None = None, *, root: str | Path = ".") -> sqlite3.Connection:
    p = db_path or default_graph_db(root)
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
    conn = _connect(db_path, root=canon)
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
        stale_files: list[str] = []
        removed_files: list[str] = []
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
            stale_files.append(fstr)
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
                removed_files.append(stale)
        conn.commit()
        tot_s = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        tot_e = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        return {
            "ok": True, "root": str(canon),
            "files_seen": len(files), "files_updated": updated, "files_cached": cached,
            "files_removed": removed,
            "stale_detected": updated > 0 or removed > 0,
            "stale_files": stale_files[:20],
            "removed_files": removed_files[:20],
            "new_symbols": new_syms, "new_edges": new_edges,
            "total_symbols": tot_s, "total_edges": tot_e,
            "ms": int((time.monotonic() - t0) * 1000),
            "engine": "python",
        }
    finally:
        conn.close()


def _is_test_path(path_str: str) -> bool:
    low = path_str.lower().replace("\\", "/")
    if "/tests/" in low or "/test/" in low or low.startswith("tests/"):
        return True
    fn = Path(low).name
    return fn.startswith("test_") or fn.endswith(("_test.py", "_test.rs", "_test.go")) or ".test." in fn or ".spec." in fn


def _read_excerpt(file_path: str, line: int) -> str:
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not lines or line <= 0:
        return ""
    idx = line - 1
    s = max(0, idx - 1)
    e = min(len(lines), idx + 2)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(s, e))


def _dotted_module(root: str | Path, file_path: str) -> str:
    try:
        rel = Path(file_path).relative_to(Path(root).resolve())
    except Exception:
        rel = Path(file_path)
    s = str(rel).replace("\\", "/")
    for ext in (".py", ".rs", ".go"):
        if s.endswith(ext):
            s = s[: -len(ext)]
            break
    if s.endswith("/__init__"):
        s = s[:-9]
    return s.replace("/", ".")


def _classify_caller_edge(file_path: str, symbol: str, def_modules: list[str]) -> tuple[str, str]:
    try:
        txt = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "text_match_call", "medium"
    for line in txt.splitlines():
        t = line.strip()
        if (t.startswith("from ") or t.startswith("import ") or t.startswith("use ")) and symbol in t:
            return "import_resolved_call", "high"
        if t.startswith("import ") and any(m and m in t for m in def_modules):
            return "import_resolved_call", "high"
    if f"def {symbol}(" in txt or f"fn {symbol}(" in txt:
        return "local_same_file_call", "medium"
    return "text_match_call", "medium"


_BUILTIN_CALLEES = {
    "get", "int", "str", "float", "bool", "list", "dict", "set", "tuple",
    "len", "append", "extend", "items", "keys", "values", "pop", "update",
    "join", "split", "strip", "lstrip", "rstrip", "lower", "upper", "replace",
    "format", "print", "range", "enumerate", "zip", "sorted", "reversed",
    "min", "max", "sum", "abs", "round", "any", "all", "isinstance",
    "hasattr", "getattr", "setattr", "Exception", "ValueError", "RuntimeError",
    "TypeError", "KeyError", "Path", "Decimal", "ROUND_HALF_UP",
}


def query_graph(symbol: str, *, root: str | Path = ".", depth: int = 2,
                db_path: Path | None = None) -> dict[str, Any]:
    t0 = time.monotonic()
    idx = index_workspace(root, db_path=db_path)
    conn = _connect(db_path, root=root)
    try:
        mod_filter: str | None = None
        query_sym = symbol
        if "." in symbol:
            m, s = symbol.rsplit(".", 1)
            if m and s:
                mod_filter, query_sym = m, s

        defs_raw = [dict(r) for r in conn.execute(
            "SELECT file_path AS file, name, kind, line, signature FROM symbols WHERE name=? LIMIT 25",
            (query_sym,),
        )]
        defs: list[dict[str, Any]] = []
        def_modules: list[str] = []
        for d in defs_raw:
            is_t = _is_test_path(d["file"])
            mod = _dotted_module(root, d["file"])
            if not is_t and mod:
                def_modules.append(mod)
            d["module"] = mod
            d["is_test"] = is_t
            d["excerpt"] = _read_excerpt(d["file"], int(d["line"]))
            defs.append(d)
        if mod_filter:
            matched = [d for d in defs if d["module"] == mod_filter or d["module"].endswith(f".{mod_filter}")]
            if matched:
                defs = matched
        if not defs:
            defs_raw = [dict(r) for r in conn.execute(
                "SELECT file_path AS file, name, kind, line, signature FROM symbols WHERE name LIKE ? LIMIT 25",
                (f"%{query_sym}%",),
            )]
            for d in defs_raw:
                is_t = _is_test_path(d["file"])
                mod = _dotted_module(root, d["file"])
                if not is_t and mod:
                    def_modules.append(mod)
                d["module"] = mod
                d["is_test"] = is_t
                d["excerpt"] = _read_excerpt(d["file"], int(d["line"]))
                defs.append(d)

        callers: list[dict[str, Any]] = []
        production_callers: list[dict[str, Any]] = []
        unresolved_candidates: list[dict[str, Any]] = []
        callees: list[dict[str, Any]] = []
        seen_up = {query_sym}
        seen_down = {query_sym}
        seen_caller_edges: set[tuple[str, str, str, int]] = set()
        seen_callee_edges: set[tuple[str, str, str, int]] = set()
        cq: deque[tuple[str, int]] = deque([(query_sym, 0)])
        dq: deque[tuple[str, int]] = deque([(query_sym, 0)])
        while cq:
            cur, d = cq.popleft()
            if d >= depth:
                continue
            for r in conn.execute("SELECT src_name, rel, file_path, line FROM edges WHERE dst_name=? LIMIT 40", (cur,)):
                ekey = (r["src_name"], cur, r["file_path"], int(r["line"]))
                if ekey in seen_caller_edges:
                    continue
                seen_caller_edges.add(ekey)
                is_t = _is_test_path(r["file_path"])
                how, conf = _classify_caller_edge(r["file_path"], cur, def_modules)
                item = {
                    "caller": r["src_name"], "target": cur, "rel": r["rel"],
                    "file": r["file_path"], "line": r["line"], "hop": d + 1,
                    "is_test": is_t, "how": how, "confidence": conf,
                    "excerpt": _read_excerpt(r["file_path"], int(r["line"])),
                }
                if is_t or how == "local_same_file_call":
                    cand = dict(item)
                    cand["reason"] = "test_file_caller" if is_t else "shadowed_local_definition"
                    unresolved_candidates.append(cand)
                else:
                    production_callers.append(dict(item))
                callers.append({
                    "caller": r["src_name"], "target": cur,
                    "file": r["file_path"], "line": r["line"], "is_test": is_t,
                })
                if r["src_name"] not in seen_up and d + 1 < depth:
                    seen_up.add(r["src_name"])
                    cq.append((r["src_name"], d + 1))
        while dq:
            cur, d = dq.popleft()
            if d >= depth:
                continue
            for r in conn.execute("SELECT dst_name, rel, file_path, line FROM edges WHERE src_name=? LIMIT 40", (cur,)):
                if r["dst_name"] in _BUILTIN_CALLEES:
                    continue
                ekey = (cur, r["dst_name"], r["file_path"], int(r["line"]))
                if ekey in seen_callee_edges:
                    continue
                seen_callee_edges.add(ekey)
                callees.append({"caller": cur, "target": r["dst_name"], "rel": r["rel"],
                                "file": r["file_path"], "line": r["line"], "hop": d + 1})
                if r["dst_name"] not in seen_down and d + 1 < depth:
                    seen_down.add(r["dst_name"])
                    dq.append((r["dst_name"], d + 1))

        prod_defs = sum(1 for d in defs if not d["is_test"])
        ambiguous = len(defs) > 1
        prod_ambiguous = prod_defs > 1
        ambiguity_reason = (
            "multiple_production_definitions" if prod_ambiguous
            else ("test_or_shadow_only" if ambiguous else None)
        )
        follow_up = None
        if prod_ambiguous:
            follow_up = f"Multiple non-test definitions of '{query_sym}' found ({prod_defs}); inspect module imports to disambiguate."
        elif not production_callers:
            follow_up = "No import-resolved or text production callers found; consider route_grep if called dynamically."

        return {
            "ok": True, "symbol": symbol, "depth": depth,
            "ambiguous": ambiguous,
            "production_ambiguous": prod_ambiguous,
            "ambiguity_reason": ambiguity_reason,
            "evidence_complete": (not prod_ambiguous) and bool(production_callers) and not idx["stale_detected"],
            "definitions": defs,
            "production_callers": production_callers,
            "callers": callers,
            "unresolved_candidates": unresolved_candidates,
            "callees": callees,
            "index_status": {
                "stale_detected": idx["stale_detected"],
                "stale_files": idx["stale_files"],
                "files_updated": idx["files_updated"],
                "files_removed": idx["files_removed"],
                "refreshed": True,
            },
            "follow_up": follow_up,
            "ms": int((time.monotonic() - t0) * 1000), "engine": "python",
        }
    finally:
        conn.close()
