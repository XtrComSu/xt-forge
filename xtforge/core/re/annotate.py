"""Stateful binary annotation overlay (`re_overlay.db`) matching Rust `re_fast.rs`."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from ..route import guard
from ...version import xt_home

OVERLAY_SCHEMA = """
CREATE TABLE IF NOT EXISTS binaries (
  sha256 TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  format TEXT NOT NULL,
  size INTEGER NOT NULL,
  updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS annotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL,
  rva INTEGER NOT NULL,
  kind TEXT NOT NULL,
  orig_name TEXT NOT NULL DEFAULT '',
  new_name TEXT NOT NULL DEFAULT '',
  type_decl TEXT NOT NULL DEFAULT '',
  comment TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 1.0,
  updated INTEGER NOT NULL,
  UNIQUE(sha256, rva, kind)
);
CREATE INDEX IF NOT EXISTS idx_ann_sha ON annotations(sha256);
"""


def parse_rva(val: str | int) -> int:
    if isinstance(val, int):
        return val
    s = str(val).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def sniff_format(data: bytes) -> str:
    if len(data) >= 4:
        if data[:4] == b"\x7fELF":
            return "elf"
        if data[:2] == b"MZ":
            return "pe"
        if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                        b"\xca\xfe\xba\xbe"):
            return "macho"
    return "raw"


def overlay_db_path() -> Path:
    return xt_home() / "re_overlay.db"


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    p = db_path or overlay_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(OVERLAY_SCHEMA)
    return conn


def binary_sha256(path: str | Path) -> tuple[Path, str, str, int]:
    canon = guard.read_guard(path)
    data = canon.read_bytes()
    return canon, hashlib.sha256(data).hexdigest(), sniff_format(data), len(data)


def annotate(
    *,
    action: str,
    binary: str | Path,
    rva: str | int = 0,
    name: str = "",
    orig: str = "",
    comment: str = "",
    type_decl: str = "",
    confidence: float = 1.0,
    fmt: str = "json",
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Create, list, or export binary overlay annotations keyed by SHA-256."""
    canon, sha, sniff, size = binary_sha256(binary)
    conn = _connect(db_path)
    ts = int(time.time())
    try:
        conn.execute(
            "INSERT INTO binaries(sha256,name,format,size,updated) VALUES(?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET updated=excluded.updated",
            (sha, canon.name, sniff, size, ts),
        )
        if action in ("rename", "comment", "type"):
            addr = parse_rva(rva)
            conn.execute(
                "INSERT INTO annotations(sha256,rva,kind,orig_name,new_name,type_decl,comment,confidence,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(sha256,rva,kind) DO UPDATE SET "
                "new_name=excluded.new_name, orig_name=excluded.orig_name, "
                "type_decl=excluded.type_decl, comment=excluded.comment, "
                "confidence=excluded.confidence, updated=excluded.updated",
                (sha, addr, action, orig, name, type_decl, comment, confidence, ts),
            )
            conn.commit()
            return {
                "ok": True, "action": action, "sha256": sha,
                "rva": hex(addr), "name": name, "orig": orig,
                "comment": comment, "type_decl": type_decl, "engine": "python",
            }

        rows = [
            {
                "rva": hex(r["rva"]),
                "rva_int": r["rva"],
                "kind": r["kind"],
                "orig_name": r["orig_name"],
                "new_name": r["new_name"],
                "type_decl": r["type_decl"],
                "comment": r["comment"],
                "confidence": r["confidence"],
                "updated": r["updated"],
            }
            for r in conn.execute(
                "SELECT rva,kind,orig_name,new_name,type_decl,comment,confidence,updated "
                "FROM annotations WHERE sha256=? ORDER BY rva",
                (sha,),
            ).fetchall()
        ]
        if action == "export":
            if fmt == "r2":
                lines = []
                for item in rows:
                    if item["kind"] == "rename" and item["new_name"]:
                        lines.append(f"afn {item['new_name']} @ {item['rva']}")
                    elif item["kind"] == "comment" and item["comment"]:
                        b64 = item["comment"].replace('"', "'")
                        lines.append(f"CC {b64} @ {item['rva']}")
                return {"ok": True, "sha256": sha, "format": "r2", "script": "\n".join(lines)}
            if fmt == "ghidra":
                lines = []
                for item in rows:
                    if item["kind"] == "rename" and item["new_name"]:
                        lines.append(f"rename({item['rva']}, {json.dumps(item['new_name'])})")
                    elif item["kind"] == "comment" and item["comment"]:
                        lines.append(f"setEOLComment({item['rva']}, {json.dumps(item['comment'])})")
                return {"ok": True, "sha256": sha, "format": "ghidra", "script": "\n".join(lines)}
            return {"ok": True, "sha256": sha, "format": "json", "annotations": rows}

        return {
            "ok": True, "sha256": sha, "binary": canon.name,
            "count": len(rows), "annotations": rows, "engine": "python",
        }
    finally:
        conn.close()


def overlay_map_for_binary(binary: str | Path, db_path: Path | None = None) -> dict[str, Any]:
    """Return quick lookup maps {renames_by_rva, renames_by_orig, comments_by_rva, count}."""
    p = db_path or overlay_db_path()
    if not p.is_file():
        return {"count": 0, "renames_by_rva": {}, "renames_by_orig": {}, "comments_by_rva": {}}
    try:
        _, sha, _, _ = binary_sha256(binary)
    except Exception:
        return {"count": 0, "renames_by_rva": {}, "renames_by_orig": {}, "comments_by_rva": {}}
    conn = _connect(p)
    try:
        rows = conn.execute(
            "SELECT rva,kind,orig_name,new_name,comment FROM annotations WHERE sha256=?",
            (sha,),
        ).fetchall()
    finally:
        conn.close()
    renames_rva: dict[str, str] = {}
    renames_orig: dict[str, str] = {}
    comments_rva: dict[str, str] = {}
    for r in rows:
        hx = hex(r["rva"]).lower()
        if r["kind"] == "rename" and r["new_name"]:
            renames_rva[hx] = r["new_name"]
            if r["orig_name"]:
                renames_orig[r["orig_name"]] = r["new_name"]
        elif r["kind"] == "comment" and r["comment"]:
            comments_rva[hx] = r["comment"]
    return {
        "count": len(rows),
        "renames_by_rva": renames_rva,
        "renames_by_orig": renames_orig,
        "comments_by_rva": comments_rva,
    }
