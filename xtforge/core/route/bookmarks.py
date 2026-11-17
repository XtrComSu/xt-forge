"""route_resolve: fuzzy/bookmarked names -> absolute paths (F6).

Bookmarks live in universal memory as kind=device records, so they travel with
the agent across harnesses.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..mem.scopes import GLOBAL
from . import guard

BUILTIN: dict[str, str] = {
    "home": "~",
    "termux home": "~",
    "termux_home": "~",
    "downloads": "~/storage/shared/Download",
    "download": "~/storage/shared/Download",
    "dcim": "~/storage/shared/DCIM",
    "pictures": "~/storage/shared/Pictures",
    "movies": "~/storage/shared/Movies",
    "documents": "~/storage/shared/Documents",
    "sdcard": "/sdcard",
    "tmp": "/tmp",
    "workspace": "~/xt-forge",
    "project": "~/xt-forge",
}


def resolve(query: str, store: Any = None, limit: int = 5) -> dict[str, Any]:
    """Resolve a fuzzy name to candidates with confidence + liveness."""
    raw = (query or "").strip()
    if not raw:
        return {"ok": False, "err": "empty query"}
    q = raw.lower()
    lookup: dict[str, str] = dict(BUILTIN)
    if store is not None:
        for rec in store.list(scope=GLOBAL, kind="device", limit=100):
            name = str(rec.get("title") or "").strip().lower()
            if name:
                lookup[name] = str(rec.get("body") or "")
    cands: list[dict[str, Any]] = []
    for name, target in lookup.items():
        conf = _confidence(q, name)
        if conf <= 0:
            continue
        p = Path(os.path.expandvars(target)).expanduser()
        cands.append({"name": name, "path": str(p), "confidence": conf})
    if raw.startswith(("/", "~", ".")) or os.path.exists(os.path.expanduser(raw)):
        p = Path(raw).expanduser()
        cands.append({"name": "literal", "path": str(p), "confidence": 1.0})
    cands.sort(key=lambda c: -c["confidence"])
    cands = cands[:limit]
    for c in cands:
        try:
            canon = guard.canonical(c["path"])
            st = canon.stat()
            c.update({"exists": True, "is_dir": canon.is_dir(),
                      "size": st.st_size, "mtime": int(st.st_mtime),
                      "real": str(canon)})
        except (OSError, ValueError):
            c.update({"exists": False, "is_dir": False, "size": None, "mtime": None})
    return {"ok": True, "data": {"query": raw, "candidates": cands}}


def _confidence(query: str, name: str) -> float:
    if query == name:
        return 1.0
    if query in name:
        return 0.6 + 0.3 * (len(query) / max(1, len(name)))
    qt = set(query.split())
    nt = set(name.replace("-", " ").replace("_", " ").split())
    if qt and qt <= nt:
        return 0.5
    return 0.0


def add_bookmark(name: str, path: str, store: Any) -> dict[str, Any]:
    canon = guard.canonical(path)
    if not canon.exists():
        return {"ok": False, "err": f"path does not exist: {canon}"}
    return store.put(scope=GLOBAL, kind="device", title=name, body=str(canon),
                     source="route_resolve", tags=["bookmark"])


def list_bookmarks(store: Any) -> list[dict[str, Any]]:
    return store.list(scope=GLOBAL, kind="device", limit=200)