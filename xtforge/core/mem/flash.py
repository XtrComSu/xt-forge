"""Flash memory (F1): append-only JSONL ring per scope, LRU eviction, zero LLM calls.

Entry: {id,k,v,tags[],ts,ttl_s|null,pin:bool,src}
Limits: 256 entries/scope, entry <= 2 KB. Writes are atomic (temp + fsync + rename).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from ...atomicio import atomic_write_text
from ...version import flash_dir

MAX_PER_SCOPE = 256
MAX_ENTRY_BYTES = 2048
DEFAULT_SCOPE = "global"


class FlashError(RuntimeError):
    pass


def _scope_file(scope: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in scope)
    return flash_dir() / f"scope-{safe}.jsonl"


def _key_id(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


def parse_tags(text: str) -> list[str]:
    """Extract #hashtags from free text."""
    out: list[str] = []
    for raw in text.split():
        if raw.startswith("#") and len(raw) > 1:
            tag = raw.lstrip("#").strip(".,;:!?()[]{}\"'")
            if tag:
                out.append(tag)
    return sorted(set(out))


def auto_key(text: str) -> str:
    """Stable short key from content hash."""
    return "n" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


class Flash:
    """One Flash instance manages all scopes; entries live on disk."""

    def __init__(self, base: str | Path | None = None):
        self._base = Path(base) if base else None

    def _path(self, scope: str) -> Path:
        if self._base:
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in scope)
            self._base.mkdir(parents=True, exist_ok=True)
            return self._base / f"scope-{safe}.jsonl"
        return _scope_file(scope)

    # ---------- low-level ----------

    def _load(self, scope: str) -> list[dict[str, Any]]:
        path = self._path(scope)
        if not path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict) and rec.get("id"):
                    entries.append(rec)
        return entries

    def _save(self, scope: str, entries: list[dict[str, Any]]) -> None:
        payload = "".join(
            json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in entries)
        atomic_write_text(self._path(scope), payload)

    def _expired(self, rec: dict[str, Any], now: float) -> bool:
        ttl = rec.get("ttl_s")
        return bool(ttl) and (now - float(rec.get("ts", 0))) > float(ttl)

    # ---------- public ops ----------

    def set(self, value: str, key: str | None = None, scope: str = DEFAULT_SCOPE,
            tags: Iterable[str] | None = None, ttl_s: int | None = None,
            pin: bool = False, src: str = "") -> dict[str, Any]:
        if value is None:
            raise FlashError("value required")
        if len(value.encode("utf-8")) > MAX_ENTRY_BYTES:
            raise FlashError(f"entry exceeds {MAX_ENTRY_BYTES} bytes")
        all_tags = sorted(set(parse_tags(value)) | set(tags or []))
        k = key or auto_key(value)
        entries = [e for e in self._load(scope) if e.get("k") != k]
        rec = {"id": _key_id(k), "k": k, "v": value, "tags": all_tags,
               "ts": time.time(), "ttl_s": ttl_s, "pin": bool(pin), "src": src}
        entries.append(rec)
        self._save(scope, self._evict(entries))
        return rec

    def get(self, key: str, scope: str = DEFAULT_SCOPE) -> dict[str, Any] | None:
        now = time.time()
        for rec in self._load(scope):
            if self._expired(rec, now):
                continue
            if rec.get("k") == key or rec.get("id") == key:
                return rec
        return None

    def find(self, query: str, scope: str = DEFAULT_SCOPE, top: int = 3) -> list[dict[str, Any]]:
        """Fuzzy top-N: exact substring beats prefix beats token overlap."""
        q = (query or "").strip().lower()
        if not q:
            return []
        now = time.time()
        scored: list[tuple[float, dict[str, Any]]] = []
        for rec in self._load(scope):
            if self._expired(rec, now):
                continue
            hay = f"{rec.get('k','')} {rec.get('v','')} {' '.join(rec.get('tags',[]))}".lower()
            score = 0.0
            if rec.get("k", "").lower() == q:
                score = 100.0
            elif q in hay:
                score = 50.0
            elif q in rec.get("k", "").lower():
                score = 25.0
            else:
                hits = sum(1 for t in q.split() if t in hay)
                score = float(hits)
            if rec.get("pin"):
                score += 5.0
            if score > 0:
                scored.append((score, rec))
        scored.sort(key=lambda x: (-x[0], -(x[1].get("ts") or 0)))
        return [rec for _, rec in scored[:top]]

    def list(self, scope: str = DEFAULT_SCOPE, n: int = 10,
             pin_only: bool = False) -> list[dict[str, Any]]:
        now = time.time()
        recs = [r for r in self._load(scope) if not self._expired(r, now)]
        if pin_only:
            recs = [r for r in recs if r.get("pin")]
        recs.sort(key=lambda r: (not r.get("pin"), -(r.get("ts") or 0)))
        return recs[:n]

    def pin(self, key_or_id: str, scope: str = DEFAULT_SCOPE) -> dict[str, Any] | None:
        entries = self._load(scope)
        now = time.time()
        for rec in entries:
            if self._expired(rec, now):
                continue
            if rec.get("k") == key_or_id or rec.get("id") == key_or_id:
                rec["pin"] = not rec.get("pin")
                self._save(scope, entries)
                return rec
        return None

    def delete(self, key_or_id: str, scope: str = DEFAULT_SCOPE) -> bool:
        entries = self._load(scope)
        keep = [e for e in entries
                if e.get("k") != key_or_id and e.get("id") != key_or_id]
        if len(keep) == len(entries):
            return False
        self._save(scope, keep)
        return True

    def clear(self, scope: str = DEFAULT_SCOPE) -> int:
        entries = self._load(scope)
        self._save(scope, [])
        return len(entries)

    def scopes(self) -> list[str]:
        d = self._base or flash_dir()
        if not d.exists():
            return []
        return sorted(p.stem.replace("scope-", "") for p in d.glob("scope-*.jsonl"))

    # ---------- maintenance ----------

    def _evict(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = time.time()
        alive = [e for e in entries if not self._expired(e, now)]
        if len(alive) <= MAX_PER_SCOPE:
            return alive
        pinned = [e for e in alive if e.get("pin")]
        unpinned = sorted((e for e in alive if not e.get("pin")),
                          key=lambda e: e.get("ts", 0))
        room = max(0, MAX_PER_SCOPE - len(pinned))
        return pinned + unpinned[-room:] if room else pinned[-MAX_PER_SCOPE:]

    def compact(self, scope: str = DEFAULT_SCOPE) -> dict[str, int]:
        """Drop expired, merge near-duplicates, collapse duplicate keys."""
        now = time.time()
        entries = self._load(scope)
        alive = [e for e in entries if not self._expired(e, now)]
        dropped_expired = len(entries) - len(alive)
        merged: dict[str, dict[str, Any]] = {}
        dropped_dupes = 0
        for rec in alive:
            k = rec.get("k")
            if k in merged:
                dropped_dupes += 1
                prev = merged[k]
                if (rec.get("ts") or 0) > (prev.get("ts") or 0):
                    rec["pin"] = bool(rec.get("pin") or prev.get("pin"))
                    merged[k] = rec
                continue
            merged[k] = rec
        out = list(merged.values())
        before = len(out)
        out = self._evict(out)
        self._save(scope, out)
        return {"before": before, "after": len(out),
                "expired": dropped_expired, "dupes_merged": dropped_dupes,
                "evicted": before - len(out)}

    def stats(self, scope: str = DEFAULT_SCOPE) -> dict[str, Any]:
        entries = self._load(scope)
        now = time.time()
        alive = [e for e in entries if not self._expired(e, now)]
        return {"scope": scope, "total": len(entries), "alive": len(alive),
                "pinned": sum(1 for e in alive if e.get("pin")),
                "max": MAX_PER_SCOPE}

    def wired(self, scope: str = DEFAULT_SCOPE) -> list[dict[str, Any]]:
        """Pinned entries to inject as prefix context next round."""
        return [e for e in self.list(scope, n=MAX_PER_SCOPE) if e.get("pin")]