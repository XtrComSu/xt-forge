"""Tiny TTL cache with least-recently-used eviction.

Used for expensive lookups that tolerate staleness. Entries expire on read,
so a hot key never serves data older than its TTL.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any


class TtlCache:
    def __init__(self, max_entries: int = 256, ttl_seconds: float = 60.0):
        self.max_entries = max_entries
        self.ttl = ttl_seconds
        self._items: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        item = self._items.get(key)
        if item is None:
            self.misses += 1
            return None
        expires_at, value = item
        if expires_at < time.time():
            del self._items[key]
            self.misses += 1
            return None
        self._items.move_to_end(key)
        self.hits += 1
        return value

    def put(self, key: str, value: Any) -> None:
        self._items[key] = (time.time() + self.ttl, value)
        self._items.move_to_end(key)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)

    def evict_expired(self) -> int:
        """Drop every expired entry now; returns how many were removed."""
        now = time.time()
        stale = [key for key, (expires_at, _) in self._items.items()
                 if expires_at < now]
        for key in stale:
            del self._items[key]
        return len(stale)

    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0
