"""Metrics: counters, latency histogram, snapshot export.

Everything is in-process and cheap; the snapshot is what a caller scrapes.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


class Metrics:
    def __init__(self) -> None:
        self.counters: dict[str, int] = defaultdict(int)
        self.histograms: dict[str, list[float]] = defaultdict(list)

    def count(self, name: str, value: int = 1) -> None:
        self.counters[name] += value

    def observe(self, name: str, value: float) -> None:
        """Record one latency sample; capped so a hot loop cannot eat memory."""
        samples = self.histograms[name]
        if len(samples) < 4096:
            samples.append(value)

    def quantile(self, name: str, q: float) -> float:
        samples = sorted(self.histograms.get(name, []))
        if not samples:
            return 0.0
        index = min(len(samples) - 1, int(math.ceil(q * len(samples))) - 1)
        return samples[max(0, index)]

    def snapshot(self) -> dict[str, Any]:
        """Flat export: counters plus p50/p95/p99 per histogram."""
        out: dict[str, Any] = {"counters": dict(self.counters)}
        for name in sorted(self.histograms):
            out[f"{name}.p50"] = self.quantile(name, 0.50)
            out[f"{name}.p95"] = self.quantile(name, 0.95)
            out[f"{name}.p99"] = self.quantile(name, 0.99)
        return out

    def reset(self) -> None:
        self.counters.clear()
        self.histograms.clear()
