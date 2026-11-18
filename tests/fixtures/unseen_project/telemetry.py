"""In-memory span and counter aggregation."""
from __future__ import annotations

from collections import defaultdict


class TelemetrySink:
    def __init__(self) -> None:
        self.counters: dict[str, int] = defaultdict(int)
        self.spans: dict[str, list[float]] = defaultdict(list)

    def inc(self, metric: str, amount: int = 1) -> None:
        self.counters[metric] += amount

    def record_span(self, span_name: str, elapsed_ms: float) -> None:
        """Append one timing sample up to a hard ring bound."""
        bucket = self.spans[span_name]
        if len(bucket) < 2048:
            bucket.append(elapsed_ms)
