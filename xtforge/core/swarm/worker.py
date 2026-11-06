"""Swarm worker pool orchestrator for high-throughput concurrent agent tasks."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable


class SwarmPool:
    """Thread-safe task scheduler with concurrency control and telemetry."""

    def __init__(self, workers: int = 8, timeout: int = 30):
        self.workers = max(1, min(128, workers))
        self.timeout = timeout

    def run_all(self, callables: list[Callable[[], Any]]) -> list[dict[str, Any]]:
        """Execute a list of nullary callables across the worker swarm concurrently."""
        results: list[dict[str, Any]] = [None] * len(callables)  # type: ignore

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_idx = {
                executor.submit(fn): idx for idx, fn in enumerate(callables)
            }

            for future in as_completed(future_to_idx, timeout=self.timeout):
                idx = future_to_idx[future]
                t0 = time.perf_counter()
                try:
                    res = future.result()
                    elapsed = (time.perf_counter() - t0) * 1000
                    results[idx] = {
                        "task_id": idx,
                        "ok": True,
                        "result": res,
                        "elapsed_ms": round(elapsed, 2),
                    }
                except Exception as exc:
                    elapsed = (time.perf_counter() - t0) * 1000
                    results[idx] = {
                        "task_id": idx,
                        "ok": False,
                        "error": str(exc),
                        "elapsed_ms": round(elapsed, 2),
                    }

        return results
