"""Background task worker.

Runs queued jobs with bounded retries and a backoff schedule. Nothing here
touches the network directly: jobs receive a client and report metrics.
"""
from __future__ import annotations

import time
from typing import Any, Callable

BASE_DELAY = 0.25
MAX_DELAY = 30.0
MAX_ATTEMPTS = 5


class Retryable(Exception):
    """Raised by a job when it is worth trying again."""


def backoff(attempt: int) -> float:
    """Exponential backoff with a hard ceiling.

    attempt is 1-based; the first retry waits BASE_DELAY seconds.
    """
    delay = min(BASE_DELAY * 2 ** (attempt - 1), MAX_DELAY)
    return delay


class Worker:
    def __init__(self, queue: Any, metrics: Any, clock: Callable[[], float] = time.time):
        self.queue = queue
        self.metrics = metrics
        self.clock = clock
        self.processed = 0

    def run_once(self) -> dict[str, Any]:
        job = self.queue.pop()
        if job is None:
            return {"status": "idle"}
        attempts = 0
        while True:
            attempts += 1
            started = self.clock()
            try:
                result = job.run()
            except Retryable as exc:
                self.metrics.count("worker.retry")
                if attempts >= MAX_ATTEMPTS:
                    self.metrics.count("worker.give_up")
                    return {"status": "failed", "error": str(exc), "attempts": attempts}
                time.sleep(backoff(attempts))
                continue
            self.metrics.observe("worker.latency", self.clock() - started)
            self.processed += 1
            return {"status": "ok", "result": result, "attempts": attempts}

    def drain(self, limit: int = 100) -> list[dict[str, Any]]:
        """Process up to `limit` jobs; stop early when the queue is empty."""
        out = []
        for _ in range(limit):
            outcome = self.run_once()
            if outcome["status"] == "idle":
                break
            out.append(outcome)
        return out
