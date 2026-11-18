"""Webhook delivery worker loop."""
from __future__ import annotations

import time
from typing import Callable

from .telemetry import TelemetrySink


class DeliveryError(RuntimeError):
    pass


class WebhookDispatcher:
    def __init__(self, sink: TelemetrySink, clock: Callable[[], float] = time.monotonic) -> None:
        self.sink = sink
        self.clock = clock
        self.delivered = 0

    def ship(self, task: Callable[[], str]) -> dict[str, object]:
        t0 = self.clock()
        try:
            body = task()
        except TimeoutError as exc:
            self.sink.inc("webhook.timeout")
            raise DeliveryError("upstream request timed out") from exc
        self.sink.record_span("checkout.duration", (self.clock() - t0) * 1000.0)
        self.delivered += 1
        return {"ok": True, "body": body}
