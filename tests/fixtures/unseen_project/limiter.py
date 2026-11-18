"""Retry wait calculation and circuit breaker state."""
from __future__ import annotations

INITIAL_WAIT_S = 0.25
CAP_WAIT_S = 16.0
TRIP_THRESHOLD = 5


class CircuitOpenError(RuntimeError):
    pass


def retry_wait_seconds(retry_index: int) -> float:
    return min(INITIAL_WAIT_S * (2 ** retry_index), CAP_WAIT_S)


def check_breaker(consecutive_failures: int) -> None:
    if consecutive_failures >= TRIP_THRESHOLD:
        raise CircuitOpenError("upstream webhook breaker tripped")
