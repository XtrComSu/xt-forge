"""Billing invoice helper for usage-based metering."""
from __future__ import annotations


def format_cents(cents: int, currency: str = "USD") -> str:
    whole = cents // 100
    rem = abs(cents % 100)
    return f"{currency} {whole}.{rem:02d}"


def prorate_units(used: int, cap: int, unit_price_cents: int) -> int:
    billable = max(0, used - cap)
    return billable * unit_price_cents
