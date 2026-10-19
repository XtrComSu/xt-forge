"""Reversible symbol legend (F5): repeated long strings → §n with a legend line.

Threshold: strings of >= 24 chars occurring >= 3 times in the block.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

MIN_LEN = 8
MIN_COUNT = 3
MARK = "§"
_TOKEN = re.compile(r"[A-Za-z0-9_./\\\-]{%d,}" % MIN_LEN)


def _candidates(text: str) -> list[tuple[str, int]]:
    counts = Counter(m.group(0) for m in _TOKEN.finditer(text or ""))
    cands = [(s, c) for s, c in counts.items() if c >= MIN_COUNT]
    cands.sort(key=lambda sc: (-sc[1] * len(sc[0]), sc[0]))
    return cands


def apply_legend(text: str) -> dict[str, Any]:
    """Substitute repeated long strings with §1..§n; legend prepended.

    Trailing newline of the input is preserved so expansion round-trips exactly.
    """
    src = text or ""
    trailing = ""
    if src.endswith("\n"):
        body = src[:-1]
        trailing = "\n"
    else:
        body = src
    cands = _candidates(body)
    if not cands:
        return {"text": src, "legend": {}, "replaced": 0}
    legend: dict[str, str] = {}
    out = body
    for i, (s, _c) in enumerate(cands, 1):
        alias = f"{MARK}{i}"
        out = out.replace(s, alias)
        legend[alias] = s
    legend_line = "LEGEND: " + " | ".join(f"{k}={v}" for k, v in legend.items())
    return {"text": legend_line + "\n" + out + trailing, "legend": legend,
            "replaced": len(legend)}


def expand_legend(text: str, legend: dict[str, str]) -> str:
    """Inverse of apply_legend: strip the legend line and restore every alias."""
    out = text
    if out.startswith("LEGEND:"):
        nl = out.find("\n")
        out = out[nl + 1:] if nl >= 0 else ""
    for alias in sorted(legend, key=len, reverse=True):
        out = out.replace(alias, legend[alias])
    return out


def legend_tokens(legend: dict[str, str]) -> int:
    if not legend:
        return 0
    return (len("LEGEND: ") + len(" | ".join(f"{k}={v}" for k, v in legend.items()))) // 4