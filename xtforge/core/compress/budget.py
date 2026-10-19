"""Token budget allocator (F5). Never degrades STATIC_SYSTEM or the goal/criteria."""
from __future__ import annotations

from typing import Any

DEFAULT_WINDOW = 24_000
DEFAULT_OUTPUT_RESERVE = 4_000
TOOL_RESERVE = 2_000

# fraction of the *content* budget per layer
SHARES = {
    "STATIC_SYSTEM": 0.30,
    "TOOL_SCHEMAS": 0.20,
    "PROJECT_PINNED": 0.15,
    "PHASE": 0.20,
    "HANDOFF": 0.10,
    "USER": 0.05,
}

DEGRADE = {"HANDOFF": "L2", "PHASE": "L2", "PROJECT_PINNED": "L1"}
DEFAULT_LEVEL = "L1"


def content_budget(window: int = DEFAULT_WINDOW, output_reserve: int = DEFAULT_OUTPUT_RESERVE,
                   tool_reserve: int = TOOL_RESERVE) -> int:
    return max(0, window - output_reserve - tool_reserve)


def allocate(layers: list[dict[str, Any]], window: int = DEFAULT_WINDOW,
             output_reserve: int = DEFAULT_OUTPUT_RESERVE,
             tool_reserve: int = TOOL_RESERVE) -> dict[str, Any]:
    """Return per-layer budgets and which layers must degrade to fit."""
    total = content_budget(window, output_reserve, tool_reserve)
    budgets = {name: int(total * share) for name, share in SHARES.items()}
    needed = sum(e["tokens"] for e in layers)
    degrade: dict[str, str] = {}
    over = needed - total
    if over <= 0:
        return {"total": total, "needed": needed, "budgets": budgets,
                "degrade": degrade, "fits": True, "overflow": 0}
    for name in ("HANDOFF", "PHASE", "PROJECT_PINNED"):
        if over <= 0:
            break
        if name in DEGRADE:
            degrade[name] = DEGRADE[name]
            over -= budgets.get(name, 0)
    return {"total": total, "needed": needed, "budgets": budgets,
            "degrade": degrade, "fits": over <= 0, "overflow": max(0, over)}


def apply(layers: list[dict[str, Any]], window: int = DEFAULT_WINDOW) -> dict[str, Any]:
    """Compress layers per the allocation plan, never touching protected layers."""
    from . import passes
    plan = allocate(layers, window=window)
    out: list[dict[str, Any]] = []
    for entry in layers:
        name = entry["layer"]
        budget = plan["budgets"].get(name)
        level = plan["degrade"].get(name, DEFAULT_LEVEL)
        if name in ("STATIC_SYSTEM", "USER") or budget is None:
            out.append(dict(entry, level="L0"))
            continue
        text = entry.get("text", "")
        if entry["tokens"] <= budget:
            out.append(dict(entry, level=level, fitted=True))
            continue
        res = passes.compress(text, level)
        trimmed = res["text"]
        # hard cut with an explicit marker if still over
        max_chars = budget * 4
        if len(trimmed) > max_chars:
            head = max_chars * 2 // 3
            tail = max_chars - head
            trimmed = (trimmed[:head] + f"\n…[TRUNCATED {len(trimmed) - max_chars} chars]…\n"
                       + trimmed[-tail:])
        out.append(dict(entry, text=trimmed,
                        tokens=max(0, (len(trimmed) + 3) // 4),
                        level=level, fitted=len(trimmed) <= max_chars))
    return {"plan": plan, "layers": out}