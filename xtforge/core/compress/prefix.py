"""Layered prefix assembly (F5): stable-first so provider prefix caches hit.

Order: STATIC_SYSTEM -> TOOL_SCHEMAS -> PROJECT_PINNED -> WORKFLOW/PHASE ->
       HANDOFF/DIGEST -> USER/TURN.  Volatile content is always last.
"""
from __future__ import annotations

import hashlib
from typing import Any

LAYERS = ("STATIC_SYSTEM", "TOOL_SCHEMAS", "PROJECT_PINNED", "PHASE",
          "HANDOFF", "USER")

PROTECTED = {"STATIC_SYSTEM"}
DEGRADE_ORDER = ("HANDOFF", "PHASE", "PROJECT_PINNED")


def layer_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:12]


def assemble(parts: dict[str, Any]) -> dict[str, Any]:
    """parts: {LAYER: text}. Missing layers are skipped. Returns text + per-layer hashes."""
    rendered: list[dict[str, Any]] = []
    warnings: list[str] = []
    for name in LAYERS:
        val = parts.get(name)
        if val is None or val == "":
            continue
        text = val if isinstance(val, str) else str(val)
        rendered.append({"layer": name, "hash": layer_hash(text),
                         "tokens": max(0, (len(text) + 3) // 4), "chars": len(text)})
    body = "\n\n".join(f"## {r['layer']}\n{parts[r['layer']]}" for r in rendered)
    return {"text": body, "layers": rendered,
            "prefix_hash": layer_hash(body), "warnings": warnings,
            "tokens": sum(r["tokens"] for r in rendered)}


def warn_on_stable_drift(prev_hashes: dict[str, str], new_layers: list[dict[str, Any]]) -> list[str]:
    """A stable layer (STATIC_SYSTEM / PROJECT_PINNED) changing breaks prefix caching."""
    out: list[str] = []
    for entry in new_layers:
        name = entry["layer"]
        if name not in PROTECTED and name != "PROJECT_PINNED":
            continue
        old = prev_hashes.get(name)
        if old and old != entry["hash"]:
            out.append(f"stable layer {name} changed: {old} -> {entry['hash']} (prefix cache miss)")
    return out