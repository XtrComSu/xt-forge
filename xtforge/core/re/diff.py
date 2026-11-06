"""Normalized binary and control-flow graph diffing.

Compares functions, basic block counts, and symbols across two versions of a binary
to locate security patches, added entry points, and structural regressions.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..route import guard
from .native import get_symbols, sniff_format
from .analysis import build_cfg


def diff_binaries(bin1: str | Path, bin2: str | Path) -> dict[str, Any]:
    """Compare functions and control-flow graphs across two binary builds."""
    c1 = guard.read_guard(bin1)
    c2 = guard.read_guard(bin2)

    if not c1.is_file():
        return {"ok": False, "err": f"bin1 not a file: {bin1}"}
    if not c2.is_file():
        return {"ok": False, "err": f"bin2 not a file: {bin2}"}

    syms1 = {s["name"]: s for s in get_symbols(c1, limit=2000).get("symbols", []) if s.get("name")}
    syms2 = {s["name"]: s for s in get_symbols(c2, limit=2000).get("symbols", []) if s.get("name")}

    names1 = set(syms1.keys())
    names2 = set(syms2.keys())

    added = sorted(list(names2 - names1))
    removed = sorted(list(names1 - names2))
    common = sorted(list(names1 & names2))

    modified = []
    identical = []

    # Compare common functions
    for name in common[:100]:  # Cap deep CFG diffs to top 100 functions for responsiveness
        rva1 = syms1[name].get("rva") or syms1[name].get("value")
        rva2 = syms2[name].get("rva") or syms2[name].get("value")

        if rva1 == rva2:
            identical.append(name)
        else:
            # RVA changed, compare block counts
            cfg1 = build_cfg(c1, symbol=name, max_instructions=50)
            cfg2 = build_cfg(c2, symbol=name, max_instructions=50)

            b1 = len(cfg1.get("blocks", []))
            b2 = len(cfg2.get("blocks", []))
            if b1 != b2:
                modified.append({
                    "name": name,
                    "rva1": rva1,
                    "rva2": rva2,
                    "status": "structure_changed",
                    "blocks_v1": b1,
                    "blocks_v2": b2,
                })
            else:
                modified.append({
                    "name": name,
                    "rva1": rva1,
                    "rva2": rva2,
                    "status": "relocated_or_patched",
                    "blocks": b1,
                })

    similarity = 0.0
    total_fns = len(names1 | names2)
    if total_fns > 0:
        similarity = round((len(identical) / total_fns) * 100.0, 1)

    return {
        "ok": True,
        "bin1": str(c1),
        "bin2": str(c2),
        "total_functions_v1": len(names1),
        "total_functions_v2": len(names2),
        "added_count": len(added),
        "added_functions": added,
        "removed_count": len(removed),
        "removed_functions": removed,
        "matched_functions": common,
        "modified_count": len(modified),
        "modified_functions": modified,
        "identical_count": len(identical),
        "similarity_pct": similarity,
    }
