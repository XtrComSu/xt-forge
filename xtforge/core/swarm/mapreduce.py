"""Map-reduce binary decompiler and structural analysis farm."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..re import native as renative
from ..re.analysis import build_cfg
from .worker import SwarmPool


def _analyze_one_function(target: Path, fn_name: str, rva: int | None) -> dict[str, Any]:
    """Map worker: inspect control flow and traits of a single function."""
    cfg = build_cfg(target, symbol=fn_name, rva=rva, max_instructions=50)
    blocks = cfg.get("blocks", [])
    edges = cfg.get("edges", [])
    b_count = len(blocks)
    e_count = len(edges)
    complexity = max(1, e_count - b_count + 2) if b_count else 1

    return {
        "name": fn_name,
        "rva": hex(rva) if rva else None,
        "blocks": b_count,
        "edges": e_count,
        "complexity": complexity,
    }


def map_functions(target: str | Path, workers: int = 8) -> dict[str, Any]:
    """Map-reduce analysis across all functions in a binary using a worker swarm."""
    canon = renative.guard.read_guard(target)
    if not canon.is_file():
        return {"ok": False, "err": "target is not a file"}

    # Extract candidate functions from symbols / exports
    sym_res = renative.get_symbols(canon, limit=2000)
    symbols = sym_res.get("symbols", [])

    fn_targets: list[tuple[str, int | None]] = []
    for s in symbols:
        name = s.get("name")
        rva_val = s.get("rva") or s.get("value")
        rva_int = int(rva_val, 16) if isinstance(rva_val, str) and rva_val.startswith("0x") else None
        if name:
            fn_targets.append((name, rva_int))

    if not fn_targets:
        # Fallback: analyze main / entry point
        info = renative.get_info(canon)
        ep = info.get("entry_point")
        rva_int = int(ep, 16) if isinstance(ep, str) and ep.startswith("0x") else None
        fn_targets.append(("entry_point", rva_int))

    pool = SwarmPool(workers=workers)
    tasks = [
        (lambda fn=name, r=rva: _analyze_one_function(canon, fn, r))
        for name, rva in fn_targets
    ]

    results = pool.run_all(tasks)
    mapped_functions = [r["result"] for r in results if r["ok"] and r.get("result")]

    # Reducer: aggregate metrics and categorization
    total_complexity = sum(f["complexity"] for f in mapped_functions)
    avg_complexity = round(total_complexity / max(1, len(mapped_functions)), 2)
    hot_functions = sorted(mapped_functions, key=lambda f: -f["complexity"])[:10]

    return {
        "ok": True,
        "path": str(canon),
        "function_count": len(mapped_functions),
        "average_complexity": avg_complexity,
        "hottest_functions": hot_functions,
        "functions": mapped_functions,
    }
