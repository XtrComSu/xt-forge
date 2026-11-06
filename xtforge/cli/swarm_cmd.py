"""`xtforge swarm`: high-concurrency binary analysis and speculative solving."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.swarm.mapreduce import map_functions
from ..core.swarm.mcts import speculative_solve
from ..core.swarm.audit import audit_binary


def _out(args: Any, payload: dict[str, Any], human: str, code: int = 0) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
    else:
        print(human)
    return code


def cmd_swarm(args: Any) -> int:
    verb = getattr(args, "swarm_verb", "map")
    target = getattr(args, "target", None) or getattr(args, "path", None)
    if not target:
        return _out(args, {"ok": False, "error": "swarm requires a target file"}, "error: swarm requires a target file", code=2)

    workers = getattr(args, "workers", 8) or 8

    if verb == "map":
        res = map_functions(target, workers=workers)
        if not res.get("ok"):
            return _out(args, res, f"error: {res.get('err')}", code=1)
        lines = [f"Swarm Map for {res.get('path')}: {res.get('function_count')} functions (avg complexity: {res.get('average_complexity')})"]
        lines.append("  Hottest Functions:")
        for fn in res.get("hottest_functions", []):
            lines.append(f"    {fn['name']:<24} {fn.get('rva') or 'N/A':<10} {fn['blocks']:>3} blocks  complexity:{fn['complexity']}")
        return _out(args, res, "\n".join(lines))

    elif verb == "solve":
        off_str = getattr(args, "offset", "0") or "0"
        off = int(off_str, 16) if ("0x" in off_str or "0X" in off_str) else int(off_str)
        size = getattr(args, "size", 256) or 256
        hyps = getattr(args, "hypotheses", None)
        hyp_list = [h.strip() for h in hyps.split(",")] if hyps else None

        res = speculative_solve(target, offset=off, size=size, hypotheses=hyp_list, workers=workers)
        if not res.get("ok"):
            return _out(args, res, f"error: {res.get('err')}", code=1)

        human = (
            f"Speculative Solve for {target} at {res.get('offset')} (score: {res.get('score')}):\n"
            f"  Winner: {res.get('winning_hypothesis')} (key: {res.get('hex_key') or res.get('key')})\n"
            f"  Sample: {res.get('decoded_sample')}"
        )
        return _out(args, res, human)

    elif verb == "audit":
        res = audit_binary(target, workers=workers)
        if not res.get("ok"):
            return _out(args, res, f"error: {res.get('err')}", code=1)
        summary = res.get("summary", {})
        lines = [
            f"Swarm Security & Capability Audit for {res.get('path')}: {res.get('total_findings')} findings",
            f"  Severities: HIGH={summary.get('HIGH',0)}  MEDIUM={summary.get('MEDIUM',0)}  LOW={summary.get('LOW',0)}  INFO={summary.get('INFO',0)}"
        ]
        for f in res.get("findings", [])[:15]:
            lines.append(f"  [{f['severity']:<6}] {f['title']}: {f['description']}")
        return _out(args, res, "\n".join(lines))

    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"}, f"error: unknown verb {verb}", code=2)
