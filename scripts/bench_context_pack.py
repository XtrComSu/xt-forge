#!/usr/bin/env python3
"""Measure context packing: project map vs query-aware packing.

Round 5 acceptance: **30% token reduction at equal answer accuracy on 20
tasks**. Accuracy here means "the evidence line the answer needs is present in
the packed context", which is measurable and does not depend on a model.

Cost is normalized as *tokens per recovered answer*, so a packer cannot look
cheap by returning nothing:

    tokens_per_hit = packed tokens / evidence hits

Usage:
    python3 scripts/bench_context_pack.py [--budget 1200] [--tasks ...] [--json]
                                         [--no-gate]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.route import pack as packmod  # noqa: E402
from xtforge.core.route import shortcuts  # noqa: E402

DEFAULT_TASKS = ROOT / "tests" / "fixtures" / "context_tasks.json"
DEFAULT_PROJECT = ROOT / "tests" / "fixtures" / "mini_project"
REDUCTION_TARGET = 0.30


def tokens(text: str) -> int:
    return max(0, (len(text or "") + 3) // 4)


def evaluate(project: Path, tasks: list[dict], budget: int,
             file_limit: int, mode: str) -> dict:
    hits = 0
    total_tokens = 0
    missed: list[str] = []
    per_task = []
    for task in tasks:
        if mode == "baseline":
            out = shortcuts.route_context(str(project), budget, file_limit)
            context = (out.get("data") or {}).get("context", "")
        else:
            out = packmod.pack(str(project), task["query"],
                               token_budget=budget, file_limit=file_limit)
            context = (out.get("data") or {}).get("context", "")
        cost = tokens(context)
        hit = task["evidence"] in context
        total_tokens += cost
        if hit:
            hits += 1
        else:
            missed.append(task["id"])
        per_task.append({"id": task["id"], "tokens": cost, "hit": hit})
    return {
        "mode": mode,
        "tasks": len(tasks),
        "hits": hits,
        "accuracy": round(hits / max(1, len(tasks)), 4),
        "total_tokens": total_tokens,
        "mean_tokens": round(total_tokens / max(1, len(tasks)), 1),
        "tokens_per_hit": round(total_tokens / max(1, hits), 1),
        "missed": missed,
        "per_task": per_task,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", default=str(DEFAULT_TASKS))
    ap.add_argument("--project", default=str(DEFAULT_PROJECT))
    ap.add_argument("--budget", type=int, default=1200)
    ap.add_argument("--file-limit", type=int, default=12)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-gate", action="store_true",
                    help=" report but do not fail on a missed target")
    args = ap.parse_args(argv)

    fixture = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
    tasks = fixture["tasks"]
    project = Path(args.project)

    baseline = evaluate(project, tasks, args.budget, args.file_limit, "baseline")
    query = evaluate(project, tasks, args.budget, args.file_limit, "query")

    reduction = 0.0
    if baseline["tokens_per_hit"] > 0:
        reduction = 1.0 - (query["tokens_per_hit"] / baseline["tokens_per_hit"])
    accuracy_ok = query["accuracy"] >= baseline["accuracy"]
    target_ok = reduction >= REDUCTION_TARGET

    payload = {
        "tasks": len(tasks),
        "budget": args.budget,
        "baseline": {k: baseline[k] for k in
                     ("accuracy", "hits", "mean_tokens", "tokens_per_hit", "missed")},
        "query_aware": {k: query[k] for k in
                        ("accuracy", "hits", "mean_tokens", "tokens_per_hit", "missed")},
        "tokens_per_hit_reduction": round(reduction, 4),
        "target_reduction": REDUCTION_TARGET,
        "accuracy_equal_or_better": accuracy_ok,
        "pass": bool(accuracy_ok and target_ok),
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"context packing — {len(tasks)} tasks, budget {args.budget} tokens")
        print(f"  baseline (project map)   accuracy {baseline['accuracy']:.2f}  "
              f"mean {baseline['mean_tokens']:.0f} tok  "
              f"{baseline['tokens_per_hit']:.0f} tok/hit")
        print(f"  query-aware (ranked)     accuracy {query['accuracy']:.2f}  "
              f"mean {query['mean_tokens']:.0f} tok  "
              f"{query['tokens_per_hit']:.0f} tok/hit")
        print(f"  tokens/hit reduction {reduction:+.1%} "
              f"(target {REDUCTION_TARGET:.0%})")
        print(f"  accuracy equal or better: {accuracy_ok}")
        if query["missed"]:
            print(f"  query-aware missed: {', '.join(query['missed'])}")
        if baseline["missed"]:
            print(f"  baseline missed:    {', '.join(baseline['missed'])}")
        print(f"  RESULT {'PASS' if payload['pass'] else 'FAIL'}")
    if args.no_gate:
        return 0
    return 0 if payload["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
