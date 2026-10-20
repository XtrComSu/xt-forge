"""Eval runs: record benchmark results, compare them, report deltas.

The three `scripts/bench_*.py` scripts compute numbers; this stores them,
compares them and refuses to let a regression hide in a log file.

    python3 scripts/bench_mem_recall.py --json | xtforge eval record mem-recall
    xtforge eval list mem-recall
    xtforge eval compare mem-recall 2026-10-20T10:00:00Z 2026-10-21T10:00:00Z
    xtforge eval report mem-recall

A suite declares which way is better, so `compare` can call a regression a
regression instead of printing a minus sign and hoping you notice.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Iterable

from ...version import xt_home

DIRECTIONS = ("higher", "lower")

# Suite registry: metric direction is a promise about what "better" means.
SUITES: dict[str, dict[str, Any]] = {
    "mem-recall": {
        "description": "memory retrieval quality on the 50-query fixture",
        "direction": "higher",
        "metrics": ["lexical.recall", "lexical.mrr", "hybrid.recall",
                    "hybrid.mrr", "delta"],
    },
    "context-pack": {
        "description": "context packing cost per recovered answer",
        "direction": "lower",
        "metrics": ["baseline.tokens_per_hit", "query_aware.tokens_per_hit",
                    "tokens_per_hit_reduction", "baseline.accuracy",
                    "query_aware.accuracy"],
    },
    "secret-scan": {
        "description": "scanner recall and false positives on the seeded fixture",
        "direction": "higher",
        "metrics": ["secrets.found", "patterns.found", "manifest.found"],
    },
    "model-eval": {
        "description": "model quality on fixed cases: pass rate, latency, size",
        "direction": "higher",
        "metrics": ["cases.pass_rate", "cases.passed", "latency.mean_s",
                    "output.mean_chars"],
        "lower_better": ["latency.mean_s", "latency.p95_s", "output.mean_chars"],
    },
}


def eval_dir() -> Path:
    return xt_home() / "evals"


def suite_dir(suite: str) -> Path:
    return eval_dir() / _safe(suite)


def _safe(name: str) -> str:
    cleaned = "".join(ch for ch in (name or "").strip().lower()
                      if ch.isalnum() or ch in "-_")
    if not cleaned:
        raise ValueError("suite name is empty after sanitising")
    return cleaned[:60]


def _flatten(obj: Any, prefix: str = "") -> dict[str, float]:
    out: dict[str, float] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            key = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten(value, key))
    elif isinstance(obj, bool):
        out[prefix] = float(obj)
    elif isinstance(obj, (int, float)):
        out[prefix] = float(obj)
    return out


def record(suite: str, payload: dict[str, Any], note: str = "",
           now: int | None = None) -> dict[str, Any]:
    """Store one benchmark result. Returns the stored run."""
    name = _safe(suite)
    ts = int(now if now is not None else time.time())
    metrics = {k: v for k, v in _flatten(payload).items()
               if isinstance(v, (int, float))}
    digest = hashlib.sha256(
        json.dumps(metrics, sort_keys=True).encode("utf-8")).hexdigest()[:8]
    meta = SUITES.get(name, {})
    run = {
        "suite": name,
        "run_id": f"{ts}-{digest}",
        "recorded": ts,
        "note": note,
        "metrics": metrics,
        "payload": payload,
        "direction": meta.get("direction", "higher"),
        "lower_better": list(meta.get("lower_better", [])),
    }
    directory = suite_dir(name)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run['run_id']}.json"
    path.write_text(json.dumps(run, ensure_ascii=False, indent=2,
                               default=str) + "\n", encoding="utf-8")
    return run


def list_runs(suite: str) -> list[dict[str, Any]]:
    directory = suite_dir(suite)
    if not directory.is_dir():
        return []
    runs = []
    for path in sorted(directory.glob("*.json")):
        try:
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(runs, key=lambda r: r.get("recorded", 0))


def latest(suite: str) -> dict[str, Any] | None:
    runs = list_runs(suite)
    return runs[-1] if runs else None


def load(suite: str, run_id: str) -> dict[str, Any]:
    path = suite_dir(suite) / f"{_safe(run_id)}.json"
    if not path.is_file():
        raise ValueError(f"no such run: {suite}/{run_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def compare(base: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Per-metric delta with a regression call, not just a minus sign.

    Suite direction decides what "better" means; `lower_better` overrides it
    per metric (latency is lower-is-better even in a higher-is-better suite).
    """
    direction = current.get("direction") or base.get("direction") or "higher"
    lower_better = set(current.get("lower_better")
                       or base.get("lower_better") or [])
    base_metrics = base.get("metrics", {})
    cur_metrics = current.get("metrics", {})
    rows = []
    regressions = 0
    for key in sorted(set(base_metrics) | set(cur_metrics)):
        before = base_metrics.get(key)
        after = cur_metrics.get(key)
        if before is None or after is None:
            rows.append({"metric": key, "before": before, "after": after,
                         "delta": None, "verdict": "added"
                         if after is not None else "removed"})
            continue
        delta = round(after - before, 6)
        if delta == 0:
            verdict = "same"
        else:
            better_when_higher = (direction == "higher"
                                  and key not in lower_better)
            verdict = ("better" if (delta > 0) == better_when_higher
                       else "regressed")
            if verdict == "regressed":
                regressions += 1
        rows.append({"metric": key, "before": before, "after": after,
                     "delta": delta, "verdict": verdict})
    return {
        "suite": current.get("suite") or base.get("suite"),
        "direction": direction,
        "base_run": base.get("run_id"),
        "current_run": current.get("run_id"),
        "rows": rows,
        "regressions": regressions,
        "ok": regressions == 0,
    }


def report(suite: str, limit: int = 5) -> str:
    runs = list_runs(suite)[-limit:]
    if not runs:
        return f"(no runs recorded for {suite})"
    lines = [f"# Eval: {suite}", ""]
    meta = SUITES.get(_safe(suite), {})
    if meta:
        lines += [f"{meta.get('description', '')}",
                  f"direction: better is {meta.get('direction', 'higher')}", ""]
    lines.append("| run | recorded | metrics |")
    lines.append("|---|---|---|")
    for run in runs:
        metrics = run.get("metrics", {})
        shown = ", ".join(f"{k.split('.')[-1]}={v:g}"
                          for k, v in list(metrics.items())[:3])
        lines.append(f"| `{run.get('run_id')}` | {run.get('recorded')} | {shown} |")
    if len(runs) >= 2:
        lines.append("")
        verdict = compare(runs[-2], runs[-1])
        lines.append(f"latest vs previous: **{verdict['regressions']} regressions**")
        for row in verdict["rows"][:10]:
            if row["verdict"] in ("regressed", "better"):
                lines.append(f"- `{row['metric']}` {row['before']} → "
                             f"{row['after']} ({row['delta']:+g}) {row['verdict']}")
    lines.append("")
    return "\n".join(lines)
