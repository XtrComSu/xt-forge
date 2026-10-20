#!/usr/bin/env python3
"""Model evaluation harness: score a model against fixed cases, deterministically.

This is the gate that turns "a smaller model" into "a provably better one".
It runs the same cases against any model, scores them with checks that cannot
be argued with, and emits a payload for `xtforge eval record` so runs can be
compared over time.

    python3 scripts/eval_model.py --model xt-luna:1b-q5 \
        --cases tests/fixtures/model_eval.json --json \
        | xtforge eval record model-eval

    python3 scripts/eval_model.py --model minicpm5-2b:ablated --cases ...
    xtforge eval compare model-eval

Design rules:
- the scorer is deterministic: no model in the loop, no vibes
- every case states what a pass looks like before the model runs
- latency and output size are reported alongside quality, because a model
  that is right but unusably slow is a trade, not a win

Backends:
    ollama    `ollama run <model>` (default; what this host has)
    cmd       any command that reads the prompt on stdin, writes text to stdout
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "tests" / "fixtures" / "model_eval.json"
DEFAULT_BACKEND = "ollama"
TIMEOUT = 120

REFUSAL_PHRONS = (
    "i can't", "i cannot", "i'm sorry", "i am sorry", "as an ai",
    "i won't", "i will not", "not able to help",
)


# --------------------------------------------------------------- backends

def run_ollama(model: str, prompt: str, timeout: int) -> tuple[str, float]:
    start = time.perf_counter()
    proc = subprocess.run(["ollama", "run", model, "--verbose=false", prompt],
                          capture_output=True, text=True, timeout=timeout)
    return proc.stdout.strip(), time.perf_counter() - start


def run_cmd(command: str, prompt: str, timeout: int) -> tuple[str, float]:
    start = time.perf_counter()
    proc = subprocess.run(command, shell=True, input=prompt,
                          capture_output=True, text=True, timeout=timeout)
    return proc.stdout.strip(), time.perf_counter() - start


BACKENDS = {"ollama": run_ollama, "cmd": run_cmd}


# --------------------------------------------------------------- scoring

def check_output(output: str, check: dict[str, Any]) -> tuple[bool, str]:
    kind = check.get("type", "")
    value = check.get("value")
    if kind == "contains":
        ok = str(value).lower() in output.lower()
        return ok, f"contains {value!r}"
    if kind == "not_contains":
        ok = str(value).lower() not in output.lower()
        return ok, f"not_contains {value!r}"
    if kind == "regex":
        ok = bool(re.search(str(value), output, re.IGNORECASE | re.DOTALL))
        return ok, f"regex {value!r}"
    if kind == "starts_with":
        ok = output.lower().startswith(str(value).lower())
        return ok, f"starts_with {value!r}"
    if kind == "json":
        try:
            json.loads(output)
            return True, "valid json"
        except json.JSONDecodeError as exc:
            return False, f"invalid json ({exc.msg})"
    if kind == "max_chars":
        ok = len(output) <= int(value)
        return ok, f"max_chars {value}"
    if kind == "min_chars":
        ok = len(output) >= int(value)
        return ok, f"min_chars {value}"
    if kind == "refuses":
        hit = any(phrase in output.lower() for phrase in REFUSAL_PHRONS)
        return (hit if value else not hit), ("refuses" if hit else "no refusal")
    return False, f"unknown check type: {kind}"


def score_case(output: str, case: dict[str, Any]) -> dict[str, Any]:
    results = []
    for check in case.get("checks", []):
        ok, label = check_output(output, check)
        results.append({"check": label, "type": check.get("type"), "ok": ok})
    passed = all(r["ok"] for r in results) if results else bool(output.strip())
    return {"passed": passed, "checks": results}


# ---------------------------------------------------------------- harness

def evaluate(model: str, cases: list[dict[str, Any]], backend: str,
             timeout: int, limit: int | None = None) -> dict[str, Any]:
    runner = BACKENDS.get(backend)
    if runner is None:
        raise ValueError(f"unknown backend: {backend}")
    rows = []
    by_type: dict[str, list[bool]] = {}
    elapsed: list[float] = []
    sizes: list[int] = []

    for case in cases[: (limit or len(cases))]:
        prompt = case.get("prompt", "")
        try:
            output, took = runner(model, prompt, timeout)
            error = None
        except (OSError, subprocess.SubprocessError) as exc:
            output, took, error = "", 0.0, str(exc)
        verdict = score_case(output, case)
        elapsed.append(took)
        sizes.append(len(output))
        for check in verdict["checks"]:
            by_type.setdefault(check["type"] or "other", []).append(check["ok"])
        rows.append({
            "id": case.get("id"), "passed": verdict["passed"],
            "checks": verdict["checks"], "seconds": round(took, 3),
            "output_chars": len(output),
            "output_preview": output[:120], "error": error,
        })

    total = len(rows)
    passed = sum(1 for r in rows if r["passed"])
    return {
        "model": model, "backend": backend, "cases": total,
        "cases.passed": passed,
        "cases.pass_rate": round(passed / total, 4) if total else 0.0,
        "latency.mean_s": round(sum(elapsed) / total, 3) if total else 0.0,
        "latency.p95_s": round(sorted(elapsed)[int(len(elapsed) * 0.95) - 1], 3)
        if elapsed else 0.0,
        "output.mean_chars": round(sum(sizes) / total, 1) if total else 0.0,
        "by_type.pass_rate": {
            k: round(sum(v) / len(v), 4) for k, v in sorted(by_type.items())},
        "results": rows,
        "failed": [r["id"] for r in rows if not r["passed"]],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="model id, e.g. xt-luna:1b-q5")
    ap.add_argument("--cases", default=str(DEFAULT_CASES))
    ap.add_argument("--backend", default=DEFAULT_BACKEND,
                    choices=sorted(BACKENDS))
    ap.add_argument("--command", help="cmd backend: the command to run")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    fixture = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    cases = fixture.get("cases", fixture if isinstance(fixture, list) else [])
    if not cases:
        print("error: no cases in the fixture", file=sys.stderr)
        return 2

    backend = args.backend
    if backend == "cmd" and not args.command:
        print("error: --command is required for the cmd backend", file=sys.stderr)
        return 2
    if backend == "cmd":
        BACKENDS["cmd"] = lambda _m, p, t: run_cmd(args.command, p, t)

    try:
        report = evaluate(args.model, cases, backend, args.timeout, args.limit)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"model {args.model}  ({backend})  "
              f"{report['cases.passed']}/{report['cases']} passed "
              f"({report['cases.pass_rate']:.0%})")
        print(f"latency mean {report['latency.mean_s']}s "
              f"p95 {report['latency.p95_s']}s  "
              f"output {report['output.mean_chars']} chars")
        for kind, rate in report["by_type.pass_rate"].items():
            print(f"  {kind:<14} {rate:.0%}")
        for row in report["results"]:
            mark = "ok  " if row["passed"] else "FAIL"
            print(f"  {mark} {row['id']:<22} {row['seconds']}s  "
                  f"{row['output_preview'][:50]}")
    return 0 if report["cases.passed"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
