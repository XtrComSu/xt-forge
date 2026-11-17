"""Metacognitive 'vibe check' oversight and negative-memory guardrails for Goal runs."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..mem.scopes import project_scope
from ..mem.search import search as mem_search
from ..mem.store import Store
from ..route import guard
from ...version import xt_home


def _git_changed_files(root: Path) -> list[str]:
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode != 0:
            return []
        files: list[str] = []
        for line in res.stdout.splitlines():
            if len(line) >= 4:
                files.append(line[3:].strip().split(" -> ")[-1])
        return files
    except (OSError, subprocess.SubprocessError):
        return []


def check_progress(
    *,
    objective: str,
    run_id: str | None = None,
    plan_text: str = "",
    criteria: list[str] | None = None,
    files_touched: list[str] | None = None,
    file_cap: int = 8,
    root: str | Path = ".",
    interactive: bool = False,
) -> dict[str, Any]:
    """Audit active work for goal drift, diff bloat, stuck repeats, and known failures."""
    base = Path(root).resolve()
    touched = list(files_touched or [])
    if not touched:
        touched = _git_changed_files(base)

    goal_data: dict[str, Any] = {}
    if run_id:
        from ...atomicio import read_json
        from ...version import run_dir
        goal_data = read_json(run_dir(run_id) / "goal.json") or {}
        if not criteria and goal_data.get("criteria"):
            criteria = list(goal_data["criteria"])
        if not objective and goal_data.get("objective"):
            objective = str(goal_data["objective"])

    findings: list[dict[str, Any]] = []
    # 1. Diff bloat vs file_cap
    if len(touched) > max(1, file_cap):
        findings.append({
            "kind": "scope_bloat",
            "severity": "warn",
            "message": f"{len(touched)} touched files exceeds file_cap={file_cap}",
        })

    # 2. Criteria / plan keyword drift check
    if criteria:
        hay_src = [plan_text, " ".join(touched)]
        if not any(s.strip() for s in hay_src):
            hay_src = [objective]
        hay = " ".join(hay_src).lower()
        missing = []
        for c in criteria:
            toks = [t for t in c.lower().split() if len(t) >= 4]
            if toks and not any(t in hay for t in toks):
                missing.append(c)
        if missing:
            findings.append({
                "kind": "criteria_drift",
                "severity": "warn",
                "message": f"{len(missing)} criterion term(s) absent from current plan/diff",
                "missing": missing[:5],
            })

    # 3. Repetition / stuck telemetry if goal run state exists
    reports = goal_data.get("reports") or []
    if len(reports) >= 2:
        last_errs = [r.get("errors") for r in reports[-2:]]
        if last_errs[0] and last_errs[0] == last_errs[1]:
            findings.append({
                "kind": "repeat_error",
                "severity": "high",
                "message": "identical error signature in consecutive rounds; switch hypothesis",
            })

    # 4. Query negative memory (`failed_attempt`, `anti_pattern`)
    neg_warnings: list[dict[str, Any]] = []
    db = xt_home() / "mem.db"
    if db.is_file() and objective.strip():
        store = Store(db)
        try:
            scopes = [project_scope(str(base)), "global"]
            res = mem_search(
                store,
                query=f"{objective} {plan_text}".strip()[:200],
                scopes=scopes,
                k=5,
                token_budget=600,
                kinds=["failed_attempt", "anti_pattern"],
            )
            neg_warnings = [item["record"] for item in res.get("results") or []]
        finally:
            store.close()

    for w in neg_warnings:
        findings.append({
            "kind": "negative_memory",
            "severity": "warn",
            "id": w.get("id"),
            "title": w.get("title"),
            "error_sig": w.get("error_sig") or "",
        })

    status = "proceed"
    if any(f["severity"] == "high" for f in findings):
        status = "rethink"
    elif findings:
        status = "caution"

    confirmed = True
    if interactive and sys.stdin.isatty() and os.environ.get("XT_NONINTERACTIVE") != "1":
        print(f"[goal check] status={status} objective={objective[:80]}")
        for f in findings:
            print(f"  - [{f['severity']}] {f['kind']}: {f.get('message') or f.get('title')}")
        ans = input("Proceed? [Y/n]: ").strip().lower()
        confirmed = ans in ("", "y", "yes")
        if not confirmed:
            status = "paused_by_user"

    guard.audit_log(
        tool="goal.check",
        args={"run_id": run_id or "", "touched": len(touched)},
        outcome=status,
    )
    return {
        "ok": confirmed,
        "status": status,
        "objective": objective,
        "touched_count": len(touched),
        "touched_files": touched[:25],
        "findings": findings,
        "negative_warnings": len(neg_warnings),
    }
