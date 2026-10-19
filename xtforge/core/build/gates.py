"""Gate evaluation (F4). Deterministic gates run in code; llm_verify is injected."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

GATE_TIMEOUT = 900


def run_gates(phase_gates: list[dict[str, Any]], workdir: str | Path,
              llm_verify: Callable[[str, str], str] | None = None
              ) -> list[dict[str, Any]]:
    """Evaluate every gate; all must pass to advance. Never raises."""
    from ..route import guard
    results: list[dict[str, Any]] = []
    root = Path(workdir)
    for i, g in enumerate(phase_gates or []):
        gtype = g.get("type")
        gid = str(g.get("id") or f"{gtype}#{i}")
        try:
            if gtype == "file_exists":
                res = _file_exists(root, g)
            elif gtype == "not_empty":
                res = _not_empty(root, g)
            elif gtype == "json_valid":
                res = _json_valid(root, g)
            elif gtype == "cmd":
                res = _cmd(root, g, guard)
            elif gtype == "llm_verify":
                res = _llm_verify(root, g, llm_verify)
            else:
                res = {"id": gid, "result": "fail", "evidence": f"unknown gate type {gtype!r}"}
        except Exception as exc:  # a broken gate must not crash the build
            res = {"id": gid, "result": "fail", "evidence": f"gate error: {exc}"}
        results.append(res)
    return results


def all_passed(results: list[dict[str, Any]]) -> bool:
    return bool(results) and all(r.get("result") == "pass" for r in results)


def summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    passed = [r for r in results if r.get("result") == "pass"]
    failed = [r for r in results if r.get("result") != "pass"]
    return {"total": len(results), "passed": len(passed), "failed": len(failed),
            "all_passed": all_passed(results),
            "failed_ids": [r["id"] for r in failed]}


def _resolve(root: Path, p: str) -> Path:
    cand = Path(p)
    return cand if cand.is_absolute() else root / p


def _file_exists(root: Path, g: dict[str, Any]) -> dict[str, Any]:
    target = _resolve(root, g["path"])
    ok = target.exists()
    return {"id": str(g.get("id") or "file_exists"), "result": "pass" if ok else "fail",
            "evidence": f"{'exists' if ok else 'missing'}: {target}"}


def _not_empty(root: Path, g: dict[str, Any]) -> dict[str, Any]:
    target = _resolve(root, g["path"])
    if not target.exists():
        return {"id": str(g.get("id") or "not_empty"), "result": "fail",
                "evidence": f"missing: {target}"}
    size = target.stat().st_size
    return {"id": str(g.get("id") or "not_empty"),
            "result": "pass" if size > 0 else "fail",
            "evidence": f"{size} bytes: {target}"}


def _json_valid(root: Path, g: dict[str, Any]) -> dict[str, Any]:
    target = _resolve(root, g["path"])
    if not target.exists():
        return {"id": str(g.get("id") or "json_valid"), "result": "fail",
                "evidence": f"missing: {target}"}
    try:
        json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"id": str(g.get("id") or "json_valid"), "result": "fail",
                "evidence": f"invalid JSON: {exc}"}
    return {"id": str(g.get("id") or "json_valid"), "result": "pass",
            "evidence": f"valid JSON: {target}"}


def _cmd(root: Path, g: dict[str, Any], guard: Any) -> dict[str, Any]:
    cmd = g.get("run", "")
    expect = int(g.get("expect_exit", 0))
    reason = guard.check_command(cmd)
    if reason:
        return {"id": str(g.get("id") or "cmd"), "result": "fail",
                "evidence": f"denied: {reason}"}
    env = dict(os.environ)
    # Harness shells (opencode runs the CLI through a wrapper) often lack
    # Termux's bin dir, so `python3 ...` inside a gate would not resolve.
    # Put the running interpreter's dir and $PREFIX/bin first.
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    env["PATH"] = f"{Path(sys.executable).parent}:{prefix}/bin:{env.get('PATH', '')}"
    try:
        r = subprocess.run(cmd, shell=True, cwd=str(root), capture_output=True,
                           text=True, timeout=GATE_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return {"id": str(g.get("id") or "cmd"), "result": "fail",
                "evidence": f"timeout after {GATE_TIMEOUT}s"}
    except OSError as exc:
        return {"id": str(g.get("id") or "cmd"), "result": "fail", "evidence": str(exc)}
    ok = r.returncode == expect
    tail = "\n".join(((r.stdout or "") + (r.stderr or "")).splitlines()[-15:])
    return {"id": str(g.get("id") or "cmd"), "result": "pass" if ok else "fail",
            "evidence": f"exit={r.returncode} expected={expect}\n{tail}"}


def _llm_verify(root: Path, g: dict[str, Any],
                llm_verify: Callable[[str, str], str] | None) -> dict[str, Any]:
    gid = str(g.get("id") or "llm_verify")
    if llm_verify is None:
        return {"id": gid, "result": "fail",
                "evidence": "no verifier driver available for llm_verify gate"}
    from .. import prompts
    try:
        rendered = prompts.render(g["prompt"], criteria=g.get("criteria", g["prompt"]),
                                  pass_score=g.get("pass_score", 0.8))
    except prompts.PromptError as exc:
        return {"id": gid, "result": "fail", "evidence": f"gate prompt invalid: {exc}"}
    raw = llm_verify(rendered, str(root))
    score = _extract_score(raw)
    threshold = float(g.get("pass_score", 0.8))
    ok = score is not None and score >= threshold
    return {"id": gid, "result": "pass" if ok else "fail",
            "evidence": f"score={score} threshold={threshold}"}


def _extract_score(raw: str) -> float | None:
    if not raw:
        return None
    text = raw.strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    try:
        return float(obj.get("score"))
    except (TypeError, ValueError, AttributeError):
        return None