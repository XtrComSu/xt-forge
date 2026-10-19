"""Verification (F3): objective command -> independent verifier -> engine verdict.

Ordering per spec:
 1. the objective's --verify shell command exit code (strongest signal)
 2. criteria checklist judged from evidence ONLY, in a fresh context
 3. engine decides; self-reported "done" without evidence is never enough.
"""
from __future__ import annotations

import re
import subprocess
import time
from typing import Any

from ..compress import digest as dg

VERIFY_TIMEOUT = 900
JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def run_verify(cmd: str, cwd: str | None = None,
               timeout: int = VERIFY_TIMEOUT) -> dict[str, Any]:
    """Run the objective's verification command. Exit code is authoritative."""
    from ..route import guard
    reason = guard.check_command(cmd)
    if reason:
        return {"ok": False, "exit": None, "tail": "", "err": f"denied: {reason}"}
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit": None, "tail": "",
                "err": f"verify timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "exit": None, "tail": "", "err": str(exc)}
    out = (r.stdout or "") + (r.stderr or "")
    return {"ok": r.returncode == 0, "exit": r.returncode,
            "tail": "\n".join(out.splitlines()[-15:]),
            "ms": int((time.perf_counter() - t0) * 1000)}


def parse_verdict(raw: str) -> dict[str, Any] | None:
    """Parse a verifier JSON verdict from model output, tolerating prose fences."""
    if not raw:
        return None
    text = raw.strip()
    start = text.find("{")
    if start < 0:
        return None
    end = text.rfind("}")
    if end < start:
        return None
    import json
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or "results" not in obj:
        return None
    return obj


REQUIRED = ("results", "score", "verdict")
VALID_STATUS = {"met", "unmet", "unknown"}


def validate_verdict(obj: dict[str, Any] | None) -> tuple[bool, list[str]]:
    if obj is None:
        return False, ["no JSON verdict found"]
    problems: list[str] = []
    for k in REQUIRED:
        if k not in obj:
            problems.append(f"missing key: {k}")
    if obj.get("verdict") not in {"pass", "fail", "insufficient_evidence"}:
        problems.append("verdict must be pass|fail|insufficient_evidence")
    results = obj.get("results")
    if not isinstance(results, list):
        problems.append("results must be a list")
        return False, problems
    for i, r in enumerate(results):
        if not isinstance(r, dict):
            problems.append(f"results[{i}] not an object")
            continue
        if r.get("status") not in VALID_STATUS:
            problems.append(f"results[{i}].status must be met|unmet|unknown")
    return not problems, problems


def check(criteria: list[str], verify_result: dict[str, Any] | None,
          verifier_raw: str | None, mode: str = "strict",
          pass_score: float = 1.0) -> dict[str, Any]:
    """Combine objective-command result and independent verdict into a decision."""
    reasons: list[str] = []
    if verify_result is not None:
        if verify_result.get("err"):
            reasons.append(f"verify error: {verify_result['err']}")
        elif not verify_result.get("ok"):
            reasons.append(f"verify command exited {verify_result.get('exit')}")
    obj = parse_verdict(verifier_raw) if verifier_raw else None
    valid, problems = validate_verdict(obj)
    if verifier_raw and not valid:
        reasons.append("verifier output invalid: " + "; ".join(problems[:3]))
    score = 0.0
    if obj and valid:
        try:
            score = float(obj.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
    cmd_ok = verify_result.get("ok") if verify_result is not None else None
    if mode == "strict":
        threshold = 1.0
    else:
        threshold = pass_score
    if cmd_ok is None:
        # No objective command: the independent verifier alone decides.
        passed = valid and score >= threshold
    else:
        passed = bool(cmd_ok) and valid and score >= threshold
    return {"passed": passed, "score": score, "reasons": reasons,
            "cmd_ok": cmd_ok, "verifier_valid": valid}


def evidence_bundle(verify_result: dict[str, Any] | None, files_touched: list[str],
                    artifacts: list[str], diff_stat: str = "") -> str:
    """Assemble the ONLY evidence the verifier sees (never the agent's opinion)."""
    parts = ["<evidence>"]
    if verify_result is not None:
        parts.append(f"cmd_exit={verify_result.get('exit')}")
        if verify_result.get("err"):
            parts.append(f"cmd_err={verify_result['err']}")
        if verify_result.get("tail"):
            parts.append("output_tail:")
            parts.append(verify_result["tail"][-2000:])
    if diff_stat:
        parts.append("diff_stat:")
        parts.append(diff_stat[:1000])
    parts.append("files_touched=" + ",".join(files_touched[:20]))
    if artifacts:
        parts.append("artifacts=" + ",".join(artifacts[:20]))
    parts.append("</evidence>")
    return "\n".join(parts)


def summary_digest(reports: list[dict[str, Any]]) -> str:
    done = [r.get("action", "?") for r in reports if (r.get("claims_done"))]
    files = sorted({f for r in reports for f in (r.get("files_touched") or [])})
    errs: list[str] = []
    for r in reports:
        errs.extend(dg.error_sig(str(e.get("sig", ""))) for e in (r.get("errors") or [])
                    if isinstance(e, dict))
    return dg.build(
        obj="goal",
        done="; ".join(done[-3:]) if done else "none",
        files=",".join(files[:8]) if files else "none",
        decisions="none",
        errors=dg.tally_errors(errs),
        nxt="next round" if reports else "init",
        open_="none")