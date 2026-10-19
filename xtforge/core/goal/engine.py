"""Goal engine (F3): bounded autonomous loop.

State machine: INIT -> PLAN -> ROUND(i) -> CHECK -> {DONE|ROUND(i+1)|STUCK|
BUDGET_HIT|HALTED}. State lives on disk (runs/<id>/goal.json) so the loop
survives process death and phone sleep.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Callable

from ...atomicio import atomic_write_json, read_json
from ...version import run_dir, version_str
from ..compress import digest as dg
from . import stop as stopmod
from . import verify as vmod
from .stuck import StuckDetector

Driver = Callable[[dict[str, Any]], dict[str, Any]]

REPAIR_PROMPT = (
    "Your previous output could not be parsed as ROUND_REPORT JSON. "
    "Emit ONLY one JSON object with exactly these keys: round, action, "
    "files_touched, evidence, errors, state_digest, claims_done, blocked."
)
MAX_REPAIRS = 1


class Goal:
    def __init__(self, objective: str, *, run_id: str | None = None,
                 rounds: int = stopmod.DEFAULT_ROUNDS,
                 criteria: list[str] | None = None,
                 verify_cmd: str | None = None,
                 budget_tokens: int = stopmod.DEFAULT_BUDGET_TOKENS,
                 budget_min: int = stopmod.DEFAULT_BUDGET_MIN,
                 stuck_k: int = stopmod.DEFAULT_STUCK_K,
                 mode: str = "strict",
                 file_cap: int = stopmod.DEFAULT_FILE_CAP,
                 max_repairs: int = MAX_REPAIRS):
        self.run_id = run_id or f"goal-{uuid.uuid4().hex[:10]}"
        self.objective = objective
        self.max_rounds = stopmod.clamp_rounds(rounds)
        self.criteria = criteria or []
        self.verify_cmd = verify_cmd
        self.budget_tokens = budget_tokens
        self.budget_min = budget_min
        self.mode = mode
        self.file_cap = file_cap
        self.max_repairs = max_repairs
        self.detector = StuckDetector(stuck_k)
        self.state = "INIT"
        self.round_no = 0
        self.started = time.time()
        self.tokens_used = 0
        self.user_stopped = False
        self.reports: list[dict[str, Any]] = []
        self.history: list[dict[str, Any]] = []

    # ---------- persistence ----------

    @property
    def path(self) -> Path:
        return run_dir(self.run_id) / "goal.json"

    def save(self) -> None:
        atomic_write_json(self.path, {
            "xt_version": version_str(), "run_id": self.run_id, "state": self.state,
            "round": self.round_no, "max_rounds": self.max_rounds,
            "objective": self.objective, "criteria": self.criteria,
            "verify_cmd": self.verify_cmd, "budget_tokens": self.budget_tokens,
            "budget_min": self.budget_min, "mode": self.mode,
            "file_cap": self.file_cap, "tokens_used": self.tokens_used,
            "started": self.started, "user_stopped": self.user_stopped,
            "reports": self.reports[-20:], "history": self.history[-50:],
        })

    def load(self) -> bool:
        data = read_json(self.path)
        if not data:
            return False
        self.state = data.get("state", "INIT")
        self.round_no = int(data.get("round", 0))
        self.max_rounds = stopmod.clamp_rounds(int(data.get("max_rounds", self.max_rounds)))
        self.tokens_used = int(data.get("tokens_used", 0))
        self.criteria = list(data.get("criteria") or self.criteria)
        self.verify_cmd = data.get("verify_cmd", self.verify_cmd)
        self.user_stopped = bool(data.get("user_stopped", False))
        self.reports = list(data.get("reports") or [])
        self.history = list(data.get("history") or [])
        self.started = float(data.get("started", self.started))
        return True

    # ---------- prompting ----------

    def round_payload(self, digest_text: str, verifier_feedback: str = "",
                      mem_lines: list[str] | None = None) -> dict[str, Any]:
        return {
            "round": self.round_no + 1,
            "max_rounds": self.max_rounds,
            "objective": self.objective,
            "criteria": self.criteria,
            "verify_cmd": self.verify_cmd or "(none)",
            "state_digest": digest_text,
            "verifier_feedback": verifier_feedback or "(none)",
            "rounds_left": max(0, self.max_rounds - self.round_no),
            "tokens_left": max(0, self.budget_tokens - self.tokens_used),
            "file_cap": self.file_cap,
            "memory": mem_lines or [],
            "run_id": self.run_id,
        }

    def digest(self) -> str:
        if not self.reports:
            return dg.build(obj=self.objective[:120], nxt="start round 1")
        return vmod.summary_digest(self.reports)

    # ---------- report parsing ----------

    def parse_report(self, raw: str) -> dict[str, Any] | None:
        if not raw:
            return None
        text = raw.strip()
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            return None
        import json
        for candidate in (text[start:end + 1], text):
            try:
                obj = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and self._report_valid(obj):
                return obj
        return None

    def _report_valid(self, obj: dict[str, Any]) -> bool:
        required = ("round", "action", "files_touched", "evidence",
                    "errors", "state_digest", "claims_done", "blocked")
        if any(k not in obj for k in required):
            return False
        if not isinstance(obj.get("files_touched"), list):
            return False
        if not isinstance(obj.get("evidence"), list):
            return False
        if not isinstance(obj.get("errors"), list):
            return False
        if not isinstance(obj.get("claims_done"), bool):
            return False
        if obj.get("blocked") is not None and not isinstance(obj.get("blocked"), str):
            return False
        # claims_done without evidence is a contract violation (F3).
        if obj.get("claims_done") and not obj.get("evidence"):
            return False
        return True

    # ---------- main loop ----------

    def run(self, driver: Driver, verifier: Callable[[str, str], str] | None = None,
            changed_files: Callable[[dict[str, Any]], bool] | None = None,
            memory: Callable[[], list[dict[str, Any]]] | None = None) -> dict[str, Any]:
        self.state = "PLAN"
        self.save()
        verifier_feedback = ""
        repairs = 0
        while True:
            self.state = "ROUND"
            mem_lines: list[dict[str, Any]] = []
            if memory is not None:
                try:
                    mem_lines = memory() or []
                except Exception:
                    mem_lines = []
            payload = self.round_payload(self.digest(), verifier_feedback,
                                         mem_lines=mem_lines)
            result = driver(payload)
            self.round_no += 1
            raw = result.get("output", "") if isinstance(result, dict) else str(result)
            self.tokens_used += int(result.get("tokens", 0)) if isinstance(result, dict) else 0
            report = self.parse_report(raw)
            if report is None and repairs < self.max_repairs:
                # Repair is about malformed JSON, not verification: it must work
                # for verifier-less drivers too (MCP round contract).
                repairs += 1
                payload["repair"] = REPAIR_PROMPT
                result = driver(payload)
                self.tokens_used += int(result.get("tokens", 0)) if isinstance(result, dict) else 0
                raw = result.get("output", "")
                report = self.parse_report(raw)
            if report is None:
                self.reports.append({"round": self.round_no, "action": "(unparseable)",
                                     "files_touched": [], "evidence": [], "errors": [
                                         {"sig": "MalformedReport", "msg": "not valid JSON"}],
                                     "state_digest": self.digest(),
                                     "claims_done": False, "blocked": "malformed output"})
                self._record(changed_files, report={}, new_evidence=False)
                verdict = {"passed": False, "score": 0.0,
                           "reasons": ["malformed round report"]}
            else:
                self.reports.append(report)
                touched = bool(report.get("files_touched"))
                self._record(changed_files, report, new_evidence=bool(report.get("evidence")))
                verdict = self._check(report, verifier)
            self.state = "CHECK"
            self.save()
            self.state, reason = stopmod.should_stop(
                self.round_no, self.max_rounds, self.started, self.tokens_used,
                self.budget_tokens, self.budget_min, self.detector,
                self.user_stopped, blocked=bool(report and report.get("blocked")))
            self.history.append({"round": self.round_no, "state": self.state,
                                 "reason": reason, "verdict": verdict["passed"]})
            self.save()
            if verdict["passed"]:
                self.state = "DONE"
                self.save()
                return self.finish("DONE", "criteria satisfied", verdict)
            if self.state in stopmod.TERMINAL:
                return self.finish(self.state, reason, verdict)
            verifier_feedback = "; ".join(verdict["reasons"][:3]) or "criteria unmet"
        return self.finish(self.state, "loop exited", {})

    def _record(self, changed_files: Callable[[dict[str, Any]], bool] | None,
                report: dict[str, Any], new_evidence: bool) -> None:
        changed = bool(report.get("files_touched")) if report else False
        if changed_files is not None and report:
            try:
                changed = changed or bool(changed_files(report))
            except Exception:
                changed = changed
        self.detector.observe(report or {"errors": [], "state_digest": self.digest()},
                              changed, new_evidence)

    def _check(self, report: dict[str, Any],
               verifier: Callable[[str, str], str] | None) -> dict[str, Any]:
        cmd_result = None
        if self.verify_cmd:
            cmd_result = vmod.run_verify(self.verify_cmd, cwd=str(run_dir(self.run_id).parent.parent))
        verifier_raw = None
        if verifier is not None and self.criteria:
            bundle = vmod.evidence_bundle(cmd_result, report.get("files_touched") or [],
                                          result_artifacts(report))
            verifier_raw = verifier("; ".join(self.criteria), bundle)
        verdict = vmod.check(self.criteria, cmd_result, verifier_raw, mode=self.mode)
        # Objective-command acceptance: when no independent verifier is wired
        # (MCP-native runs), a passing --verify command plus an evidence-backed
        # claims_done is the strongest available signal. Self-report alone still
        # never passes; a valid verifier verdict always takes precedence.
        if (not verdict["passed"] and verifier_raw is None
                and cmd_result is not None and cmd_result.get("ok")
                and report.get("claims_done") and report.get("evidence")):
            verdict = {**verdict, "passed": True, "score": max(verdict.get("score", 0.0), 1.0),
                       "acceptance": "objective_command_evidence",
                       "reasons": (verdict.get("reasons") or [])
                       + ["verify command passed; claims_done backed by evidence"]}
        if cmd_result is not None and not cmd_result.get("ok") and cmd_result.get("tail"):
            tail = " / ".join(cmd_result["tail"].splitlines()[-3:])
            verdict["reasons"] = (verdict.get("reasons") or []) + [f"verify tail: {tail}"]
        return verdict

    def finish(self, outcome: str, reason: str, verdict: dict[str, Any]) -> dict[str, Any]:
        files = [f for r in self.reports for f in (r.get("files_touched") or [])]
        summary = stopmod.summary(outcome, reason, self.round_no, self.max_rounds,
                                  files, reason, "/goal status")
        summary["score"] = verdict.get("score", 0.0)
        summary["detector"] = self.detector.status()
        summary["tokens_used"] = self.tokens_used
        self.state = outcome
        self.save()
        return summary

    # ---------- commands ----------

    def extend(self, n: int) -> int:
        before = self.max_rounds
        self.max_rounds = stopmod.clamp_rounds(max(self.max_rounds + n, self.max_rounds))
        self.save()
        return self.max_rounds - before

    def stop(self) -> None:
        self.user_stopped = True
        self.state = "HALTED"
        self.save()

    def pause(self) -> None:
        self.state = "HALTED"
        self.save()

    def resume(self) -> None:
        if self.state in ("HALTED", "STUCK", "BUDGET_HIT"):
            self.state = "PLAN"
            self.user_stopped = False
            self.save()


def result_artifacts(report: dict[str, Any]) -> list[str]:
    arts = report.get("artifacts") or []
    return [a.get("path", "") if isinstance(a, dict) else str(a) for a in arts]