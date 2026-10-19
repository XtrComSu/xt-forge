"""Build runner (F4): phase loop with reset contexts, gates, handoffs, resume.

State lives in runs/<id>/build.json, so a crash or phone sleep resumes at the
exact phase boundary it stopped on.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Callable

from ...atomicio import atomic_write_json, read_json
from ...version import run_dir, version_str
from . import gates as gatemod
from . import handoff as hoff
from . import loader
from .drivers import parse_phase_report
from .loader import Phase, Workflow

PENDING = "pending"
RUNNING = "running"
PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"
HALTED = "halted"


class BuildRun:
    def __init__(self, wf: Workflow, run_id: str | None = None,
                 workdir: str | Path | None = None, from_phase: str | None = None,
                 to_phase: str | None = None):
        self.wf = wf
        self.run_id = run_id or f"build-{wf.id}-{uuid.uuid4().hex[:8]}"
        self.workdir = Path(workdir or Path.cwd())
        self.from_phase = from_phase
        self.to_phase = to_phase
        self.state: dict[str, Any] = {
            "xt_version": version_str(), "workflow": wf.id, "run_id": self.run_id,
            "workdir": str(self.workdir), "started": time.time(),
            "phase_order": [], "phases": {}, "current": None,
            "halted": False, "halt_reason": None,
        }
        self.packets: dict[str, dict[str, Any]] = {}

    # ---------- persistence ----------

    @property
    def path(self) -> Path:
        return run_dir(self.run_id) / "build.json"

    def save(self) -> None:
        atomic_write_json(self.path, self.state)

    def load(self) -> bool:
        data = read_json(self.path)
        if not data or data.get("workflow") != self.wf.id:
            return False
        self.state = data
        self.run_id = data.get("run_id", self.run_id)
        self.workdir = Path(data.get("workdir", self.workdir))
        return True

    # ---------- phase selection ----------

    def selection(self) -> list[str]:
        order = self.wf.order()
        if self.from_phase and self.from_phase in order:
            order = order[order.index(self.from_phase):]
        if self.to_phase and self.to_phase in order:
            order = order[:order.index(self.to_phase) + 1]
        return order

    def phase_state(self, pid: str) -> dict[str, Any]:
        return self.state["phases"].setdefault(pid, {
            "status": PENDING, "attempts": 0, "started": None, "finished": None,
            "gates": [], "report": {}, "error": None, "skipped": False,
        })

    def set_status(self, pid: str, status: str, **extra: Any) -> None:
        st = self.phase_state(pid)
        st["status"] = status
        st.update(extra)
        self.save()

    # ---------- main loop ----------

    def run(self, driver: Any, llm_verify: Callable[[str, str], str] | None = None,
            dry_run: bool = False) -> dict[str, Any]:
        order = self.selection()
        self.state["phase_order"] = order
        self.state.setdefault("phases", {})
        self.save()
        variables = self.wf.extend_vars({})
        previous_report: dict[str, Any] = {}
        previous_phase = ""
        for pid in order:
            phase = self.wf.phase(pid)
            if phase is None:
                continue
            if not loader.evaluate_condition(phase.when, variables):
                self.set_status(pid, SKIPPED, reason="when condition false")
                continue
            st = self.phase_state(pid)
            if st["status"] == PASSED and not st.get("retry"):
                continue  # resume: already done
            packet = self._packet_for(previous_phase, previous_report, phase)
            try:
                report = self._run_phase(phase, driver, packet, llm_verify, dry_run)
            except Exception as exc:
                self.set_status(pid, FAILED, error=f"runner exception: {exc}")
                return self._finish(HALTED, f"exception in phase {pid}: {exc}")
            previous_phase, previous_report = pid, report
            if st["status"] == PASSED:
                self._maybe_halt(pid, phase)
                if self.state["halted"]:
                    return self._finish(HALTED, self.state["halt_reason"] or "halted")
                if phase.pause_for_human:
                    self.set_status(pid, PASSED, paused_for_human=True)
                    return self._finish("paused", f"phase {pid} awaits human input")
            else:
                action = self._handle_failure(phase)
                if action == "halt":
                    return self._finish(HALTED, f"phase {pid} failed: {st.get('error')}")
        return self._finish("done", "all phases complete")

    def _packet_for(self, from_phase: str, report: dict[str, Any],
                    phase: Phase) -> dict[str, Any]:
        if not from_phase:
            return hoff.empty_packet("", phase.id, objective=str(self.wf.vars.get("product", "")))
        level = phase.handoff.get("level", hoff.DEFAULT_LEVEL)
        include = phase.handoff.get("include")
        packet = hoff.build_packet(from_phase, phase.id, report, level=level,
                                   include=include,
                                   objective=str(self.wf.vars.get("product", "")))
        check = hoff.validate(packet, hoff.LEVEL_BUDGET.get(level, 1500))
        if not check["valid"]:
            packet, dropped = hoff.enforce_budget(packet, hoff.LEVEL_BUDGET.get(level, 1500))
            packet["_compressed"] = dropped
        self.packets[phase.id] = packet
        return packet

    def _run_phase(self, phase: Phase, driver: Any, packet: dict[str, Any],
                   llm_verify: Callable[[str, str], str] | None,
                   dry_run: bool) -> dict[str, Any]:
        st = self.phase_state(phase.id)
        st["attempts"] = int(st.get("attempts", 0)) + 1
        st["started"] = time.time()
        st["status"] = RUNNING
        st.pop("error", None)
        self.state["current"] = phase.id
        self.save()
        prompt = loader.phase_prompt(self.wf, phase, handoff_block=packet)
        if dry_run:
            # A dry run reports the plan; it neither requires inputs nor runs gates.
            self.set_status(phase.id, PASSED, dry_run=True,
                            report={"phase": phase.id, "outputs": [], "gates": []},
                            prompt_preview=prompt[:400])
            return {"phase": phase.id}
        for rel in phase.inputs:
            if not (self.workdir / rel).exists():
                self.set_status(phase.id, FAILED, error=f"missing input artifact: {rel}")
                return {}
        budget = {"max_rounds": phase.max_rounds, "compress": phase.compress,
                  "thinking": phase.thinking, "model": phase.model}
        result = driver.run_phase(prompt, phase.tools, budget, phase.id)
        if not isinstance(result, dict):
            self.set_status(phase.id, FAILED, error="driver returned no result")
            return {}
        report = result.get("report_json") or parse_phase_report(
            result.get("transcript_tail", ""))
        missing_inputs = [o for o in phase.outputs
                          if not any(a.get("path", "").endswith(o)
                                     for a in (report.get("outputs") or [])
                                     if isinstance(a, dict))]
        results = gatemod.run_gates(phase.gates, self.workdir, llm_verify)
        if missing_inputs and phase.gates:
            results = results + [{"id": f"output:{p}", "result": "fail",
                                  "evidence": f"declared output not reported: {p}"}
                                 for p in missing_inputs]
        gsum = gatemod.summary(results)
        st["gates"] = results
        st["report"] = report
        st["finished"] = time.time()
        if gsum["all_passed"]:
            st["status"] = PASSED
            st["retry"] = False
        else:
            st["status"] = FAILED
            st["error"] = f"gates failed: {gsum['failed_ids']}"
        self.save()
        return report

    def _handle_failure(self, phase: Phase) -> str:
        on_fail = phase.on_fail or {}
        st = self.phase_state(phase.id)
        retries = int(on_fail.get("retry", 0))
        if int(st.get("attempts", 0)) <= retries:
            st["status"] = PENDING
            self.save()
            return "retry"
        action = str(on_fail.get("then", "halt"))
        if action == "skip":
            st["status"] = SKIPPED
            self.save()
            return "skip"
        if action.startswith("goto:"):
            target = action.split(":", 1)[1]
            if target in {p.id for p in self.wf.phases}:
                st["status"] = SKIPPED
                st["goto"] = target
                self.save()
                return "goto"
        return "halt"

    def _maybe_halt(self, pid: str, phase: Phase) -> None:
        if phase.pause_for_human:
            return

    def _finish(self, outcome: str, reason: str) -> dict[str, Any]:
        self.state["outcome"] = outcome
        self.state["reason"] = reason
        self.state["finished"] = time.time()
        self.state["current"] = None
        self.save()
        phases = {k: v.get("status") for k, v in self.state["phases"].items()}
        return {"ok": outcome == "done", "outcome": outcome, "reason": reason,
                "run_id": self.run_id, "phases": phases,
                "failed": [k for k, v in phases.items() if v == FAILED],
                "state_path": str(self.path)}

    # ---------- commands ----------

    def status(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "workflow": self.wf.id,
                "outcome": self.state.get("outcome", "in_progress"),
                "current": self.state.get("current"),
                "phases": {k: v.get("status") for k, v in self.state["phases"].items()}}

    def retry_phase(self, pid: str) -> dict[str, Any]:
        st = self.phase_state(pid)
        st["status"] = PENDING
        st["retry"] = True
        self.save()
        return {"phase": pid, "status": PENDING, "retry": True}

    def skip_phase(self, pid: str) -> dict[str, Any]:
        self.set_status(pid, SKIPPED, skipped=True)
        return {"phase": pid, "status": SKIPPED}

    def resume(self) -> bool:
        return self.load()


# ---------- run lookup ----------

def latest_run_id(workflow_id: str) -> str | None:
    """Most recent run id for a workflow, newest mtime first."""
    from ...version import runs_dir
    cands = sorted(runs_dir().glob(f"build-{workflow_id}-*/build.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0].parent.name if cands else None


def open_run(wf: Workflow, run_id: str | None = None,
             workdir: str | Path = ".", **kw: Any) -> BuildRun | None:
    """Open an explicit or the most recent run, or None when there is none.

    `build status <wf>` used to fabricate a fresh random run id, so it always
    reported an empty pipeline instead of the real one.
    """
    resolved = run_id or latest_run_id(wf.id)
    if not resolved:
        return None
    run = BuildRun(wf, run_id=resolved, workdir=workdir, **kw)
    run.load()
    return run