"""Phase drivers (F4): the pluggable boundary between runner and harness.

Each phase runs in a RESET context: the driver receives a fresh prompt and no
prior chat history. Driver.run_phase is the only required method.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Protocol

DRIVER_TIMEOUT = 1800


class Driver(Protocol):
    name: str

    def run_phase(self, prompt: str, tools: list[str], budget: dict[str, Any],
                  phase_id: str) -> dict[str, Any]:
        """Returns PhaseResult: {status, transcript_tail, artifacts, report_json}."""
        ...


def _result(status: str, transcript_tail: str = "", report_json: dict[str, Any] | None = None,
            artifacts: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {"status": status, "transcript_tail": transcript_tail,
            "artifacts": artifacts or [],
            "report_json": report_json or {}, **extra}


def parse_phase_report(raw: str) -> dict[str, Any]:
    """Extract the PHASE_REPORT JSON object from driver output."""
    if not raw:
        return {}
    text = raw.strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        return {}
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


class FakeDriver:
    """Deterministic driver for tests and dry runs. Writes declared outputs."""

    name = "fake"

    def __init__(self, outputs: list[str] | None = None, fail: bool = False,
                 workdir: str | Path = "."):
        self.outputs = outputs or []
        self.fail = fail
        self.workdir = Path(workdir)
        self.calls: list[dict[str, Any]] = []

    def run_phase(self, prompt: str, tools: list[str], budget: dict[str, Any],
                  phase_id: str) -> dict[str, Any]:
        self.calls.append({"phase": phase_id, "prompt_len": len(prompt),
                           "tools": tools, "budget": budget})
        if self.fail:
            return _result("failed", "fake driver configured to fail")
        written: list[str] = []
        for rel in self.outputs:
            p = self.workdir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"# produced by {phase_id}\n", encoding="utf-8")
            written.append(str(p))
        report = {"phase": phase_id,
                  "outputs": [{"path": o, "status": "created"} for o in self.outputs],
                  "gates": [], "decisions": [f"{phase_id} used the fake driver"],
                  "open_questions": [], "interfaces": []}
        return _result("ok", f"wrote {len(written)} artifacts", report, written)


class CliDriver:
    """Spawns a harness non-interactively once per phase (reset per phase).

    UNVERIFIED until a real harness --help confirms the flags. Configured via
    XT_BUILD_CMD (a shell command template) so no harness API is hardcoded.
    """

    name = "cli"

    def __init__(self, command_template: str | None = None,
                 workdir: str | Path = ".", env: dict[str, str] | None = None):
        self.command_template = command_template or os.environ.get("XT_BUILD_CMD", "")
        self.workdir = Path(workdir)
        self.env = env

    def available(self) -> bool:
        return bool(self.command_template)

    def run_phase(self, prompt: str, tools: list[str], budget: dict[str, Any],
                  phase_id: str) -> dict[str, Any]:
        if not self.command_template:
            return _result("unavailable", "no XT_BUILD_CMD configured")
        prompt_file = self.workdir / f".xt-prompt-{phase_id}.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        cmd = self.command_template.format(
            prompt_file=str(prompt_file), phase_id=phase_id,
            workdir=str(self.workdir))
        env = {**os.environ, **(self.env or {})}
        env.setdefault("XT_PHASE_ID", phase_id)
        try:
            r = subprocess.run(cmd, shell=True, cwd=str(self.workdir), env=env,
                               capture_output=True, text=True, timeout=DRIVER_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result("failed", f"timeout after {DRIVER_TIMEOUT}s")
        except OSError as exc:
            return _result("failed", str(exc))
        tail = "\n".join(((r.stdout or "") + (r.stderr or "")).splitlines()[-40:])
        report = parse_phase_report(r.stdout or "")
        status = "ok" if r.returncode == 0 else "failed"
        return _result(status, tail, report)


class McpDriver:
    """Lets an already-running agent pull phases: build_next / build_report.

    Reset is soft here — the agent is instructed to disregard earlier phase
    context. Works in any MCP-capable harness.

    `wait_timeout=0` (default) keeps the original non-blocking contract: a
    phase with no submission returns "unavailable" immediately. The MCP server
    passes a positive timeout so an agent has time to answer build_next and
    return build_report before the phase is declared failed.
    """

    name = "mcp"

    def __init__(self, workdir: str | Path = ".", wait_timeout: float = 0.0):
        self.workdir = Path(workdir)
        self.session_id = f"build-{uuid.uuid4().hex[:10]}"
        self.pending_prompt: str | None = None
        self.pending_phase: str | None = None
        self.submissions: list[dict[str, Any]] = []
        self.wait_timeout = float(wait_timeout)
        self._gate = threading.Event()

    def next_phase(self, prompt: str, tools: list[str], budget: dict[str, Any],
                   phase_id: str) -> dict[str, Any]:
        self.pending_prompt = prompt
        self.pending_phase = phase_id
        self._gate.clear()
        return {"phase": phase_id, "prompt": prompt, "tools": tools,
                "budget": budget, "session": self.session_id,
                "instruction": "Work only this phase. Ignore context from earlier phases."}

    def submit(self, phase_id: str, report: dict[str, Any],
               transcript_tail: str = "") -> dict[str, Any]:
        self.submissions.append({"phase": phase_id, "report": report})
        if self.pending_phase == phase_id:
            self.pending_prompt = None
            self.pending_phase = None
        self._gate.set()
        return _result("ok", transcript_tail, report)

    def run_phase(self, prompt: str, tools: list[str], budget: dict[str, Any],
                   phase_id: str) -> dict[str, Any]:
        """Waits for a matching build_report when wait_timeout > 0."""
        self.next_phase(prompt, tools, budget, phase_id)
        deadline = time.monotonic() + self.wait_timeout
        while True:
            for sub in self.submissions:
                if sub["phase"] == phase_id:
                    return _result("ok", "", sub["report"])
            remaining = deadline - time.monotonic()
            if self.wait_timeout <= 0 or remaining <= 0:
                break
            self._gate.wait(timeout=min(1.0, remaining))
            self._gate.clear()
        return _result("failed" if self.wait_timeout > 0 else "unavailable",
                       f"no build_report submitted for {phase_id}")