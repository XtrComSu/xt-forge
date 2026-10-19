"""MCP goal driver (F3): the harness agent itself executes goal rounds.

Unlike CliGoalDriver (one shell command per round), this driver hands each
round to the *live harness session*: the agent pulls the round prompt with
`goal_next`, does the work with its real tools, and files `goal_report`. The
engine thread blocks inside `__call__` until a report arrives.

Same contract shape as build's McpDriver. One driver = one run.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any

from .. import prompts

DEFAULT_WAIT_TIMEOUT = 900.0
ROUND_TOOLS = ("bash, read, glob, grep, edit, write, task, todowrite; "
               "xt-forge_* MCP tools (route_*, flash_ops, mem_*, xt_compress)")


class McpGoalDriver:
    """Blocks the engine until the harness submits the round report."""

    name = "mcp"

    def __init__(self, wait_timeout: float = DEFAULT_WAIT_TIMEOUT):
        self.session_id = f"goal-{uuid.uuid4().hex[:10]}"
        self.wait_timeout = float(wait_timeout)
        self._cond = threading.Condition()
        self._pending: dict[str, Any] | None = None
        self._submission: dict[str, Any] | None = None
        self._abort_reason: str | None = None
        self.calls = 0

    # ---------- engine side ----------

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._cond:
            if self._abort_reason:
                return self._abort_output(payload)
            self.calls += 1
            kind = "repair" if payload.get("repair") else "round"
            self._pending = {"round": int(payload.get("round", 0)), "kind": kind,
                             "payload": dict(payload), "opened": time.time()}
            self._submission = None
            self._cond.notify_all()
            deadline = time.monotonic() + self.wait_timeout
            while self._submission is None:
                if self._abort_reason:
                    self._pending = None
                    return self._abort_output(payload)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._pending = None
                    return {"output": "", "tokens": 0,
                            "timeout": True}
                self._cond.wait(timeout=min(1.0, remaining))
            out = self._submission
            self._submission = None
            self._pending = None
            return out

    # ---------- harness side ----------

    def next_prompt(self) -> dict[str, Any] | None:
        with self._cond:
            if self._pending is None:
                return None
            pending = dict(self._pending)
            pending["prompt"] = render_round_prompt(pending["payload"])
            return pending

    def submit(self, raw_output: str, tokens: int = 0) -> bool:
        """Deliver a round report. False when nothing is pending."""
        with self._cond:
            if self._pending is None and not self._abort_reason:
                return False
            self._submission = {"output": raw_output, "tokens": int(tokens or 0)}
            self._cond.notify_all()
            return True

    def abort(self, reason: str) -> None:
        with self._cond:
            self._abort_reason = reason
            self._cond.notify_all()

    # ---------- internals ----------

    def _abort_output(self, payload: dict[str, Any]) -> dict[str, Any]:
        report = {
            "round": int(payload.get("round", 0)),
            "action": "halted by control",
            "files_touched": [], "evidence": [],
            "errors": [], "state_digest": "OBJ=halted",
            "claims_done": False,
            "blocked": self._abort_reason or "aborted",
        }
        return {"output": json.dumps(report), "tokens": 0, "aborted": True}


def render_round_prompt(payload: dict[str, Any]) -> str:
    """Canon prompt (prompts/goal_round.md) + repair banner + pinned memory."""
    text = prompts.render(
        "goal_round",
        round=payload.get("round", 1),
        max_rounds=payload.get("max_rounds", 8),
        objective=payload.get("objective", ""),
        criteria="; ".join(payload.get("criteria") or []) or "(none declared)",
        verifier_feedback=payload.get("verifier_feedback") or "(none)",
        rounds_left=payload.get("rounds_left", 0),
        tokens_left=payload.get("tokens_left", 0),
        file_cap=payload.get("file_cap", 12),
        tools=ROUND_TOOLS,
        verify_cmd=payload.get("verify_cmd") or "(none)",
    )
    if payload.get("repair"):
        text = ("<repair>" + str(payload["repair"]) + "</repair>\n\n" + text)
    mem = payload.get("memory") or []
    if mem:
        lines = "\n".join(f"[MEM:{m.get('k', '?')}] {m.get('v', '')}"
                          if isinstance(m, dict) else f"[MEM:{m}]" for m in mem)
        text += ("\n\n<pinned_memory>\n" + lines + "\n</pinned_memory>")
    return text
