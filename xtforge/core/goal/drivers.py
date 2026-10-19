"""Goal drivers (F3): how a goal loop gets its rounds produced.

A driver is `Callable[[payload], {"output": str, "tokens": int}]`. The CLI and
MCP surfaces share `start()` so both emit the identical contract when no driver
is configured.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Callable

GOAL_TIMEOUT = 1800
DRIVER_REQUIRED = "goal run requires a driver"


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


class CliGoalDriver:
    """Runs `XT_GOAL_DRIVER` (a shell command) once per round.

    The round payload is piped to the command as JSON on stdin; stdout becomes
    the ROUND_REPORT text. `{round}`, `{run_id}` and friends may be used in the
    template as placeholders.
    """

    name = "cli"

    def __init__(self, command_template: str | None = None,
                 timeout: int = GOAL_TIMEOUT, env: dict[str, str] | None = None):
        self.command_template = (command_template
                                 if command_template is not None
                                 else os.environ.get("XT_GOAL_DRIVER", ""))
        self.timeout = timeout
        self.env = env

    def available(self) -> bool:
        return bool(self.command_template)

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.command_template:
            raise RuntimeError(DRIVER_REQUIRED)
        try:
            cmd = self.command_template.format_map(_SafeDict(payload))
        except (ValueError, IndexError):
            cmd = self.command_template
        env = {**os.environ, **(self.env or {})}
        env.setdefault("XT_GOAL_RUN_ID", str(payload.get("run_id", "")))
        r = subprocess.run(cmd, shell=True, input=json.dumps(payload, default=str),
                           capture_output=True, text=True, timeout=self.timeout,
                           env=env)
        tail = (r.stdout or "") + (r.stderr or "")
        return {"output": r.stdout or "", "tokens": int(payload.get("tokens", 0) or 0),
                "returncode": r.returncode, "log": tail[-4000:]}


def resolve_driver(driver: Callable[[dict[str, Any]], dict[str, Any]] | None = None
                   ) -> Callable[[dict[str, Any]], dict[str, Any]] | None:
    """Return the configured driver, or None when the harness must provide one."""
    if driver is not None:
        return driver
    cli = CliGoalDriver()
    return cli if cli.available() else None


def flash_memory_provider() -> list[dict[str, Any]]:
    """Pinned flash notes, injected into every round payload (the /mw wire)."""
    try:
        from ..mem.flash import Flash
        return [{"k": e.get("k"), "v": e.get("v")} for e in Flash().wired()]
    except Exception:
        return []


def start(objective: str, *, rounds: int = 8, criteria: list[str] | None = None,
          verify_cmd: str | None = None, budget_tokens: int | None = None,
          driver: Callable[[dict[str, Any]], dict[str, Any]] | None = None
          ) -> dict[str, Any]:
    """Start a goal loop, or report the driver-required contract verbatim.

    Shared by the CLI (`xtforge goal run`) and the MCP `goal_run` tool so the
    two surfaces can never disagree about the error text.
    """
    from .engine import Goal
    active = resolve_driver(driver)
    if active is None:
        return {"error": DRIVER_REQUIRED, "objective": objective,
                "hint": "set XT_GOAL_DRIVER=<command>, or start the loop from a "
                        "harness session that can act as the driver"}
    kwargs: dict[str, Any] = {"rounds": rounds, "criteria": criteria or [],
                              "verify_cmd": verify_cmd}
    if budget_tokens:
        kwargs["budget_tokens"] = budget_tokens
    goal = Goal(objective, **kwargs)
    return goal.run(active, memory=flash_memory_provider)
