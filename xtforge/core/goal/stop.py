"""Goal stop conditions (F3). Every condition is hard and checked every round.

Termination is provable: rounds are capped, budgets are finite, and the
detector trips on no-progress and repeated-error signatures.
"""
from __future__ import annotations

import os
import time
from typing import Any

from .stuck import StuckDetector

HARD_CAP = int(os.environ.get("XT_GOAL_HARD_CAP", "50"))
DEFAULT_ROUNDS = 8
DEFAULT_BUDGET_TOKENS = 120_000
DEFAULT_BUDGET_MIN = 60
DEFAULT_STUCK_K = 2
DEFAULT_FILE_CAP = 12

STATES = ("INIT", "PLAN", "ROUND", "CHECK",
          "DONE", "STUCK", "BUDGET_HIT", "HALTED")

# Terminal states — reaching any one guarantees the loop exits.
TERMINAL = {"DONE", "STUCK", "BUDGET_HIT", "HALTED"}


def should_stop(round_no: int, max_rounds: int, started: float,
                tokens_used: int, budget_tokens: int, budget_min: int,
                detector: StuckDetector, user_stopped: bool,
                blocked: bool) -> tuple[str | None, str]:
    """Return (terminal_state, reason). None means continue."""
    if user_stopped:
        return "HALTED", "user requested stop"
    if blocked:
        return "HALTED", "agent reported blocked"
    if round_no >= min(max_rounds, HARD_CAP):
        return "BUDGET_HIT", f"rounds exhausted ({round_no}/{min(max_rounds, HARD_CAP)})"
    if tokens_used >= budget_tokens:
        return "BUDGET_HIT", f"token budget exhausted ({tokens_used}/{budget_tokens})"
    if time.time() - started >= budget_min * 60:
        return "BUDGET_HIT", f"time budget exhausted ({budget_min} min)"
    stuck, reason = detector.is_stuck()
    if stuck:
        return "STUCK", reason
    loop, loop_reason = detector.repeated_error()
    if loop:
        return "STUCK", loop_reason
    return None, ""


def clamp_rounds(n: int) -> int:
    """`extend` can raise N but never above XT_GOAL_HARD_CAP."""
    return max(1, min(int(n), HARD_CAP))


def summary(outcome: str, reason: str, rounds_used: int, max_rounds: int,
            files_changed: list[str], remains: str,
            next_command: str) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "reason": reason,
        "rounds_used": rounds_used,
        "max_rounds": max_rounds,
        "what_changed": sorted(set(files_changed)),
        "what_remains": remains,
        "next_recommended_command": next_command,
    }