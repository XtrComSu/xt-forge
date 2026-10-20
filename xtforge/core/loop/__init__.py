"""Loop helpers: the grammar and the policy, exposed as pure verbs.

Scheduling itself lives in the harness (the OpenCode plugin owns timers);
everything that decides *whether* and *when* lives here so it is testable and
identical across harnesses.
"""
from __future__ import annotations

from .parse import (MAX_DELAY, MAX_TASK_CHARS, MIN_DELAY, clamp_delay,
                    next_delay, normalize_interval, parse_command,
                    parse_interval, parse_markers, quiet_penalty)
from .schedule import (KILL_SWITCH, LIFETIME_SECONDS, MAX_TASKS, Schedule,
                       create, disabled, enforce, is_alive, jitter)

__all__ = [
    "KILL_SWITCH", "LIFETIME_SECONDS", "MAX_DELAY", "MAX_TASKS",
    "MAX_TASK_CHARS", "MIN_DELAY", "Schedule", "clamp_delay", "create",
    "disabled", "enforce", "is_alive", "jitter", "next_delay",
    "normalize_interval", "parse_command", "parse_interval", "parse_markers",
    "quiet_penalty",
]
