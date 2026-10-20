"""Loop grammar: intervals, task commands, and completion markers.

Pure logic, no timers. The harness owns scheduling; this owns the language, so
the rules are testable and identical everywhere.

    /loop 2h check the CI             fixed cadence
    /loop check the CI every 2h       fixed cadence (other order)
    /loop check the CI                self-paced
    /loop 2h                          fixed, task from loop.md
    /loop                             self-paced, task from loop.md

Self-paced iterations end with exactly one marker:

    <loop-next delay="300" reason="CI still running"/>
    <loop-done reason="deploy is green"/>

A missing marker is a gap, not a crash: the caller schedules one safety check
and then stops.
"""
from __future__ import annotations

import re
from typing import Any

UNIT_SECONDS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}
NAMED = {
    "minutely": 60, "hourly": 3600, "daily": 86400, "nightly": 86400,
    "weekly": 604800,
}

# Clean cadence steps, matching the cron-like expectations people carry.
STEPS_SECONDS = (
    [n * 60 for n in (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30)] +
    [n * 3600 for n in (1, 2, 3, 4, 6, 8, 12)] +
    [n * 86400 for n in (1, 2, 3, 7)]
)
MIN_INTERVAL = 60
MAX_INTERVAL = 7 * 86400
MIN_DELAY = 60
MAX_DELAY = 3600
MAX_TASK_CHARS = 4000

INTERVAL_RE = re.compile(
    r"^\s*(?:every\s+)?(\d+)\s*"
    r"(s|sec|secs|second|seconds|m|min|mins|minute|minutes|"
    r"h|hr|hrs|hour|hours|d|day|days|w|week|weeks)\s*$", re.IGNORECASE)
LEADING_RE = re.compile(
    r"^\s*(?:every\s+)?(\d+\s*(?:s|sec|secs|second|seconds|m|min|mins|minute|"
    r"minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)|"
    + "|".join(NAMED) + r")\s+(.*)$", re.IGNORECASE | re.DOTALL)
EVERY_RE = re.compile(
    r"\s+every\s+(\d+\s*(?:s|sec|secs|second|seconds|m|min|mins|minute|minutes|"
    r"h|hr|hrs|hour|hours|d|day|days|w|week|weeks)|"
    + "|".join(NAMED) + r")\s*$", re.IGNORECASE | re.DOTALL)
NEXT_MARKER = re.compile(r"<loop-next\b([^>]*?)/?>", re.IGNORECASE)
DONE_MARKER = re.compile(r"<loop-done\b([^>]*?)/?>", re.IGNORECASE)
ATTR = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")


def parse_interval(text: str) -> int | None:
    """Parse `5m`, `2 hours`, `every 3d`, `hourly` into seconds."""
    raw = (text or "").strip().lower()
    if not raw:
        return None
    if raw in NAMED:
        return NAMED[raw]
    match = INTERVAL_RE.match(raw)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2).lower()
    return amount * UNIT_SECONDS.get(unit, 0) or None


def normalize_interval(seconds: int) -> tuple[int, str]:
    """Snap to a clean cadence and describe it. Deterministic."""
    value = max(MIN_INTERVAL, min(int(seconds), MAX_INTERVAL))
    chosen = next((step for step in STEPS_SECONDS if step >= value), MAX_INTERVAL)
    if chosen < 3600:
        return chosen, f"{chosen // 60}m"
    if chosen < 86400:
        return chosen, f"{chosen // 3600}h"
    return chosen, f"{chosen // 86400}d"


def clamp_delay(seconds: int | None) -> int:
    """Self-paced delays live between one minute and one hour."""
    if seconds is None:
        return MAX_DELAY
    return max(MIN_DELAY, min(int(seconds), MAX_DELAY))


def parse_command(text: str, default_task: str = "") -> dict[str, Any]:
    """Parse a `/loop` invocation into mode, interval and task."""
    raw = (text or "").strip()
    lowered = raw.lower()

    # /loop <task> every <interval>
    every = EVERY_RE.search(lowered)
    if every:
        interval = parse_interval(every.group(1))
        task = raw[:every.start()].strip() or default_task
        return _plan("fixed", interval, task)

    # /loop <interval> <task>  |  /loop <interval>  |  /loop <task>
    leading = LEADING_RE.match(raw)
    if leading:
        interval = parse_interval(leading.group(1))
        if interval is not None:
            return _plan("fixed", interval, leading.group(2).strip() or default_task)

    # /loop <interval> — cadence only, task comes from loop.md
    whole = parse_interval(raw)
    if whole is not None:
        return _plan("fixed", whole, default_task)

    return _plan("self-paced", None, raw or default_task)


def _plan(mode: str, interval: int | None, task: str) -> dict[str, Any]:
    task = " ".join((task or "").split())
    if len(task) > MAX_TASK_CHARS:
        task = task[:MAX_TASK_CHARS]
    out: dict[str, Any] = {"mode": mode, "task": task, "interval": interval}
    if mode == "fixed":
        if interval is None:
            out["error"] = "no interval parsed"
        else:
            seconds, label = normalize_interval(interval)
            out["interval"] = seconds
            out["label"] = label
            out["requested"] = interval
    return out


def parse_markers(text: str) -> dict[str, Any]:
    """Read the iteration outcome. Exactly one marker is expected."""
    body = text or ""
    next_match = NEXT_MARKER.search(body)
    done_match = DONE_MARKER.search(body)
    if next_match and done_match:
        return {"action": "conflict",
                "gap": "iteration returned both <loop-next> and <loop-done>"}
    if done_match:
        attrs = dict(ATTR.findall(done_match.group(1) or ""))
        return {"action": "done", "reason": attrs.get("reason", "").strip()}
    if next_match:
        attrs = dict(ATTR.findall(next_match.group(1) or ""))
        raw_delay = attrs.get("delay", "")
        delay = int(raw_delay) if raw_delay.lstrip("-").isdigit() else None
        return {"action": "next", "requested_delay": delay,
                "delay": clamp_delay(delay),
                "reason": attrs.get("reason", "").strip()}
    return {"action": None, "gap": "no <loop-next> or <loop-done> marker"}


def quiet_penalty(quiet_streak: int) -> float:
    """Back off while iterations make no progress: 2^streak, capped at 4x."""
    if quiet_streak <= 0:
        return 1.0
    return min(4.0, 2.0 ** min(quiet_streak, 2))


def next_delay(base: int, marker: dict[str, Any], quiet_streak: int = 0,
               omit_streak: int = 0) -> dict[str, Any]:
    """What happens after one iteration. Returns an action, never a guess."""
    if marker.get("action") == "done":
        return {"action": "stop", "reason": marker.get("reason", "")}
    if marker.get("action") == "conflict":
        return {"action": "stop", "reason": marker.get("gap", "conflicting markers")}
    if marker.get("action") is None:
        # One safety check is allowed; a second omission stops the loop.
        if omit_streak >= 1:
            return {"action": "stop",
                    "reason": "marker omitted twice; refusing to guess"}
        return {"action": "safety_check",
                "delay": 20 * 60,
                "reason": marker.get("gap", "marker omitted")}
    delay = clamp_delay(marker.get("delay") or base)
    delay = int(delay * quiet_penalty(quiet_streak))
    return {"action": "next", "delay": clamp_delay(delay),
            "reason": marker.get("reason", "")}
