"""Loop scheduling policy: caps, lifetime, jitter, kill switch.

The harness runs the timers; this decides whether a timer may exist at all.
Every safety property from the design lives here so it is testable and cannot
be forgotten at a call site:

- at most 50 scheduled tasks per conversation
- a seven-day lifetime for fixed loops
- deterministic jitter so many sessions do not fire together
- one self-paced loop per conversation
- `XT_NATIVE_LOOP=0` kills every loop at load

Task text is data. It is never interpreted as instructions here.
"""
from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

MAX_TASKS = 50
LIFETIME_SECONDS = 7 * 86400
JITTER_RATIO = 0.10
JITTER_CAP = 15 * 60
KILL_SWITCH = "XT_NATIVE_LOOP"


@dataclass
class Schedule:
    id: str
    session_id: str
    task: str
    mode: str                     # "fixed" | "self-paced"
    interval: int | None = None
    label: str = ""
    created: int = 0
    expires: int = 0
    last_run: int = 0
    runs: int = 0
    quiet_streak: int = 0
    omit_streak: int = 0
    paused: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Schedule":
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


def disabled() -> bool:
    """The kill switch: any value other than '0' leaves loops enabled."""
    return os.environ.get(KILL_SWITCH, "1") == "0"


def jitter(schedule_id: str, run: int, interval: int) -> int:
    """Deterministic jitter: same schedule, same fire time, everywhere."""
    spread = min(JITTER_CAP, int(interval * JITTER_RATIO))
    if spread <= 0:
        return 0
    raw = sum((index + 1) * ord(ch)
              for index, ch in enumerate(f"{schedule_id}:{run}")) % (2 * spread + 1)
    return raw - spread


def new_id(session_id: str, task: str, now: int) -> str:
    import hashlib
    raw = f"{session_id}|{task}|{now}".encode("utf-8")
    return "loop-" + hashlib.sha256(raw).hexdigest()[:10]


def create(task: str, mode: str, interval: int | None = None, *,
           session_id: str = "default", now: int | None = None,
           label: str = "") -> Schedule:
    ts = int(now if now is not None else time.time())
    return Schedule(
        id=new_id(session_id, task, ts), session_id=session_id, task=task,
        mode=mode, interval=interval, label=label, created=ts,
        expires=ts + LIFETIME_SECONDS)


def is_alive(schedule: Schedule, now: int | None = None) -> bool:
    ts = int(now if now is not None else time.time())
    return (not schedule.paused) and ts <= schedule.expires


def enforce(schedules: Iterable[Schedule], *, session_id: str,
            now: int | None = None) -> dict[str, Any]:
    """Apply the caps. Returns what to keep and why anything was dropped."""
    ts = int(now if now is not None else time.time())
    kept: list[Schedule] = []
    dropped: list[dict[str, str]] = []
    self_paced_seen = False

    for schedule in schedules:
        if schedule.expires <= ts:
            dropped.append({"id": schedule.id, "reason": "lifetime exceeded"})
            continue
        if schedule.session_id != session_id:
            kept.append(schedule)          # other conversations keep their own
            continue
        if schedule.mode == "self-paced":
            if self_paced_seen:
                dropped.append({"id": schedule.id,
                                "reason": "one self-paced loop per conversation"})
                continue
            self_paced_seen = True
        kept.append(schedule)

    mine = [s for s in kept if s.session_id == session_id]
    if len(mine) > MAX_TASKS:
        overflow = sorted(mine, key=lambda s: s.created)[:-MAX_TASKS]
        drop_ids = {s.id for s in overflow}
        kept = [s for s in kept if s.id not in drop_ids]
        dropped.extend({"id": s.id, "reason": "task cap reached"} for s in overflow)
    return {"kept": kept, "dropped": dropped,
            "active": len([s for s in kept if s.session_id == session_id])}
