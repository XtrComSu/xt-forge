"""Durable loop schedule registry (`XT_HOME/loops/schedules.json`) mirroring Go `loopd`."""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any

from ...atomicio import atomic_write_json, read_json
from ...version import xt_home

MAX_TASKS = 50
LIFETIME_SECONDS = 7 * 86400


def schedules_path() -> Path:
    return xt_home() / "loops" / "schedules.json"


def _load() -> list[dict[str, Any]]:
    data = read_json(schedules_path())
    return list(data.get("tasks") or []) if isinstance(data, dict) else []


def _save(tasks: list[dict[str, Any]]) -> None:
    atomic_write_json(schedules_path(), {"tasks": tasks})


def schedule_task(interval: str, cmd: str, *, note: str = "") -> dict[str, Any]:
    if os.environ.get("XT_NATIVE_LOOP") == "0":
        return {"ok": False, "err": "disabled by XT_NATIVE_LOOP=0"}
    from ..route.guard import check_command
    denied = check_command(cmd)
    if denied:
        return {"ok": False, "err": f"denied_command: {denied}"}
    tasks = [t for t in _load() if int(t.get("expires_at", 0)) > time.time()]
    if len(tasks) >= MAX_TASKS:
        return {"ok": False, "err": f"task cap reached ({MAX_TASKS})"}
    now = int(time.time())
    tid = hashlib.sha256(f"{interval}:{cmd}:{now}".encode()).hexdigest()[:10]
    task = {
        "id": tid,
        "interval": interval,
        "cmd": cmd,
        "note": note,
        "created_at": now,
        "expires_at": now + LIFETIME_SECONDS,
        "status": "scheduled",
    }
    tasks.append(task)
    _save(tasks)
    return {"ok": True, "task": task, "engine": "python"}


def list_tasks() -> dict[str, Any]:
    now = int(time.time())
    tasks = [t for t in _load() if int(t.get("expires_at", 0)) > now]
    return {"ok": True, "count": len(tasks), "tasks": tasks, "engine": "python"}


def stop_task(task_id: str) -> dict[str, Any]:
    tasks = _load()
    kept = [t for t in tasks if t.get("id") != task_id]
    _save(kept)
    return {"ok": len(kept) < len(tasks), "stopped": task_id, "engine": "python"}
