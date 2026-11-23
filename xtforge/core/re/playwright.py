"""Playwright trace archives.

WHY: a Playwright trace is what a browser-automation test leaves behind when it fails,
and it is the only artifact that answers "what did the page actually do". It is a zip
of newline-delimited JSON events, not a media file — so `re asar` and `re netcap`
cannot read it, and it looks like an opaque blob.

The shape, from a real trace produced by Playwright's own `tracing.start()`:

    trace.trace     one JSON object per line: context-options (header), before/after
                    (action bookends), log (console and errors), input, event,
                    frame-snapshot (DOM snapshots for the timeline)
    trace.network   JSONL of network requests and their responses
    trace.stacks    optional JS stack frames for action call sites
    *.jpeg / *.png  optional screenshots, named after the sha1 of their content

So the reader is a JSONL reader plus an event classifier. What makes it useful is not
dumping the lines but answering: which actions ran, in what order, what failed, what
console output appeared, and which requests were made.

Three things to get right:

  * The events are **newline-delimited, not a JSON array**. `json.load` on the whole
    file fails on a perfectly valid trace; it has to be split by line and parsed one at
    a time, and a partial final line (a trace cut off mid-write) must not kill the read.
  * Timings are **offsets in milliseconds from trace start**, not wall-clock. Rendering
    them as dates invents timestamps that never existed.
  * `after` events carry errors only when the action failed, and the key is `error`
    with a nested `message` — a missing key is the success case, not missing data.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_LINES = 500000

# Trace members that carry events, in the order worth reporting.
_TRACE_MEMBERS = ("trace.trace", "trace.network", "trace.stacks")
_SNAPSHOT_SUFFIXES = (".jpeg", ".jpg", ".png", ".webp")
_MAX_ERROR_CHARS = 400


def _read(path: str | Path) -> Path:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"file too large: {size} bytes (max {MAX_BYTES})")
    return canon


def _jsonl(text: str, limit: int = MAX_LINES) -> tuple[list[dict], int]:
    """Parse newline-delimited JSON, returning (events, unparsed_line_count).

    A trace is JSONL, not a JSON array. Parsing the whole file as one document fails on
    valid input, and a trace cut off mid-write leaves a partial last line that must be
    dropped rather than raised.
    """
    events: list[dict] = []
    bad = 0
    for index, line in enumerate(text.splitlines()):
        if index >= limit:
            break
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(record, dict):
            events.append(record)
        else:
            bad += 1
    return events, bad


def _action(record: dict) -> dict[str, Any] | None:
    """Turn a before/after pair into a single action row."""
    method = record.get("method")
    if not method:
        return None
    row: dict[str, Any] = {
        "call_id": record.get("callId"),
        "class": record.get("class"),
        "method": method,
        "api": f"{record.get('class') or '?'}.{method}",
    }
    params = record.get("params") or {}
    for key in ("url", "selector", "expression", "name", "pageId"):
        if key in params:
            row[key] = params[key]
    return row


def inspect_playwright_trace(path: str | Path, *, limit: int = 200) -> dict[str, Any]:
    """Summarise a Playwright trace: actions, failures, console output, requests."""
    try:
        canon = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if not zipfile.is_zipfile(canon):
        return {"ok": False, "path": str(canon),
                "error": "not a zip archive (a Playwright trace is a zip)"}

    try:
        archive = zipfile.ZipFile(canon, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        return {"ok": False, "path": str(canon), "error": f"unreadable zip: {exc}"}

    with archive:
        names = archive.namelist()
        trace_members = [name for name in names if name in _TRACE_MEMBERS]
        if "trace.trace" not in names:
            return {"ok": False, "path": str(canon),
                    "error": "no trace.trace member (not a Playwright trace)",
                    "members": names[:40]}

        try:
            raw = archive.read("trace.trace")
        except (zipfile.BadZipFile, OSError) as exc:
            return {"ok": False, "path": str(canon),
                    "error": f"cannot read trace.trace: {exc}"}
        events, unparsed = _jsonl(raw.decode("utf-8", "replace"))

        header: dict[str, Any] = {}
        actions: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        failures: list[dict[str, Any]] = []
        logs: list[dict[str, Any]] = []
        kinds: dict[str, int] = {}
        snapshot_count = 0
        last_time = 0.0

        for record in events:
            kind = record.get("type") or "unknown"
            kinds[kind] = kinds.get(kind, 0) + 1
            for key in ("startTime", "time"):
                value = record.get(key)
                if isinstance(value, (int, float)) and value > last_time:
                    last_time = float(value)
            if kind == "context-options":
                header = {
                    "version": record.get("version"),
                    "origin": record.get("origin"),
                    "browser": record.get("browserName"),
                    "platform": record.get("platform"),
                    "title": record.get("title"),
                }
            elif kind == "frame-snapshot":
                snapshot_count += 1
            elif kind == "before":
                action = _action(record)
                if action:
                    action["start_ms"] = record.get("startTime")
                    actions[action["call_id"]] = action
                    order.append(action["call_id"])
            elif kind == "after":
                call_id = record.get("callId")
                action = actions.get(call_id or "")
                end = record.get("endTime")
                if action is not None:
                    action["end_ms"] = end
                    if isinstance(action.get("start_ms"), (int, float)) \
                            and isinstance(end, (int, float)):
                        action["duration_ms"] = round(end - action["start_ms"], 3)
                error = record.get("error")
                if error:
                    message = error.get("message") if isinstance(error, dict) else error
                    failures.append({
                        "api": (action or {}).get("api") or record.get("method"),
                        "call_id": call_id,
                        "message": str(message or "")[:_MAX_ERROR_CHARS],
                    })
            elif kind == "log":
                logs.append({"level": record.get("level"),
                             "message": str(record.get("message") or "")[:300]})

        # Network member: JSONL of request/response events.
        network: list[dict[str, Any]] = []
        network_bad = 0
        if "trace.network" in names:
            try:
                network_text = archive.read("trace.network").decode("utf-8", "replace")
                network_events, network_bad = _jsonl(network_text)
            except (zipfile.BadZipFile, OSError):
                network_events = []
            requests: dict[str, dict[str, Any]] = {}
            for record in network_events:
                snapshot = record.get("snapshot") or {}
                request = snapshot.get("request") or {}
                if not request:
                    continue
                key = request.get("url") or ""
                if not key:
                    continue
                entry = requests.setdefault(key, {
                    "url": key, "method": request.get("method"),
                    "status": None, "resource_type": snapshot.get("resourceType"),
                })
                response = snapshot.get("response") or {}
                if response.get("status"):
                    entry["status"] = response["status"]
            network = list(requests.values())

        screenshots = [name for name in names
                       if name.lower().endswith(_SNAPSHOT_SUFFIXES)]

    return {
        "ok": True,
        "path": str(canon),
        "kind": "playwright-trace",
        "version": header.get("version"),
        "browser": header.get("browser"),
        "origin": header.get("origin"),
        "title": header.get("title"),
        "members": names[:60],
        "member_count": len(names),
        "event_count": len(events),
        "unparsed_lines": unparsed,
        "event_kinds": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
        "trace_members_present": trace_members,
        "duration_ms": round(last_time, 3) if last_time else None,
        "actions": [actions[call_id] for call_id in order][:limit],
        "action_count": len(order),
        "failures": failures[:limit],
        "failure_count": len(failures),
        "console": logs[:limit],
        "console_count": len(logs),
        "network": network[:limit],
        "network_count": len(network),
        "network_unparsed_lines": network_bad,
        "snapshot_count": snapshot_count,
        "screenshots": screenshots[:60],
        "screenshot_count": len(screenshots),
    }


def inspect(path: str | Path) -> dict[str, Any]:
    return inspect_playwright_trace(path)
