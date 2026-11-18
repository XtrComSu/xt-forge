"""Safe recoverable tool-call journal shared between Python and Go hub.

Stores call records in `$XT_HOME/checkpoints/call_journal.json` and enforces
three distinct lifecycle states:
  - never_started   : cancelled or failed before wire dispatch (safe to retry)
  - unknown_outcome : written on the wire (`in_flight` on crash or interrupted reply/timeout)
                      NEVER blindly retried; must verify side effect first
  - completed       : committed/reconciled result recorded (replayed idempotently)
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..atomicio import atomic_write_json
from ..version import xt_home

CALL_NEVER_STARTED = "never_started"
CALL_IN_FLIGHT = "in_flight"
CALL_UNKNOWN_OUTCOME = "unknown_outcome"
CALL_COMPLETED = "completed"

_LOCK = threading.Lock()

MUTATING_KEYWORDS = (
    "write", "delete", "remove", "patch", "modify", "update_", "install",
    "uninstall", "run_command", "exec", "sign_in", "sign_out", "rebuild",
    "submit", "create", "commit",
)


def is_mutating_tool_name(name: str) -> bool:
    low = (name or "").lower()
    return any(k in low for k in MUTATING_KEYWORDS)


def journal_path() -> Path:
    return xt_home() / "checkpoints" / "call_journal.json"


def normalize_state(state: str) -> str:
    if state == CALL_IN_FLIGHT:
        return CALL_UNKNOWN_OUTCOME
    return state


def args_digest(server: str, tool: str, args: dict[str, Any] | None = None) -> str:
    payload = json.dumps(args or {}, sort_keys=True, separators=(",", ":"), default=str)
    h = hashlib.sha256(f"{server}:{tool}:{payload}".encode("utf-8")).hexdigest()
    return h[:20]


def result_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:20]


def _load_unlocked() -> dict[str, Any]:
    p = journal_path()
    if not p.is_file():
        return {"version": 1, "entries": {}}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "entries": {}}
    entries = raw.get("entries")
    if not isinstance(entries, dict):
        return {"version": 1, "entries": {}}
    norm_entries: dict[str, dict[str, Any]] = {}
    for cid, entry in entries.items():
        if isinstance(entry, dict):
            cp = dict(entry)
            cp["state"] = normalize_state(str(cp.get("state") or CALL_UNKNOWN_OUTCOME))
            norm_entries[str(cid)] = cp
    return {"version": int(raw.get("version") or 1), "entries": norm_entries}


def _save_unlocked(jf: dict[str, Any]) -> None:
    p = journal_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(p, jf)


def find_by_key(key: str) -> dict[str, Any] | None:
    key = (key or "").strip()
    if not key:
        return None
    with _LOCK:
        jf = _load_unlocked()
        best: dict[str, Any] | None = None
        for entry in jf["entries"].values():
            if entry.get("idempotency_key") == key:
                if best is None or int(entry.get("updated_at") or 0) >= int(best.get("updated_at") or 0):
                    best = dict(entry)
        return best


def get_entry(call_id_or_key: str) -> dict[str, Any] | None:
    target = (call_id_or_key or "").strip()
    if not target:
        return None
    with _LOCK:
        jf = _load_unlocked()
        if target in jf["entries"]:
            return dict(jf["entries"][target])
    return find_by_key(target)


def upsert_entry(entry: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        now = int(time.time())
        rec = dict(entry)
        if not rec.get("call_id"):
            suffix = hashlib.sha256(f"{time.time_ns()}:{rec.get('server')}:{rec.get('tool')}".encode()).hexdigest()[:8]
            rec["call_id"] = f"call_{now}_{suffix}"
        if not rec.get("created_at"):
            rec["created_at"] = now
        rec["updated_at"] = now
        jf = _load_unlocked()
        jf["entries"][rec["call_id"]] = rec
        _save_unlocked(jf)
        return rec


def list_entries(state_filter: str = "") -> list[dict[str, Any]]:
    f = (state_filter or "").strip().lower()
    with _LOCK:
        jf = _load_unlocked()
        items = [dict(v) for v in jf["entries"].values() if not f or v.get("state") == f]
    items.sort(key=lambda e: (int(e.get("updated_at") or 0), str(e.get("call_id") or "")), reverse=True)
    return items


def parse_verification_committed(raw: Any) -> bool:
    """Inspect a read-only verification tool reply to decide whether effect committed."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return bool(raw.strip())
    if not isinstance(raw, dict):
        return bool(raw)
    if raw.get("isError") is True:
        return False

    def _inspect(m: dict[str, Any]) -> bool | None:
        for flag in ("committed", "found", "exists"):
            if isinstance(m.get(flag), bool):
                return bool(m[flag])
        st = m.get("status")
        if isinstance(st, str):
            low = st.strip().lower()
            if low in ("not_found", "missing", "absent", "unknown", "never_started"):
                return False
            if low in ("committed", "completed", "ok", "succeeded", "success"):
                return True
        if m.get("receipt") is not None:
            return True
        return None

    verdict = _inspect(raw)
    if verdict is not None:
        return verdict
    for item in raw.get("content") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            try:
                inner = json.loads(item["text"])
            except json.JSONDecodeError:
                continue
            if isinstance(inner, dict):
                v = _inspect(inner)
                if v is not None:
                    return v
    return True


def begin_call(
    server: str,
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    idempotency_key: str = "",
    verify_tool: str = "",
    verify_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Check recovery journal before starting a state-changing call."""
    key = (idempotency_key or "").strip()
    digest = args_digest(server, tool, args)
    if key:
        existing = find_by_key(key)
        if existing is not None:
            if existing.get("args_sha256") and existing["args_sha256"] != digest:
                return {"ok": False, "action": "conflict", "entry": existing,
                        "err": f"idempotency conflict for key {key!r}"}
            st = normalize_state(str(existing.get("state") or CALL_UNKNOWN_OUTCOME))
            if st == CALL_COMPLETED and not existing.get("is_error"):
                return {"ok": True, "action": "replay", "entry": existing}
            if st == CALL_UNKNOWN_OUTCOME:
                return {"ok": False, "action": "verify_required", "duplicate_prevented": True, "entry": existing}
            # never_started -> safe to start cleanly
            existing["state"] = CALL_IN_FLIGHT
            existing["attempts"] = int(existing.get("attempts") or 0) + 1
            if verify_tool:
                existing["verify_tool"] = verify_tool
            if verify_args is not None:
                existing["verify_args"] = verify_args
            return {"ok": True, "action": "proceed", "entry": upsert_entry(existing)}
    rec = upsert_entry({
        "idempotency_key": key,
        "server": server,
        "tool": tool,
        "args_sha256": digest,
        "state": CALL_IN_FLIGHT,
        "attempts": 1,
        "verify_tool": verify_tool,
        "verify_args": verify_args or ({} if not key else {"idempotency_key": key}),
    })
    return {"ok": True, "action": "proceed", "entry": rec}


def resolve_call(
    call_id_or_key: str,
    *,
    outcome: str = CALL_COMPLETED,
    result: Any = None,
    error: str = "",
    cancelled: bool = False,
    cancel_notified: bool = False,
) -> dict[str, Any]:
    entry = get_entry(call_id_or_key)
    if entry is None:
        return {"ok": False, "err": f"unknown call_id or idempotency_key: {call_id_or_key}"}
    if outcome not in (CALL_NEVER_STARTED, CALL_UNKNOWN_OUTCOME, CALL_COMPLETED):
        return {"ok": False, "err": f"invalid outcome state: {outcome}"}
    entry["state"] = outcome
    entry["cancelled"] = bool(cancelled or entry.get("cancelled"))
    entry["cancel_notified"] = bool(cancel_notified or entry.get("cancel_notified"))
    entry["is_error"] = bool(error) or outcome != CALL_COMPLETED
    entry["error"] = error
    if result is not None:
        serialized = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        entry["result"] = serialized
        entry["result_sha256"] = result_digest(serialized)
    saved = upsert_entry(entry)
    return {"ok": True, "entry": saved}


def run_recoverable_upstream_call(
    sess: Any,
    server: str,
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    idempotency_key: str = "",
    verify_tool: str = "",
    verify_args: dict[str, Any] | None = None,
    cancel_event: threading.Event | None = None,
    clip_fn: Callable[[Any], Any] | None = None,
) -> tuple[Any, bool]:
    """Execute an upstream MCP call with safe interruption/recovery semantics."""
    args = dict(args or {})
    if os.environ.get("XT_PERM_MODE", "").lower() == "explore" and is_mutating_tool_name(tool_name):
        return {"ok": False, "err": f"denied: XT_PERM_MODE=explore forbids mutating call {server}:{tool_name}"}, True

    key = (idempotency_key or "").strip()
    digest = args_digest(server, tool_name, args)
    entry: dict[str, Any] | None = None

    if key:
        existing = find_by_key(key)
        if existing is not None:
            state = normalize_state(str(existing.get("state") or CALL_UNKNOWN_OUTCOME))
            if existing.get("args_sha256") and existing["args_sha256"] != digest:
                return {"ok": False, "err": f"idempotency conflict for key {key!r}"}, True
            if state == CALL_COMPLETED and not existing.get("is_error"):
                raw_res = existing.get("result", "")
                try:
                    parsed = json.loads(raw_res) if isinstance(raw_res, str) and raw_res else raw_res
                except json.JSONDecodeError:
                    parsed = raw_res
                return (clip_fn(parsed) if clip_fn else parsed), False
            if state == CALL_UNKNOWN_OUTCOME:
                vtool = (verify_tool or existing.get("verify_tool") or "").strip()
                vargs = verify_args if verify_args is not None else (existing.get("verify_args") or {"idempotency_key": key})
                if not vtool:
                    return {
                        "ok": False,
                        "state": CALL_UNKNOWN_OUTCOME,
                        "call_id": existing.get("call_id"),
                        "idempotency_key": key,
                        "attempts": existing.get("attempts", 1),
                        "cancel_notified": bool(existing.get("cancel_notified")),
                        "duplicate_prevented": True,
                        "message": (
                            f"call {existing.get('call_id')} ({server}:{tool_name}) has unknown_outcome; "
                            "verify side effect via read-only lookup or pass verify_tool before retrying"
                        ),
                    }, True
                v_res, v_err, _, _, _ = sess.call_tool_detailed(vtool, vargs, cancel_event=cancel_event)
                if v_err:
                    return {
                        "ok": False,
                        "state": CALL_UNKNOWN_OUTCOME,
                        "duplicate_prevented": True,
                        "err": f"verification {server}:{vtool} failed: {v_res}",
                    }, True
                if parse_verification_committed(v_res):
                    serialized = json.dumps(v_res, ensure_ascii=False, default=str) if not isinstance(v_res, str) else v_res
                    existing["state"] = CALL_COMPLETED
                    existing["is_error"] = False
                    existing["error"] = ""
                    existing["result"] = serialized
                    existing["result_sha256"] = result_digest(serialized)
                    upsert_entry(existing)
                    payload = {
                        "ok": True,
                        "recovered": True,
                        "duplicate_prevented": True,
                        "state": CALL_COMPLETED,
                        "call_id": existing.get("call_id"),
                        "idempotency_key": key,
                        "attempts": existing.get("attempts", 1),
                        "verify_tool": vtool,
                        "receipt": v_res,
                    }
                    return (clip_fn(payload) if clip_fn else payload), False
                entry = existing
            else:
                entry = existing

    if cancel_event is not None and cancel_event.is_set():
        rec = dict(entry or {
            "idempotency_key": key, "server": server, "tool": tool_name,
            "args_sha256": digest, "verify_tool": verify_tool, "verify_args": verify_args or {},
        })
        rec["state"] = CALL_NEVER_STARTED
        rec["cancelled"] = True
        rec["is_error"] = True
        rec["error"] = "cancelled before dispatch"
        rec = upsert_entry(rec)
        return {"ok": False, "state": CALL_NEVER_STARTED, "call_id": rec["call_id"],
                "err": f"cancelled before start ({CALL_NEVER_STARTED})"}, True

    track = bool(key or is_mutating_tool_name(tool_name))
    if track:
        rec = dict(entry or {
            "idempotency_key": key, "server": server, "tool": tool_name,
            "args_sha256": digest, "verify_tool": verify_tool, "verify_args": verify_args or {},
        })
        rec["state"] = CALL_IN_FLIGHT
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        rec["is_error"] = False
        rec["error"] = ""
        if verify_tool:
            rec["verify_tool"] = verify_tool
        if verify_args is not None:
            rec["verify_args"] = verify_args
        entry = upsert_entry(rec)

    res, is_err, req_id, started, cancel_notified = sess.call_tool_detailed(
        tool_name, args, cancel_event=cancel_event,
    )
    if is_err:
        if track or not started or cancel_notified:
            rec = dict(entry or {
                "idempotency_key": key, "server": server, "tool": tool_name,
                "args_sha256": digest, "attempts": 1, "verify_tool": verify_tool, "verify_args": verify_args or {},
            })
            rec["request_id"] = req_id
            rec["cancel_notified"] = bool(rec.get("cancel_notified") or cancel_notified)
            rec["is_error"] = True
            rec["error"] = str(res)
            if not started:
                rec["state"] = CALL_NEVER_STARTED
                rec["cancelled"] = True
            elif cancel_notified or isinstance(res, str) and (
                "timeout" in res.lower() or "eof" in res.lower() or "cancelled" in res.lower()
            ):
                rec["state"] = CALL_UNKNOWN_OUTCOME
                if cancel_notified:
                    rec["cancelled"] = True
            else:
                rec["state"] = CALL_UNKNOWN_OUTCOME if is_mutating_tool_name(tool_name) else CALL_COMPLETED
            entry = upsert_entry(rec)
        if not started:
            return {"ok": False, "state": CALL_NEVER_STARTED, "call_id": (entry or {}).get("call_id"),
                    "err": f"cancelled before dispatch ({CALL_NEVER_STARTED}): {res}"}, True
        if (entry or {}).get("state") == CALL_UNKNOWN_OUTCOME:
            return {"ok": False, "state": CALL_UNKNOWN_OUTCOME, "call_id": (entry or {}).get("call_id"),
                    "cancel_notified": cancel_notified,
                    "err": f"interrupted call with unknown_outcome (cancel_notified={cancel_notified}): {res}"}, True
        return res, True

    if track and entry is not None:
        serialized = json.dumps(res, ensure_ascii=False, default=str) if not isinstance(res, str) else res
        entry["request_id"] = req_id
        entry["state"] = CALL_COMPLETED
        entry["is_error"] = False
        entry["error"] = ""
        entry["result"] = serialized
        entry["result_sha256"] = result_digest(serialized)
        upsert_entry(entry)
    return (clip_fn(res) if clip_fn else res), False
