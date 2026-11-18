"""CLI handler for session checkpointing (fork and rewind)."""
from __future__ import annotations

from typing import Any
from .common import _out
from ..core import call_journal, session_checkpoint


def cmd_session(args) -> int:
    verb = getattr(args, "session_verb", "list")

    if verb in ("fork", "snapshot", "save"):
        name = getattr(args, "name", None) or getattr(args, "target", None)
        res = session_checkpoint.create_checkpoint(name=name)
        human = f"Created checkpoint {res.get('id')} ({res.get('name')}) with items: {', '.join(res.get('items', []))}"
        return _out(args, res, human)

    elif verb in ("rewind", "restore"):
        cp_id = getattr(args, "target", None) or getattr(args, "name", None)
        if not cp_id:
            return _out(args, {"ok": False, "error": "rewind requires a checkpoint ID"}, "error: rewind requires a checkpoint ID", code=2)
        res = session_checkpoint.restore_checkpoint(cp_id)
        if not res.get("ok"):
            return _out(args, res, f"error: {res.get('err')}", code=1)
        human = f"Rewound state to checkpoint {res.get('id')} ({res.get('name')}). Restored: {', '.join(res.get('restored_items', []))}"
        return _out(args, res, human)

    elif verb in ("list", "ls"):
        cps = session_checkpoint.list_checkpoints()
        data = {"ok": True, "checkpoints": cps, "count": len(cps)}
        if not cps:
            human = "(no checkpoints saved)"
        else:
            lines = [f"{len(cps)} checkpoints saved:"]
            for cp in cps:
                lines.append(f"  {cp.get('id'):<24} {cp.get('created_at', '')}  {cp.get('name', '')}")
            human = "\n".join(lines)
        return _out(args, data, human)

    elif verb in ("delete", "rm"):
        cp_id = getattr(args, "target", None) or getattr(args, "name", None)
        if not cp_id:
            return _out(args, {"ok": False, "error": "delete requires a checkpoint ID"}, "error: delete requires a checkpoint ID", code=2)
        res = session_checkpoint.delete_checkpoint(cp_id)
        if not res.get("ok"):
            return _out(args, res, f"error: {res.get('err')}", code=1)
        human = f"Deleted checkpoint {cp_id}"
        return _out(args, res, human)

    elif verb == "journal":
        state = getattr(args, "state", None) or ""
        key = getattr(args, "key", None) or getattr(args, "target", None)
        if key:
            entry = call_journal.get_entry(key)
            return _out(
                args,
                {"ok": True, "journal_path": str(call_journal.journal_path()), "found": entry is not None, "entry": entry},
                f"{key}: {entry['state'] if entry else 'not found'}",
            )
        entries = call_journal.list_entries(state)
        lines = [f"{len(entries)} journal entries:"]
        for e in entries[:25]:
            lines.append(f"  {e.get('call_id'):<22} {e.get('state'):<16} {e.get('server')}:{e.get('tool')} key={e.get('idempotency_key') or '-'}")
        return _out(args, {"ok": True, "journal_path": str(call_journal.journal_path()), "count": len(entries), "entries": entries}, "\n".join(lines))

    elif verb == "recover":
        unresolved = call_journal.list_entries(call_journal.CALL_UNKNOWN_OUTCOME)
        never_started = call_journal.list_entries(call_journal.CALL_NEVER_STARTED)
        res = {
            "ok": True,
            "journal_path": str(call_journal.journal_path()),
            "unknown_outcome_count": len(unresolved),
            "never_started_count": len(never_started),
            "unknown_outcome": unresolved,
            "never_started": never_started,
        }
        return _out(args, res, f"recover: {len(unresolved)} unknown_outcome (verify before retry), {len(never_started)} never_started (safe to retry)")

    elif verb == "begin-call":
        key = getattr(args, "key", None) or getattr(args, "target", None) or ""
        srv = getattr(args, "server", None) or ""
        tool = getattr(args, "tool", None) or ""
        vtool = getattr(args, "verify_tool", None) or ""
        res = call_journal.begin_call(srv, tool, idempotency_key=key, verify_tool=vtool)
        code = 0 if res.get("ok") else 1
        return _out(args, res, f"begin-call: action={res.get('action')}", code=code)

    elif verb == "resolve-call":
        target = getattr(args, "target", None) or getattr(args, "key", None) or ""
        outcome = getattr(args, "state", None) or call_journal.CALL_COMPLETED
        res = call_journal.resolve_call(target, outcome=outcome)
        return _out(args, res, f"resolved {target} -> {outcome}", code=0 if res.get("ok") else 1)

    return _out(args, {"ok": False, "error": f"unknown session verb: {verb}"}, f"error: unknown session verb {verb}", code=2)
