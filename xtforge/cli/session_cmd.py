"""CLI handler for session checkpointing (fork and rewind)."""
from __future__ import annotations

from typing import Any
from .common import _out
from ..core import session_checkpoint


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

    return _out(args, {"ok": False, "error": f"unknown session verb: {verb}"}, f"error: unknown session verb {verb}", code=2)
