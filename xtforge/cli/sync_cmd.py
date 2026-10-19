"""`xtforge sync` — wire xt-forge into the harness (idempotent installer)."""
from __future__ import annotations

from .common import _out

_ACTION_ORDER = {"wrote": 0, "would_write": 1, "skipped": 2, "unchanged": 3}


def cmd_sync(args):
    from ..adapters.sync import build_actions
    res = build_actions(dry_run=getattr(args, "dry_run", False))
    actions = sorted(res.get("actions", []),
                     key=lambda a: (_ACTION_ORDER.get(a.get("action"), 9),
                                    a.get("path", "")))
    lines = []
    for a in actions:
        note = f" ({a['reason']})" if a.get("reason") else ""
        lines.append(f"{a.get('action', '?'):<12} {a.get('path', '')}{note}")
    lines.append("")
    lines.append(f"{res['written']} written, {res['unchanged']} unchanged, "
                 f"{res['would_write']} would write")
    return _out(args, res, "\n".join(lines))
