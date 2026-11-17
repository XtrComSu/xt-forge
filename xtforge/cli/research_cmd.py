"""`xtforge research`: unified parallel dossier fan-out across memory, code, and intel."""
from __future__ import annotations

from .common import _out


def cmd_research(args):
    from ..core import research as rmod
    topic = (args.topic or args.query or "").strip()
    if not topic:
        return _out(args, {"ok": False, "err": "research requires a topic"},
                    "error: research requires a topic", code=2)
    res = rmod.run_research(
        topic,
        root=getattr(args, "path", None) or ".",
        k=int(getattr(args, "k", 5) or 5),
        save_dossier=bool(getattr(args, "save", False)),
    )
    return _out(args, res, res.get("dossier", ""), code=0 if res.get("ok") else 1)
