"""`xtforge docs` — live library documentation, without an MCP schema.

Two MCP tools would sit in the model's context on every step. One verb costs
nothing until it is called.
"""
from __future__ import annotations

from .common import _out


def cmd_docs(args):
    from ..core import docs as docsmod
    verb = args.docs_verb
    value = (args.value or "").strip()

    try:
        if verb == "search":
            payload = docsmod.search(value, limit=args.limit or 8)
            human = "\n".join(
                f"{r.get('title', '?'):<28} {r.get('project', '')}"
                for r in payload.get("results", [])) or "(no libraries matched)"
            return _out(args, payload, human,
                        code=0 if payload.get("ok") else 1)

        if verb == "resolve":
            payload = docsmod.resolve(value)
            if payload.get("ok"):
                human = (f"{payload.get('title')} -> {payload.get('project')}\n"
                         + "\n".join(f"  also: {a['project']}"
                                     for a in payload.get("alternatives", [])))
            else:
                human = f"error: {payload.get('err')}"
            return _out(args, payload, human,
                        code=0 if payload.get("ok") else 1)

        if verb == "show":
            payload = docsmod.show(value, topic=getattr(args, "topic", None),
                                   tokens=args.limit or 4000,
                                   language=getattr(args, "language", None))
            if payload.get("ok"):
                return _out(args, payload, payload["docs"])
            return _out(args, payload,
                        f"error: {payload.get('err', 'fetch failed')}", code=1)

    except (ValueError, OSError) as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)
