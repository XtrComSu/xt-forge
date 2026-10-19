"""Flash-memory CLI handlers (the /m* product surface)."""
from __future__ import annotations

from .common import _out, _flash, _read_file_arg


def cmd_flash(args):
    f = _flash(args)
    verb = args.flash_verb
    if verb == "set":
        # --text-file / '-' keeps long or quoted notes out of the shell, which
        # is where an inline argument silently gets word-split and truncated.
        try:
            from_file = _read_file_arg(args, "text_file")
        except OSError as e:
            return _out(args, {"ok": False, "err": str(e)}, str(e), code=2)
        if from_file is not None:
            args.text = from_file
        if not (args.text or "").strip():
            # an empty /m used to store a hash-keyed blank note (silent garbage)
            return _out(args, {"ok": False, "err": "flash set requires text"},
                        'flash set requires text (usage: xtforge flash set "note #tag")',
                        code=2)
        key, val = None, args.text
        if args.text and "=" in args.text and not args.text.startswith("#"):
            key, val = args.text.split("=", 1)
        rec = f.set(val or args.text, key=key, scope=args.scope,
                    tags=args.tag or [], ttl_s=args.ttl, src="cli")
        return _out(args, rec, f"[{rec['id']}] {rec['k']} = {rec['v']}")
    if verb == "get":
        k = args.key or args.text
        rec = f.get(k, args.scope) if k else None
        if not rec and k:
            hits = f.find(k, args.scope, top=3)
            rec = hits[0] if hits else None
        return _out(args, rec, f"{rec['k']} = {rec['v']}" if rec else "not found")
    if verb == "list":
        n = args.n
        if n is None and (args.text or "").strip().isdigit():
            n = int(args.text.strip())
        recs = f.list(args.scope, n=n or 10, pin_only=bool(args.pin_only))
        return _out(args, recs, "\n".join(f"{r['id']} {r['k']}: {r['v'][:60]}"
                                          for r in recs))
    if verb == "pin":
        rec = f.pin(args.key or args.text, args.scope)
        return _out(args, rec, f"pin={rec['pin']}" if rec else "not found")
    if verb == "delete":
        if args.all:
            from ..core.route import guard
            if not args.confirm:
                tok = guard.issue_token("clear_scope", args.scope)
                return _out(args, tok,
                            f"pass --confirm {tok['confirm_token']} to clear {args.scope}")
            guard.write_guard(f"flash:{args.scope}", write=True,
                              confirm_token=args.confirm)
            n = f.clear(args.scope)
            return _out(args, {"cleared": n}, f"cleared {n}")
        ok = f.delete(args.key or args.text, args.scope)
        return _out(args, {"deleted": ok}, "deleted" if ok else "not found")
    if verb == "compact":
        return _out(args, f.compact(args.scope), "compacted")
    if verb == "stats":
        return _out(args, f.stats(args.scope))
    return 1
