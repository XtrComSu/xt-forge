"""Universal-memory CLI handlers."""
from __future__ import annotations

import json

from .common import _out, _store, _read_file_arg


def cmd_mem(args):
    from ..core.mem import export as memexport, search as memsearch
    st = _store(args)
    value = getattr(args, "value", None)
    try:
        if args.mem_verb == "put":
            try:
                from_file = _read_file_arg(args, "body_file")
            except OSError as e:
                return _out(args, {"ok": False, "error": str(e)}, str(e), code=1)
            body = ((from_file if from_file is not None else args.body) or "").strip() \
                or (value or "").strip()
            if not body:
                return _out(args, {"ok": False, "error": "mem put requires --body or --body-file"},
                            "mem put requires --body or --body-file", code=1)
            res = st.put(scope=args.scope, kind=args.kind or "fact", title=args.title or "",
                         body=body, tags=args.tag or [],
                         source=args.source or "cli", confidence=args.confidence)
            return _out(args, res, f"{res['action']} {res['id']}")
        if args.mem_verb == "get":
            rec = st.get(args.id or value)
            return _out(args, rec, json.dumps(rec, indent=2) if rec else "not found")
        if args.mem_verb == "search":
            query = args.query or value
            if not query:
                return _out(args, {"ok": False, "error": "mem search requires a query"},
                            "mem search requires a query", code=1)
            out = memsearch.search(st, query, k=args.k, token_budget=args.budget,
                                   session_id=args.session, workflow_id=args.workflow,
                                   project=args.project, explain=args.explain)
            return _out(args, out, "\n".join(r["line"] for r in out["results"]))
        if args.mem_verb == "list":
            recs = st.list(scope=args.scope, limit=args.k, kind=args.kind)
            return _out(args, recs, "\n".join(f"[{r['id']}] {r['kind']} {r['title']}"
                                              for r in recs))
        if args.mem_verb == "forget":
            ok = st.forget(args.id or value)
            return _out(args, {"forgot": ok}, f"forgot {args.id or value}" if ok
                        else "not found")
        if args.mem_verb == "review":
            return _out(args, {"pending": st.pending(limit=args.k)})
        if args.mem_verb == "purge":
            return _out(args, {"purged": st.purge_expired()})
        if args.mem_verb == "export":
            # argparse shares one --scope default ("global") across mem verbs;
            # for export the default means "all scopes" (matching the MCP
            # mem_export contract) and a comma-separated list selects scopes.
            # Passing the raw string here used to iterate its characters and
            # export zero records.
            scope_arg = (args.scope or "").strip()
            scopes = None if scope_arg in ("", "global") \
                else [s for s in scope_arg.split(",") if s]
            res = memexport.export_jsonl(st, args.path or value, scopes=scopes)
            return _out(args, res, f"exported {res['records']} -> {res['path']}")
        if args.mem_verb == "import":
            return _out(args, memexport.import_jsonl(st, args.path or value))
        if args.mem_verb == "sync":
            return _out(args, memexport.sync(st, args.path or value,
                                             conflict_log=args.conflicts))
    finally:
        st.close()
    return 1
