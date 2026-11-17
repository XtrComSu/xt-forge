"""`xtforge knowledge` — one small surface for agent-contributed knowledge.

Six verbs cover the whole lifecycle: put, get, verify, revise, link, deprecate.
Record categories are a `kind` argument rather than a verb or a tool, so adding
a category never adds a tool schema.
"""

from __future__ import annotations

import json

from .common import _out


def cmd_knowledge(args) -> int:
    from ..core.mem import knowledge as K

    verb = args.knowledge_verb
    db = getattr(args, "db", None)

    def fail(msg: str) -> int:
        return _out(args, {"ok": False, "error": msg}, f"error: {msg}", code=2)

    try:
        if verb == "put":
            res = K.put(
                kind=args.kind or "fact",
                title=args.title or "",
                body=_read_body(args),
                scope=args.scope or "global",
                status=args.status or "proposed",
                project=args.project, target=args.target,
                evidence=args.evidence, author=args.author,
                versions=args.version or [], environment=args.environment,
                tags=args.tag or [], path=db,
            )
            return _out(args, res,
                        f"{res['action']} {res['id']}  {res['kind']}  status={res['status']}")

        if verb == "get":
            rec = K.get(args.id or args.value or "", path=db)
            if rec is None:
                return fail("no such record")
            return _out(args, rec,
                        f"{rec.get('id')}  {rec.get('status')}  {rec.get('title')}")

        if verb == "search":
            res = K.search_all(
                args.query or args.value or "",
                status=args.status, kind=args.kind, project=args.project,
                target=args.target, k=args.k, path=db,
            )
            cur, hist = res["current"], res["historical"]
            human = [f"current: {len(cur)}   historical: {len(hist)}"]
            for r in cur:
                scope = "/".join(x for x in (r.get("project"), r.get("target")) if x)
                human.append(f"  [{r.get('status')}] {r.get('title')}"
                             f"{'  (' + scope + ')' if scope else ''}  {r.get('id')}")
            for r in hist:
                human.append(f"  ({r.get('status')}) {r.get('title')}  {r.get('id')}")
            return _out(args, res, "\n".join(human))

        if verb == "verify":
            res = K.verify(
                args.id or args.value or "",
                method=args.method or "",
                result=args.result or "pass",
                checker=args.checker, exit_status=args.exit_status,
                evidence=args.evidence,
                verified_status="contradicted" if args.contradict else "verified",
                path=db,
            )
            note = "" if res["promoted"] else "  (not promoted: no executed check)"
            return _out(args, res,
                        f"status={res['status']}{note}")

        if verb == "revise":
            res = K.revise(args.id or args.value or "", title=args.title,
                           body=args.body, evidence=args.evidence,
                           status=args.status, author=args.author, path=db)
            return _out(args, res, f"revised {res['id']}  revisions={res['revisions']}")

        if verb == "link":
            res = K.link(args.id or "", args.value or "", relation=args.relation or "relates_to",
                         path=db)
            return _out(args, res,
                        f"{res['action']}: {res['src']} --{res['relation']}--> {res['dst']}")

        if verb == "deprecate":
            res = K.deprecate(args.id or args.value or "", reason=args.reason or "",
                              superseded_by=args.superseded_by, path=db)
            return _out(args, res, f"{res['id']} -> {res['status']}: {res['reason']}")

        return fail(f"unknown verb {verb}")
    except (K.KnowledgeError, ValueError) as exc:
        return fail(str(exc))


def _read_body(args) -> str:
    from .common import _read_file_arg
    if getattr(args, "body_file", None):
        read = _read_file_arg(args, "body_file")
        if read is not None:
            return read
    return args.body or args.value or ""
