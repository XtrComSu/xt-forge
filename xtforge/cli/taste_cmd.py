"""`xtforge taste` — deterministic preference learning (CLI).

Every verb is `--json`-clean and shares its result shape with the `taste_*`
MCP tools. Writes go to the taste store only; nothing here touches project
files.
"""
from __future__ import annotations

import json

from .common import _out, _read_file_arg


def _store(args):
    from ..core.taste.store import TasteStore
    from ..version import taste_db_path
    return TasteStore(getattr(args, "taste_db", None) or taste_db_path())


def _human_learning(item: dict) -> str:
    arrow = "prefer" if item.get("polarity", 1) >= 0 else "avoid"
    return (f"{item['id']}  {item['status']:<9} {item['confidence']:.2f} "
            f"{item['category']:<12} [{arrow}] {item['statement']}")


def cmd_taste(args):
    verb = getattr(args, "taste_verb", None)
    value = getattr(args, "value", None)
    scope = getattr(args, "scope", None) or "global"
    limit = getattr(args, "limit", None) or getattr(args, "k", 20)
    store = _store(args)
    try:
        if verb == "learn":
            try:
                body = _read_file_arg(args, "body_file")
            except OSError as exc:
                return _out(args, {"ok": False, "error": str(exc)}, str(exc), code=1)
            statement = (body or args.body or value or "").strip()
            if not statement:
                return _out(args, {"ok": False,
                                   "error": "taste learn needs a statement"},
                            "error: taste learn needs a statement", code=2)
            delta = store.learn(statement, scope=scope,
                                source=getattr(args, "source", None) or "manual")
            after = delta["after"]
            human = (f"{delta['id']}  {after['status']:<9} "
                     f"{after['confidence']:.2f} {delta['category']:<12} "
                     f"{delta['statement']}\n"
                     f"  confidence {delta['before']['confidence']} -> "
                     f"{after['confidence']} ({after['status']})")
            return _out(args, delta, human)

        if verb == "ingest":
            try:
                text = _read_file_arg(args, "body_file")
            except OSError as exc:
                return _out(args, {"ok": False, "error": str(exc)}, str(exc), code=1)
            raw = text if text is not None else (args.body or value or "")
            if not raw.strip():
                return _out(args, {"ok": False,
                                   "error": "taste ingest needs text (--body-file -)"},
                            "error: taste ingest needs text", code=2)
            from ..core.taste import extract
            signals = extract(raw, source=getattr(args, "source", None) or "ingest",
                              scope=scope)
            deltas = store.ingest(signals, scope=scope)
            payload = {"ingested": len(deltas), "deltas": deltas}
            human = "\n".join(_human_learning({
                "id": d["id"], "status": d["after"]["status"],
                "confidence": d["after"]["confidence"],
                "category": d["category"], "polarity": d["after"]["polarity"],
                "statement": d["statement"]}) for d in deltas) \
                or "(no explicit preferences found)"
            return _out(args, payload, human)

        if verb == "search":
            rows = store.search(query=value or "", scope=scope if scope != "global" else None,
                                category=getattr(args, "category", None),
                                status=getattr(args, "status", None),
                                limit=limit)
            return _out(args, rows,
                        "\n".join(_human_learning(row) for row in rows)
                        or "(no learnings)")

        if verb == "show":
            rec_id = args.id or value
            if not rec_id:
                return _out(args, {"ok": False, "error": "taste show needs --id"},
                            "error: taste show needs --id", code=2)
            item = store.get(rec_id)
            if item is None:
                return _out(args, {"ok": False, "error": f"unknown learning: {rec_id}"},
                            f"error: unknown learning {rec_id}", code=1)
            item["evidence_log"] = store.evidence(rec_id)
            human = "\n".join([
                _human_learning(item),
                f"  key:        {item['key']}",
                f"  alpha/beta: {item['alpha']} / {item['beta']}",
                f"  evidence:   {item['evidence']} signals",
                "  log:",
            ] + [f"    {e['created']} [{e['kind']} w={e['weight']} "
                 f"{'+' if e['polarity'] >= 0 else '-'}] {e['quote'][:70]}"
                 for e in item["evidence_log"]])
            return _out(args, item, human)

        if verb == "review":
            payload = store.review(limit=limit)
            human = []
            for label, key in (("conflicts", "conflicts"), ("hints", "hints"),
                               ("weak", "weak")):
                items = payload[key]
                if items:
                    human.append(f"{label} ({len(items)})")
                    human.extend(f"  {_human_learning(item)}"
                                 for item in items)
            return _out(args, payload,
                        "\n".join(human) or "(nothing needs review)")

        if verb == "forget":
            rec_id = args.id or value
            if not rec_id:
                return _out(args, {"ok": False, "error": "taste forget needs --id"},
                            "error: taste forget needs --id", code=2)
            ok = store.forget(rec_id)
            return _out(args, {"id": rec_id, "retired": ok},
                        f"retired {rec_id}" if ok else "not found")

        if verb == "prune":
            # Tidy the profile: retire the keys the current rules would no
            # longer invent. Read-only unless --apply.
            candidates = store.prunable(limit=limit)
            applied = False
            if getattr(args, "apply", False):
                for item in candidates:
                    store.forget(item["id"])
                applied = True
            payload = {
                "candidates": candidates,
                "count": len(candidates),
                "applied": applied,
                "retired": [item["id"] for item in candidates] if applied else [],
            }
            human = "\n".join(
                f"  {item['id']}  {item['category']:<12} {item['statement'][:60]}"
                for item in candidates) or "(nothing to prune)"
            if applied:
                human = f"retired {len(candidates)}\n" + human
            else:
                human = (f"{len(candidates)} prunable "
                         "(re-run with --apply)\n" + human)
            return _out(args, payload, human)

        if verb == "export":
            root = args.path or value
            if not root:
                return _out(args, {"ok": False,
                                   "error": "taste export needs --path <dir>"},
                            "error: taste export needs --path <dir>", code=2)
            res = store.export(root, scope=scope)
            return _out(args, res,
                        "\n".join(res["files"]) or "(no learnings to export)")

        if verb == "import":
            path = args.path or value
            if not path:
                return _out(args, {"ok": False,
                                   "error": "taste import needs --path <file>"},
                            "error: taste import needs --path <file>", code=2)
            res = store.import_markdown(path, scope=scope)
            return _out(args, res,
                        f"merged {res['merged']}, disagreements {res['disagreed']}")

        if verb == "inject":
            # The block the harness injects. One format, rendered here so a
            # plugin can never drift from the CLI.
            from ..core.taste.block import render_block
            rows = store.search(scope=scope if scope != "global" else None,
                                status="enforced", limit=100)
            block = render_block(rows)
            payload = {"block": block, "rules": len(rows),
                       "scope": scope, "enabled": bool(block)}
            return _out(args, payload, block or
                        "(no enforced rules; nothing will be injected)")

        if verb == "stats":
            payload = store.stats()
            human = "\n".join([
                f"db:        {payload['db']}",
                f"learnings: {payload['total']}  signals: {payload['signals']}",
                f"enforced:  {payload['enforced']}  conflicts: {payload['conflicts']}",
                "status:    " + ", ".join(f"{k} {v}" for k, v in
                                          payload["by_status"].items()),
                "category:  " + ", ".join(f"{k} {v}" for k, v in
                                          list(payload["by_category"].items())[:8]),
            ])
            return _out(args, payload, human)

        return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                    f"error: unknown verb {verb}", code=2)
    finally:
        store.close()
