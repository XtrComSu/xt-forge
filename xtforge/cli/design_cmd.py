"""`xtforge design` — search the curated design library.

The library is files on disk with a JSON index. This command reads them; it
never writes into a user's project.

Three verbs:
    search <query>            find patterns by purpose/when/stack
    show <id>                 the full pattern text plus its state coverage
    check <id> --states a,b   assert which states a design must cover

`check` exists because "it looks fine" is not coverage. A pattern that omits the
offline or permission state is a gap, and this makes that a command rather than
an opinion.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from .common import _out

#: The design library ships inside the package. Resolve it relative to this
#: file so an installed copy finds its own assets instead of the author's
#: checkout — the same class of bug that made relative artifact paths wrong.
LIBRARY = os.environ.get("XT_DESIGN_LIBRARY") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "design"))

#: Every design staged for real use must account for these.
REQUIRED_STATES = ("loading", "empty", "error")


def _index() -> dict[str, Any]:
    path = os.path.join(LIBRARY, "index.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"design index missing at {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _score(entry: dict[str, Any], terms: list[str]) -> int:
    blob = " ".join(str(entry.get(k) or "") for k in
                    ("id", "name", "purpose", "stack", "kind")).lower()
    return sum(1 for t in terms if t in blob)


def cmd_design(args) -> int:
    verb = args.design_verb
    try:
        if verb == "search":
            query = (args.query or args.value or "").strip().lower()
            terms = [t for t in re.split(r"\W+", query) if t]
            idx = _index()
            rows = []
            for e in idx["entries"]:
                if args.kind and e.get("kind") != args.kind:
                    continue
                if terms:
                    s = _score(e, terms)
                    if s == 0:
                        continue
                else:
                    s = 1
                rows.append((s, e))
            rows.sort(key=lambda t: (-t[0], t[1]["id"]))
            hits = [e for _, e in rows[: max(1, args.limit or 8)]]
            human = [f"{len(hits)} match(es) in {len(idx['entries'])} entries"]
            for e in hits:
                human.append(f"  {e['kind']:7s} {e['id']:18s} {e.get('purpose') or e.get('name') or ''}")
                human.append(f"          states: {', '.join(e['states']) or '(none declared)'}")
            return _out(args, {"count": len(hits), "results": hits}, "\n".join(human))

        if verb == "show":
            want = args.value or args.id
            idx = _index()
            e = next((x for x in idx["entries"] if x["id"] == want), None)
            if e is None:
                return _out(args, {"ok": False, "error": f"no entry {want}"},
                            f"error: no entry {want}", code=2)
            path = os.path.join(LIBRARY, e["path"])
            text = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
            return _out(args, {**e, "text": text},
                        f"{e['id']}  ({e['kind']})\n  {path}\n  states: "
                        f"{', '.join(e['states']) or '(none)'}\n\n{text[:2000]}")

        if verb == "check":
            want = args.value or args.id
            required = [s.strip() for s in (args.states or "").split(",") if s.strip()]
            required = required or list(REQUIRED_STATES)
            idx = _index()
            e = next((x for x in idx["entries"] if x["id"] == want), None)
            if e is None:
                return _out(args, {"ok": False, "error": f"no entry {want}"},
                            f"error: no entry {want}", code=2)
            # An anti-pattern describes a failure, not a screen, so it has no
            # states to cover. Requiring them there would fail every time and
            # teach the caller to ignore the check.
            if e.get("kind") == "anti":
                res = {"id": want, "kind": "anti", "applicable": False,
                       "required": required, "missing": [], "ok": True}
                return _out(args, res,
                            f"{want}: not applicable (anti-pattern, not a screen)",
                            code=0)
            have = {s.lower() for s in (e.get("states") or [])}
            missing = [s for s in required if s.lower() not in have]
            res = {"id": want, "kind": e.get("kind"), "applicable": True,
                   "required": required, "covered": sorted(have),
                   "missing": missing, "ok": not missing}
            human = (f"{want}: {'complete' if not missing else 'MISSING ' + ', '.join(missing)}"
                     f"\n  required: {', '.join(required)}")
            return _out(args, res, human, code=0 if not missing else 1)

        return _out(args, {"ok": False, "error": f"unknown verb {verb}"},
                    f"error: unknown verb {verb}", code=2)
    except FileNotFoundError as exc:
        return _out(args, {"ok": False, "error": str(exc)}, f"error: {exc}", code=2)
