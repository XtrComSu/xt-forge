"""`xtforge eval` — record benchmark runs, compare them, report deltas.

Benches compute numbers; this is where they are stored so a regression cannot
quietly disappear into a scrollback buffer.
"""
from __future__ import annotations

import json

from .common import _out, _read_file_arg


def cmd_eval(args):
    from ..core import eval as evalmod
    verb = args.eval_verb
    suite = (args.suite or args.value or "").strip()

    try:
        if verb == "record":
            if not suite:
                return _out(args, {"ok": False, "error": "eval record needs a suite"},
                            "error: eval record needs a suite", code=2)
            try:
                raw = _read_file_arg(args, "body_file")
            except OSError as exc:
                return _out(args, {"ok": False, "error": str(exc)}, str(exc), code=1)
            text = raw if raw is not None else (args.body or "")
            if not text.strip():
                return _out(args, {"ok": False,
                                   "error": "eval record needs a JSON payload "
                                            "(--body-file -)"},
                            "error: eval record needs a JSON payload", code=2)
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                return _out(args, {"ok": False, "error": f"invalid JSON: {exc}"},
                            f"error: invalid JSON: {exc}", code=2)
            if not isinstance(payload, dict):
                return _out(args, {"ok": False,
                                   "error": "payload must be a JSON object"},
                            "error: payload must be a JSON object", code=2)
            run = evalmod.record(suite, payload, note=args.note or "")
            human = (f"recorded {run['suite']}/{run['run_id']}\n"
                     + "\n".join(f"  {k} = {v:g}"
                                 for k, v in list(run["metrics"].items())[:8]))
            return _out(args, run, human)

        if verb == "list":
            runs = evalmod.list_runs(suite)
            human = "\n".join(
                f"{r['run_id']:<28} {r.get('recorded')}  "
                f"{len(r.get('metrics', {}))} metrics"
                for r in runs) or "(no runs)"
            return _out(args, runs, human)

        if verb == "show":
            run_id = args.run_id or args.value2
            if not run_id:
                runs = evalmod.list_runs(suite)
                run = runs[-1] if runs else None
            else:
                run = evalmod.load(suite, run_id)
            if run is None:
                return _out(args, {"ok": False, "error": "no such run"},
                            "error: no such run", code=1)
            human = "\n".join(f"{k} = {v:g}"
                              for k, v in sorted(run["metrics"].items()))
            return _out(args, run, human)

        if verb == "compare":
            runs = evalmod.list_runs(suite)
            if len(runs) < 2 and not (args.run_id and args.value2):
                return _out(args, {"ok": False,
                                   "error": "need two runs to compare"},
                            "error: need two runs to compare", code=2)
            base = evalmod.load(suite, args.run_id) if args.run_id else runs[-2]
            current = (evalmod.load(suite, args.value2)
                       if args.value2 else runs[-1])
            verdict = evalmod.compare(base, current)
            human = [f"{verdict['suite']}: "
                     f"{verdict['base_run']} -> {verdict['current_run']}",
                     f"direction: better is {verdict['direction']}"]
            for row in verdict["rows"]:
                human.append(f"  {row['metric']:<32} {row['before']} -> "
                             f"{row['after']} ({row['verdict']})")
            human.append(f"regressions: {verdict['regressions']}")
            return _out(args, verdict, "\n".join(human),
                        code=0 if verdict["ok"] else 1)

        if verb == "report":
            text = evalmod.report(suite, limit=args.limit or 5)
            return _out(args, {"suite": evalmod._safe(suite), "report": text}, text)

    except ValueError as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=2)
    except OSError as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)
