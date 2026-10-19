"""Goal and build CLI handlers."""
from __future__ import annotations

import json
import os

from .common import _out


def cmd_goal(args):
    from ..core.goal import drivers as gdrivers
    from ..core.goal import engine as eng
    from ..version import runs_dir
    verb = args.goal_verb
    objective = (args.objective or "").strip()
    if verb == "status" and objective:
        verb = "run"
    if verb in {"run", "start"}:
        if not objective:
            return _out(args, {"error": "objective required"},
                        "objective required", code=2)
        criteria = [c.strip() for c in (args.criteria or "").split(";") if c.strip()]
        res = gdrivers.start(objective, rounds=args.rounds, criteria=criteria,
                             verify_cmd=args.verify,
                             budget_tokens=args.budget_tokens)
        if res.get("error"):
            return _out(args, res, res["error"], code=1)
        return _out(args, res, res.get("outcome", ""),
                    code=0 if res.get("outcome") == "DONE" else 1)
    if verb in {"status", "pause", "resume", "stop", "extend", "log"}:
        g = eng.Goal("placeholder", run_id=args.run_id or "latest")
        if not args.run_id:
            cands = sorted(runs_dir().glob("goal-*/goal.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
            if cands:
                g.run_id = cands[0].parent.name
        if not g.load():
            return _out(args, {"error": "no goal run found"}, "no goal run")
        if args.goal_verb == "status":
            return _out(args, {"run_id": g.run_id, "state": g.state,
                               "round": g.round_no, "max": g.max_rounds})
        if args.goal_verb == "stop":
            g.stop()
            return _out(args, {"state": g.state}, "stopped")
        if args.goal_verb == "pause":
            g.pause()
            return _out(args, {"state": g.state}, "paused")
        if args.goal_verb == "resume":
            g.resume()
            return _out(args, {"state": g.state}, "resumed")
        if args.goal_verb == "extend":
            added = g.extend(args.n)
            return _out(args, {"max_rounds": g.max_rounds, "added": added})
        if args.goal_verb == "log":
            return _out(args, {"history": g.history})
    return _out(args, {"error": gdrivers.DRIVER_REQUIRED},
                gdrivers.DRIVER_REQUIRED, code=1)


def cmd_build(args):
    from ..core.build import loader as buildloader, runner as buildrunner
    from ..core.build import schema as buildschema
    from ..core.build.drivers import CliDriver, FakeDriver
    verb = args.build_verb
    if verb == "list":
        items = buildloader.list_workflows()
        return _out(args, items,
                    "\n".join(f"{w['id']} ({w.get('type', 'standard')})"
                              for w in items))
    if verb == "lint":
        results = buildloader.validate_all()
        if args.path:
            import pathlib
            data = buildschema.parse(pathlib.Path(args.path).read_text())
            results = {args.path: buildschema.validate(data)}
        failed = {k: v for k, v in results.items() if v}
        return _out(args, results,
                    "all workflows valid" if not failed else json.dumps(failed, indent=2),
                    code=1 if failed else 0)
    if verb == "graph":
        wf = buildloader.load(args.workflow)
        return _out(args, {"graph": buildschema.graph_ascii(wf.phases)},
                    buildschema.graph_ascii(wf.phases))
    if verb == "new":
        res = _scaffold(args)
        return _out(args, res, res.get("error") or res.get("created", ""),
                    code=1 if res.get("error") else 0)
    if verb == "spec":
        res = _spec_build(args)
        return _out(args, res,
                    res.get("error") or _spec_line(res),
                    code=1 if res.get("error") else 0)
    if not isinstance(args.workflow, str):
        return _out(args, {"error": "workflow required"}, "workflow required", code=2)
    wf = buildloader.load(args.workflow)
    if verb == "run":
        driver = (CliDriver(workdir=args.workdir) if os.environ.get("XT_BUILD_CMD")
                  else FakeDriver(workdir=args.workdir))
        run = buildrunner.BuildRun(wf, run_id=args.run_id, workdir=args.workdir,
                                   from_phase=getattr(args, "from", None),
                                   to_phase=getattr(args, "to", None))
        res = run.run(driver, dry_run=args.dry_run)
        return _out(args, res, res.get("outcome", ""),
                    code=0 if res["ok"] else 1)
    run = buildrunner.open_run(wf, args.run_id, workdir=args.workdir,
                               from_phase=getattr(args, "from", None),
                               to_phase=getattr(args, "to", None))
    if run is None:
        return _out(args, {"error": f"no run found for {args.workflow}",
                           "workflow": args.workflow},
                    "no run found", code=1)
    if verb == "resume":
        driver = (CliDriver(workdir=args.workdir) if os.environ.get("XT_BUILD_CMD")
                  else FakeDriver(workdir=args.workdir))
        if not run.resume():
            return _out(args, {"error": "nothing to resume"},
                        "nothing to resume", code=1)
        res = run.run(driver, dry_run=args.dry_run)
        return _out(args, res, res.get("outcome", ""),
                    code=0 if res["ok"] else 1)
    if verb == "status":
        return _out(args, run.status())
    if verb == "skip":
        return _out(args, run.skip_phase(args.phase))
    if verb == "retry":
        return _out(args, run.retry_phase(args.phase))
    if verb == "abort":
        run.state["halted"] = True
        run.state["halt_reason"] = "aborted by user"
        run.save()
        return _out(args, {"aborted": True, "run_id": run.run_id})
    return _out(args, {"error": "workflow required"}, "workflow required", code=2)


def _scaffold(args):
    import re
    from ..version import project_root
    name = args.workflow or ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name or ""):
        return {"error": "workflow id must match [A-Za-z0-9_-]+",
                "got": name}
    target = project_root() / "workflows" / f"{name}.yaml"
    if target.exists():
        return {"error": "workflow already exists", "path": str(target)}
    content = (project_root() / "workflows" / "_template.yaml").read_text()
    target.write_text(content.replace("my-workflow", name))
    return {"created": str(target)}


def _spec_build(args):
    """build type 2: materialize (or only check) a spec-authored workflow."""
    from pathlib import Path
    from ..core.build import spec as specmod
    path = getattr(args, "workflow", None)
    if not path:
        return {"error": "usage: xtforge build spec <spec.json> [--out PATH] "
                         "[--check]"}
    try:
        data = specmod.load_spec(Path(path))
        if getattr(args, "check", False):
            return specmod.check_only(data)
        return specmod.materialize(data, getattr(args, "out", None))
    except specmod.SpecError as exc:
        return {"error": "; ".join(exc.errors), "errors": exc.errors}


def _spec_line(res: dict) -> str:
    phases = ", ".join(res.get("phases") or [])
    if res.get("writes") is False:
        return f"spec {res.get('spec')} ok ({res.get('type')}): {phases} — nothing written"
    return f"{res.get('out')}  [{res.get('type')}] {phases}"
