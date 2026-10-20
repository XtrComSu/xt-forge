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

    if verb == "verify":
        # Independent verification of a completion claim. The agent does not
        # get to decide whether its own evidence holds up.
        from .common import _read_file_arg
        from ..core.goal import completion as comp
        try:
            raw = _read_file_arg(args, "body_file")
        except OSError as exc:
            return _out(args, {"ok": False, "error": str(exc)}, str(exc), code=1)
        text = raw if raw is not None else (args.body or objective or "")
        if not text.strip():
            return _out(args, {"ok": False,
                               "error": "goal verify needs the marker text "
                                        "(--body-file -)"},
                        "error: goal verify needs marker text", code=2)
        criteria = [c.strip() for c in (args.criteria or "").split(";") if c.strip()]
        approved = [c.strip() for c in
                    (getattr(args, "approved_cmd", None) or []) if c.strip()]
        res = comp.verify_completion(
            text, workspace=args.workdir or ".", criteria=criteria,
            approved_cmds=approved, verify_cmd=args.verify)
        gaps = res.get("gaps") or []
        human = (f"{res['verdict'].upper()}: {res.get('claim', '')[:90]}\n"
                 + "\n".join(f"  - {gap}" for gap in gaps)) \
            if gaps else f"PASS: {res.get('claim', '')[:90]}"
        return _out(args, res, human,
                    code=0 if res.get("ok") else 1)

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


def cmd_loop(args):
    """`xtforge loop` — grammar and policy; the harness owns the timers."""
    from ..core import loop as loopmod
    verb = args.loop_verb
    value = (args.value or "").strip()

    if verb == "parse":
        plan = loopmod.parse_command(value)
        human = (f"mode:    {plan['mode']}\n"
                 f"task:    {plan['task'] or '(from loop.md)'}\n"
                 + (f"cadence: {plan.get('label')} ({plan.get('interval')}s)"
                    if plan.get("interval") else "")
                 + (f"\nerror:   {plan['error']}" if plan.get("error") else ""))
        return _out(args, plan, human.strip())

    if verb == "normalize":
        seconds = loopmod.parse_interval(value)
        if seconds is None and value.isdigit():
            seconds = int(value)
        if seconds is None:
            return _out(args, {"ok": False, "error": f"not an interval: {value}"},
                        f"error: not an interval: {value}", code=2)
        norm, label = loopmod.normalize_interval(seconds)
        return _out(args, {"requested": seconds, "seconds": norm, "label": label},
                    f"{seconds}s -> {label} ({norm}s)")

    if verb == "markers":
        res = loopmod.parse_markers(value)
        human = (f"action: {res.get('action')}\n"
                 + (f"delay:  {res.get('delay')}s\n" if res.get("delay") else "")
                 + (f"reason: {res.get('reason')}\n" if res.get("reason") else "")
                 + (f"gap:    {res.get('gap')}" if res.get("gap") else ""))
        return _out(args, res, human.strip())

    if verb == "next":
        marker = loopmod.parse_markers(getattr(args, "body", None) or value)
        res = loopmod.next_delay(args.base, marker,
                                 quiet_streak=getattr(args, "quiet", 0) or 0,
                                 omit_streak=getattr(args, "omit", 0) or 0)
        human = (f"action: {res['action']}\n"
                 + (f"delay:  {res.get('delay')}s\n" if res.get("delay") else "")
                 + f"reason: {res.get('reason', '')}")
        return _out(args, {**res, "marker": marker}, human.strip())

    if verb == "policy":
        from ..core.loop import schedule as sched
        payload = {
            "max_tasks": sched.MAX_TASKS,
            "lifetime_seconds": sched.LIFETIME_SECONDS,
            "min_delay": loopmod.MIN_DELAY,
            "max_delay": loopmod.MAX_DELAY,
            "kill_switch_env": loopmod.KILL_SWITCH,
            "disabled": loopmod.disabled(),
        }
        human = "\n".join(f"{k:<18} {v}" for k, v in payload.items())
        return _out(args, payload, human)

    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)


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
