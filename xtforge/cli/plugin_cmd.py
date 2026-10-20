"""`xtforge plugin` — install, check and remove the OpenCode plugin.

The plugin is source in this repository. These verbs put it on a machine,
report whether the installed copy still matches the source, and take it back
off again. Writes touch `~/.config/opencode/` and nothing else.
"""
from __future__ import annotations

from .common import _out


def cmd_plugin(args):
    verb = getattr(args, "plugin_verb", None)
    from ..core.plugin import manager

    try:
        if verb == "install":
            res = manager.install(home=_home(args),
                                  target=_target(args),
                                  python=getattr(args, "python", None))
            human = (f"installed {res['version']} -> {res['target']}\n"
                     f"  files: {len(res['files'])}\n"
                     f"  registered: {res['registered']}"
                     f"{' (config updated)' if res['config_changed'] else ''}")
            return _out(args, res, human)

        if verb == "status":
            res = manager.status(home=_home(args), target=_target(args))
            drift = res.get("drift", {})
            human = [f"plugin:  {res['plugin']} {res.get('version') or ''}".rstrip(),
                     f"target:  {res['target']}",
                     f"config:  {res['config']}",
                     f"state:   installed={res['installed']} "
                     f"registered={res['registered']} current={res['current']}"]
            if not res["current"]:
                for key in ("missing", "modified", "extra"):
                    if drift.get(key):
                        human.append(f"  {key}: {', '.join(drift[key])}")
            return _out(args, res, "\n".join(human))

        if verb == "uninstall":
            res = manager.uninstall(home=_home(args), target=_target(args),
                                    purge=bool(getattr(args, "purge", False)))
            human = (f"unregistered {res['target']}"
                     f"{' (files removed)' if res['files_removed'] else ''}")
            return _out(args, res, human)

        if verb == "manifest":
            res = manager.manifest()
            return _out(args, res, "\n".join(f"{d[:12]}  {f}"
                                             for f, d in sorted(res.items())))

    except (OSError, ValueError) as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)

    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)


def _home(args):
    from pathlib import Path
    value = getattr(args, "home", None)
    return Path(value) if value else None


def _target(args):
    from pathlib import Path
    value = getattr(args, "target", None)
    return Path(value) if value else None
