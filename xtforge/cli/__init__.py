"""xt-forge CLI entry: <name> <noun> <verb> [--json]."""
from __future__ import annotations

import argparse
import json
import sys

from ..version import app_name
from .mem_cmd import cmd_mem
from .flash_cmd import cmd_flash
from .ops_cmd import cmd_goal, cmd_build
from .slash_cmd import cmd_slash
from .sync_cmd import cmd_sync
from .calibrate_cmd import cmd_calibrate
from .tools_cmd import cmd_tools
from .device_cmd import (cmd_route, cmd_phone, cmd_compress, cmd_ascii,
                         cmd_version, cmd_doctor)


def _add_mem(sub) -> None:
    m = sub.add_parser("mem", help="universal memory")
    m.add_argument("mem_verb", choices=["put", "get", "search", "list", "forget",
                                        "review", "purge", "export", "import", "sync"])
    m.add_argument("value", nargs="?", default=None,
                   help="positional shorthand: id for get/forget, query for "
                        "search, body for put, path for export/import/sync")
    m.add_argument("--id")
    m.add_argument("--scope", default="global")
    m.add_argument("--kind", help="record kind; defaults to 'fact' on put and "
                                  "to every kind on list/search")
    m.add_argument("--title")
    m.add_argument("--body")
    m.add_argument("--body-file", dest="body_file",
                   help="read the record body from a file, or '-' for stdin. "
                        "Use instead of --body for long or multi-line text: "
                        "an inline value has to survive a shell round-trip.")
    m.add_argument("--tag", action="append")
    m.add_argument("--source")
    m.add_argument("--confidence", type=float, default=1.0)
    m.add_argument("--query", "-q")
    m.add_argument("--k", "-k", type=int, default=5)
    m.add_argument("--budget", type=int, default=800)
    m.add_argument("--session")
    m.add_argument("--workflow")
    m.add_argument("--project")
    m.add_argument("--explain", action="store_true")
    m.add_argument("--path")
    m.add_argument("--conflicts")
    m.set_defaults(func=cmd_mem)


def _add_flash(sub) -> None:
    fl = sub.add_parser("flash", help="flash memory (/m* commands)")
    fl.add_argument("flash_verb", choices=["set", "get", "list", "pin", "delete",
                                           "compact", "stats"])
    fl.add_argument("text", nargs="?")
    fl.add_argument("key", nargs="?")
    fl.add_argument("--scope", default="global")
    fl.add_argument("--n", "-n", type=int)
    fl.add_argument("--tag", action="append")
    fl.add_argument("--ttl", type=int)
    fl.add_argument("--all", action="store_true")
    fl.add_argument("--pin-only", action="store_true")
    fl.add_argument("--confirm")
    fl.add_argument("--text-file", dest="text_file",
                    help="read note text from a file, or '-' for stdin. "
                         "Use this instead of inline text whenever the note "
                         "contains spaces, quotes, newlines or is long: an "
                         "inline argument has to survive a shell round-trip.")
    fl.set_defaults(func=cmd_flash)


def _add_goal(sub) -> None:
    g = sub.add_parser("goal", help="bounded goal loop")
    g.add_argument("goal_verb", nargs="?", default="status",
                   choices=["status", "pause", "resume", "stop", "extend", "log",
                            "run", "start"])
    g.add_argument("objective", nargs="?")
    g.add_argument("--run-id")
    g.add_argument("--rounds", type=int, default=8)
    g.add_argument("--criteria")
    g.add_argument("--verify")
    g.add_argument("--budget-tokens", type=int)
    g.add_argument("--n", type=int, default=1)
    g.set_defaults(func=cmd_goal)


def _add_build(sub) -> None:
    b = sub.add_parser("build", help="staged build pipeline")
    b.add_argument("build_verb", choices=["list", "run", "resume", "status", "skip",
                                          "retry", "abort", "graph", "lint", "new",
                                          "spec"])
    b.add_argument("workflow", nargs="?", default=None)
    b.add_argument("phase", nargs="?", default=None)
    b.add_argument("--from", dest="from", default=None)
    b.add_argument("--to", default=None)
    b.add_argument("--var", action="append")
    b.add_argument("--run-id")
    b.add_argument("--workdir", default=".")
    b.add_argument("--dry-run", action="store_true")
    b.add_argument("--path")
    b.add_argument("--out", help="where `build spec` writes the workflow "
                                 "(default: workflows/<spec>.yaml)")
    b.add_argument("--check", action="store_true",
                   help="validate spec + prompts only; write nothing")
    b.set_defaults(func=cmd_build)


def _add_route(sub) -> None:
    r = sub.add_parser("route", help="filesystem navigation tools")
    r.add_argument("route_verb", choices=["resolve", "tree", "find", "grep", "peek",
                                          "du", "recent", "where", "index", "context",
                                          "batch-peek", "errors"])
    r.add_argument("path", nargs="?", default=None)
    r.add_argument("name", nargs="?", default=None)
    r.add_argument("--paths", action="append", default=[])
    r.add_argument("--token-budget", type=int, default=1200)
    r.add_argument("--file-limit", type=int, default=12)
    r.add_argument("--lines-per-file", type=int, default=30)
    r.add_argument("--max-lines", type=int, default=40)
    r.add_argument("--query")
    r.add_argument("--pattern")
    r.add_argument("--glob")
    r.add_argument("--regex")
    r.add_argument("--type")
    r.add_argument("--min-size", type=int, default=-1)
    r.add_argument("--limit", type=int, default=50)
    r.add_argument("--depth", "-d", type=int, default=2)
    r.add_argument("--max", type=int, default=200)
    r.add_argument("--context", type=int, default=1)
    r.add_argument("--mode", default="head")
    r.add_argument("--start", type=int, default=1)
    r.add_argument("--count", type=int, default=50)
    r.add_argument("--top", type=int, default=15)
    r.add_argument("--minutes", type=int, default=60)
    r.set_defaults(func=cmd_route)


def _add_phone(sub) -> None:
    ph = sub.add_parser("phone", help="device state tools")
    ph.add_argument("phone_verb", choices=["info", "procs", "net", "clip-get",
                                           "clip-set", "notify", "wakelock", "adb"])
    ph.add_argument("text", nargs="?")
    ph.add_argument("--title", default="xt-forge")
    ph.add_argument("--top", type=int, default=10)
    ph.add_argument("--by", default="mem")
    ph.add_argument("--on", default="on", choices=["on", "off"])
    ph.set_defaults(func=cmd_phone)


def _add_compress(sub) -> None:
    c = sub.add_parser("compress", help="compress text (stdin, --text or --path)")
    c.add_argument("level", nargs="?", default="L1", choices=["L0", "L1", "L2", "L3"])
    c.add_argument("--path")
    c.add_argument("--text", help="inline text to compress instead of stdin")
    c.add_argument("--stats", action="store_true")
    c.add_argument("--legend", action="store_true")
    c.set_defaults(func=cmd_compress)


def _add_slash(sub) -> None:
    s = sub.add_parser("slash", help="run a slash command (/m /mg /ml /help ...)")
    s.add_argument("text", nargs="+", help="slash command text, e.g. '/ml 20'")
    s.set_defaults(func=cmd_slash)


def _add_sync(sub) -> None:
    s = sub.add_parser(
        "sync",
        help="install/sync .pth, launcher, command templates, theme, plugin wiring")
    s.add_argument("--dry-run", action="store_true",
                   help="report what would change without writing")
    s.set_defaults(func=cmd_sync)


def _add_calibrate(sub) -> None:
    c = sub.add_parser(
        "calibrate",
        help="reboot-aware recalibration (WAL checkpoint, expiry, flash compact, caps reprobe)")
    c.add_argument("--force", action="store_true",
                   help="recalibrate even when caches look fresh")
    c.add_argument("--status", dest="calibrate_status", action="store_true",
                   help="report reboot/caps/WAL status without doing work")
    c.set_defaults(func=cmd_calibrate)


def _add_tools(sub) -> None:
    t = sub.add_parser("tools", help="external tool detection and install hints")
    t.add_argument("tools_verb", nargs="?", default="status", choices=["status"])
    t.set_defaults(func=cmd_tools)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=app_name())
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.add_argument("--db", help="path to mem.db")
    p.add_argument("--flash-base", help="flash storage directory override")
    sub = p.add_subparsers(dest="noun")
    _add_mem(sub)
    _add_flash(sub)
    _add_goal(sub)
    _add_build(sub)
    _add_route(sub)
    _add_phone(sub)
    _add_compress(sub)
    _add_slash(sub)
    _add_sync(sub)
    _add_calibrate(sub)
    _add_tools(sub)
    ascii_cmd = sub.add_parser("ascii", help="XT-Forge ASCII banners")
    ascii_cmd.add_argument("style", nargs="?", default="signal",
                           choices=["compact", "wide", "signal"])
    ascii_cmd.set_defaults(func=cmd_ascii)
    sub.add_parser("version", help="version and paths").set_defaults(func=cmd_version)
    sub.add_parser("doctor", help="environment probe").set_defaults(func=cmd_doctor)
    # Storage flags are documented as global but were root-only, so
    # "xtforge mem get --id x --db /tmp/m.db" failed with argparse exit 2.
    # SUPPRESS keeps a subparser default from clobbering the root value.
    for child in sub.choices.values():
        child.add_argument("--db", default=argparse.SUPPRESS,
                           help="path to mem.db (same as the global flag)")
        child.add_argument("--flash-base", default=argparse.SUPPRESS,
                           help="flash storage directory override")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # --json is documented as global but argparse binds it to the root parser
    # only, so "xtforge version --json" used to fail. Accept it anywhere.
    force_json = len(argv) > 1 and "--json" in argv[1:]
    if force_json:
        argv = [argv[0]] + [a for a in argv[1:] if a != "--json"]
    parser = build_parser()
    args = parser.parse_args(argv)
    if force_json:
        args.json = True
    if not getattr(args, "noun", None):
        parser.print_help()
        return 0
    try:
        result = args.func(args)
        return result if isinstance(result, int) else 0
    except Exception as exc:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())