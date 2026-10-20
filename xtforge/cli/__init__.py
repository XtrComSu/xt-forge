"""xt-forge CLI entry: <name> <noun> <verb> [--json]."""
from __future__ import annotations

import argparse
import json
import sys

from ..version import app_name
from .mem_cmd import cmd_mem
from .flash_cmd import cmd_flash
from .ops_cmd import cmd_goal, cmd_build, cmd_loop
from .slash_cmd import cmd_slash
from .sync_cmd import cmd_sync
from .calibrate_cmd import cmd_calibrate
from .tools_cmd import cmd_tools
from .repos_cmd import cmd_repos
from .scan_cmd import cmd_re, cmd_scan
from .codec_cmd import cmd_codec
from .recon_cmd import cmd_recon
from .docs_cmd import cmd_docs
from .intel_cmd import cmd_intel, cmd_hub
from .eval_cmd import cmd_eval
from .taste_cmd import cmd_taste
from .plugin_cmd import cmd_plugin
from .device_cmd import (cmd_route, cmd_phone, cmd_compress, cmd_ascii,
                         cmd_version, cmd_doctor, cmd_code)


def _add_mem(sub) -> None:
    m = sub.add_parser("mem", help="universal memory")
    m.add_argument("mem_verb", choices=["put", "get", "search", "list", "forget",
                                        "review", "purge", "export", "import", "sync",
                                        "link", "links", "unlink", "capture"])
    m.add_argument("value", nargs="?", default=None,
                   help="positional shorthand: id for get/forget, query for "
                        "search, body for put, path for export/import/sync")
    m.add_argument("value2", nargs="?", default=None,
                   help="second id for link/unlink: mem link <src> <dst>")
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
    m.add_argument("--pending", action="store_true",
                   help="stage as a review-queue candidate instead of a "
                        "promoted record")
    m.add_argument("--query", "-q")
    m.add_argument("--k", "-k", type=int, default=5)
    m.add_argument("--budget", type=int, default=800)
    m.add_argument("--session")
    m.add_argument("--workflow")
    m.add_argument("--project")
    m.add_argument("--explain", action="store_true")
    m.add_argument("--path")
    m.add_argument("--conflicts")
    m.add_argument("--rel",
                   help="link relation: relates_to|supersedes|derived_from|"
                        "part_of|caused_by|fixes|contradicts|see_also")
    m.add_argument("--action", choices=["promote", "drop"],
                   help="review action for a pending record (needs --id)")
    m.add_argument("--no-hybrid", action="store_true",
                   help="lexical-only search (skip the embedding pass)")
    m.add_argument("--embed-mode", default="auto",
                   choices=["auto", "hash", "off"],
                   help="embedding backend for hybrid search")
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
                            "run", "start", "verify"])
    g.add_argument("objective", nargs="?")
    g.add_argument("--run-id")
    g.add_argument("--rounds", type=int, default=8)
    g.add_argument("--criteria")
    g.add_argument("--verify")
    g.add_argument("--budget-tokens", type=int)
    g.add_argument("--n", type=int, default=1)
    g.add_argument("--body", help="verify: the <goal-done> marker text")
    g.add_argument("--body-file", dest="body_file",
                   help="verify: read the marker from a file, or '-' for stdin")
    g.add_argument("--approved-cmd", dest="approved_cmd", action="append",
                   help="verify: command allowed to be replayed as proof "
                        "(repeatable; --verify is always approved)")
    g.add_argument("--workdir", default=".",
                   help="verify: workspace that evidence must stay inside")
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
    r.add_argument("--rank", action="store_true",
                   help="grep: return relevance-ranked matches")
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


def _add_code(sub) -> None:
    c = sub.add_parser("code", help="code structure: symbols, outline, refs")
    c.add_argument("code_verb", choices=["symbols", "outline", "refs"])
    c.add_argument("value", nargs="?", default=None,
                   help="symbol name for refs (same as --name)")
    c.add_argument("path", nargs="?", default=None,
                   help="file or directory (default: .)")
    c.add_argument("--name", help="symbol name for refs")
    c.add_argument("--limit", type=int, default=50)
    c.set_defaults(func=cmd_code)


def _add_re(sub) -> None:
    r = sub.add_parser("re", help="binary inspection and native RE analysis")
    r.add_argument("re_verb", choices=["info", "needed", "sections", "symbols",
                                       "strings", "entropy", "pack",
                                       "ioc", "disasm", "graph"])
    r.add_argument("value", nargs="?", default=None,
                   help="binary path (same as --path)")
    r.add_argument("path", nargs="?", default=None)
    r.add_argument("--limit", type=int, default=200)
    r.add_argument("--min-len", dest="min_len", type=int, default=4)
    r.add_argument("--block", type=int, default=0,
                   help="entropy: report per-block entropy of this size")
    r.add_argument("--count", type=int, default=32,
                   help="entropy: max blocks to report (disasm: instruction count)")
    r.add_argument("--symbol", help="disasm: disassemble one symbol")
    r.add_argument("--section", help="disasm: disassemble one section")
    r.add_argument("--start", help="disasm: skip below this hex address")
    r.set_defaults(func=cmd_re)


def _add_docs(sub) -> None:
    d = sub.add_parser("docs", help="live library documentation (Context7)")
    d.add_argument("docs_verb", choices=["search", "show", "resolve"])
    d.add_argument("value", nargs="?", default=None,
                   help="library name for search/resolve, project id for show")
    d.add_argument("--topic", help="show: narrow to one topic")
    d.add_argument("--language", help="show: prefer examples in this language")
    d.add_argument("--limit", type=int, default=None,
                   help="search: result count (show: token budget)")
    d.set_defaults(func=cmd_docs)


def _add_intel(sub) -> None:
    i = sub.add_parser("intel", help="keyless threat intel (IP, CVE, KEV, hashes)")
    i.add_argument("intel_verb",
                   choices=["ip", "domain", "cve", "kev", "search", "hash",
                            "sources"])
    i.add_argument("value", nargs="?", default=None,
                   help="IP, CVE id, keyword or file hash")
    i.add_argument("--query", help="kev: filter the catalog")
    i.add_argument("--since", type=int, default=None,
                   help="search: only CVEs published in the last N days")
    i.add_argument("--limit", type=int, default=20)
    i.set_defaults(func=cmd_intel)


def _add_hub(sub) -> None:
    h = sub.add_parser("hub", help="HuggingFace models, datasets and quants")
    h.add_argument("hub_verb", choices=["models", "datasets", "show", "files"])
    h.add_argument("value", nargs="?", default=None,
                   help="search term (models/datasets) or repo id (show/files)")
    h.add_argument("--limit", type=int, default=10)
    h.add_argument("--sort", default="downloads",
                   help="downloads, likes, lastModified, trendingScore")
    h.add_argument("--gguf", action="store_true",
                   help="models: only repos containing GGUF files")
    h.add_argument("--task", help="models: filter by pipeline task")
    h.add_argument("--revision", default="main")
    h.set_defaults(func=cmd_hub)


def _add_scan(sub) -> None:
    s = sub.add_parser("scan", help="static safety scan (read-only)")
    s.add_argument("scan_verb", choices=["secrets", "patterns", "deps"])
    s.add_argument("value", nargs="?", default=None,
                   help="file or directory (same as --path)")
    s.add_argument("path", nargs="?", default=None)
    s.add_argument("--glob", help="limit scanning to matching files")
    s.add_argument("--reveal", action="store_true",
                   help="print matched values (default: masked)")
    s.add_argument("--limit", type=int, default=500)
    s.set_defaults(func=cmd_scan)


def _add_taste(sub) -> None:
    t = sub.add_parser("taste", help="deterministic preference learning")
    t.add_argument("taste_verb", choices=["ingest", "search", "show", "review",
                                          "learn", "forget", "export", "import",
                                          "inject", "stats", "prune"])
    t.add_argument("value", nargs="?", default=None,
                   help="statement for learn, query for search, id for show")
    t.add_argument("--id", help="learning id")
    t.add_argument("--scope", default="global")
    t.add_argument("--category", help="filter by category")
    t.add_argument("--status", help="filter by status (enforced|hint|weak|conflict)")
    t.add_argument("--body", help="inline text for learn/ingest")
    t.add_argument("--body-file", dest="body_file",
                   help="read text from a file, or '-' for stdin")
    t.add_argument("--source", help="where a signal came from")
    t.add_argument("--path", help="export directory or import file")
    t.add_argument("--limit", "--k", "-n", dest="limit", type=int, default=None)
    t.add_argument("--taste-db", dest="taste_db",
                   help="taste database path override")
    t.add_argument("--apply", action="store_true",
                   help="prune: retire the listed learnings")
    t.set_defaults(func=cmd_taste)


def _add_loop(sub) -> None:
    l = sub.add_parser("loop", help="loop grammar and scheduling policy")
    l.add_argument("loop_verb", choices=["parse", "normalize", "markers", "next",
                                         "policy"])
    l.add_argument("value", nargs="?", default=None,
                   help="command text, interval, or marker text")
    l.add_argument("--body", help="next: the iteration's marker text")
    l.add_argument("--base", type=int, default=300,
                   help="next: base delay in seconds (default 300)")
    l.add_argument("--quiet", type=int, default=0,
                   help="next: consecutive iterations with no progress")
    l.add_argument("--omit", type=int, default=0,
                   help="next: consecutive iterations missing a marker")
    l.set_defaults(func=cmd_loop)


def _add_codec(sub) -> None:
    c = sub.add_parser("codec", help="hash, encode, decode, entropy, inspect")
    c.add_argument("codec_verb", choices=["hash", "encode", "decode", "roundtrip",
                                          "entropy", "inspect"])
    c.add_argument("value", nargs="?", default=None,
                   help="input value (same as --text)")
    c.add_argument("--text", help="inline input value")
    c.add_argument("--path", help="read input from a file")
    c.add_argument("--algo", default="sha256",
                   help="hash algorithm (md5|sha1|sha256|sha512|sha3_256|"
                        "blake2b|blake2s|crc32), or 'all'")
    c.add_argument("--all", action="store_true", help="hash: every algorithm")
    c.add_argument("--scheme", default="base64",
                   help="codec scheme (base64|base64url|base32|hex|binary|"
                        "url|html|rot13|upper|reverse)")
    c.add_argument("--block", type=int, default=0,
                   help="entropy: report per-block entropy of this size")
    c.set_defaults(func=cmd_codec)


def _add_recon(sub) -> None:
    r = sub.add_parser("recon", help="scoped findings ledger + reports")
    r.add_argument("recon_verb", choices=["new", "note", "finding", "list",
                                          "report", "stats"])
    r.add_argument("value", nargs="?", default=None,
                   help="target label (same as --target)")
    r.add_argument("--target", help="target label, e.g. example.com")
    r.add_argument("--title", help="finding: short title")
    r.add_argument("--severity", default="info",
                   choices=["critical", "high", "medium", "low", "info"])
    r.add_argument("--detail", help="finding: longer description")
    r.add_argument("--evidence", help="finding: proof (url, output, path)")
    r.add_argument("--tag", action="append")
    r.add_argument("--body", help="note: text (or use --text)")
    r.add_argument("--text", help="note: text")
    r.add_argument("--path", help="report: write markdown here instead of stdout")
    r.set_defaults(func=cmd_recon)


def _add_eval(sub) -> None:
    e = sub.add_parser("eval", help="record and compare benchmark runs")
    e.add_argument("eval_verb", choices=["record", "list", "show", "compare",
                                         "report"])
    e.add_argument("value", nargs="?", default=None,
                   help="suite name (same as --suite)")
    e.add_argument("value2", nargs="?", default=None,
                   help="compare: the current run id")
    e.add_argument("--suite", help="suite name, e.g. mem-recall")
    e.add_argument("--run-id", dest="run_id",
                   help="show/compare: run id (defaults to the latest)")
    e.add_argument("--body", help="record: JSON payload inline")
    e.add_argument("--body-file", dest="body_file",
                   help="record: read the JSON payload from a file or '-'")
    e.add_argument("--note", help="record: note stored with the run")
    e.add_argument("--limit", type=int, default=None, help="report: run count")
    e.set_defaults(func=cmd_eval)


def _add_repos(sub) -> None:
    r = sub.add_parser("repos", help="bundled top-repos catalog (read-only)")
    r.add_argument("repos_verb", choices=["list", "search", "show", "domains",
                                          "suggest", "plan", "stats", "export"])
    r.add_argument("value", nargs="?", default=None,
                   help="query for search, owner/name for show/plan, "
                        "capability for suggest")
    r.add_argument("--query", "-q", help="search query (same as the positional)")
    r.add_argument("--capability", help="capability family for suggest")
    r.add_argument("--domain", help="filter: cs domain, e.g. red teaming")
    r.add_argument("--verdict", help="filter: adopt|borrow|study|skip")
    r.add_argument("--surface", help="filter (list/export) or override (plan)")
    r.add_argument("--language", help="filter: language, e.g. Rust")
    r.add_argument("--license", help="filter: SPDX id, e.g. MIT")
    r.add_argument("--min-stars", type=int, default=0)
    r.add_argument("--include-archived", action="store_true")
    r.add_argument("--limit", "--k", "-n", dest="limit", type=int, default=None,
                   help="max rows (export: all rows when omitted)")
    r.add_argument("--sort", default="fit", choices=["fit", "stars", "name"])
    r.add_argument("--format", default="json",
                   choices=["json", "csv", "md", "jsonl"],
                   help="export format; jsonl is the learning dataset")
    r.add_argument("--path", help="export destination; prints when omitted")
    r.add_argument("--ns", help="plan: target namespace, e.g. scan")
    r.add_argument("--tool-verb", dest="tool_verb",
                   help="plan: target verb, e.g. secrets")
    r.set_defaults(func=cmd_repos)


def _add_plugin(sub) -> None:
    p = sub.add_parser("plugin", help="install the OpenCode plugin")
    p.add_argument("plugin_verb", choices=["install", "status", "uninstall",
                                            "manifest"])
    p.add_argument("--home", help="home directory to install into "
                                  "(default: $HOME)")
    p.add_argument("--target", help="plugin directory to install into")
    p.add_argument("--python", help="interpreter the plugin should use")
    p.add_argument("--purge", action="store_true",
                   help="uninstall: also delete the installed files")
    p.set_defaults(func=cmd_plugin)


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
    _add_code(sub)
    _add_re(sub)
    _add_docs(sub)
    _add_intel(sub)
    _add_hub(sub)
    _add_scan(sub)
    _add_taste(sub)
    _add_plugin(sub)
    _add_loop(sub)
    _add_codec(sub)
    _add_recon(sub)
    _add_eval(sub)
    _add_phone(sub)
    _add_compress(sub)
    _add_slash(sub)
    _add_sync(sub)
    _add_calibrate(sub)
    _add_tools(sub)
    _add_repos(sub)
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