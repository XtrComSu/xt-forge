"""xt-forge CLI entry: <name> <noun> <verb> [--json]."""
from __future__ import annotations

import argparse
import json
import sys

from ..version import app_name, version_str
from .mem_cmd import cmd_mem
from .flash_cmd import cmd_flash
from .ops_cmd import cmd_goal, cmd_build, cmd_loop
from .slash_cmd import cmd_slash
from .sync_cmd import cmd_sync
from .calibrate_cmd import cmd_calibrate
from .tools_cmd import cmd_tools
from .scan_cmd import cmd_re, cmd_scan, cmd_test
from .swarm_cmd import cmd_swarm
from .session_cmd import cmd_session
from .codec_cmd import cmd_codec
from .recon_cmd import cmd_recon
from .recall_cmd import cmd_recall
from .search_cmd import cmd_search
from .tool_cmd import cmd_tool
from .artifact_cmd import cmd_artifact
from .knowledge_cmd import cmd_knowledge
from .design_cmd import cmd_design
from .mcp_cmd import cmd_mcp
from .docs_cmd import cmd_docs
from .intel_cmd import cmd_intel, cmd_hub
from .eval_cmd import cmd_eval
from .taste_cmd import cmd_taste
from .plugin_cmd import cmd_plugin
from .research_cmd import cmd_research
from .device_cmd import (cmd_route, cmd_phone, cmd_compress, cmd_ascii,
                         cmd_version, cmd_doctor, cmd_code, cmd_guard,
                         cmd_skills)
from .prompt_cmd import cmd_prompt


def _add_mem(sub) -> None:
    m = sub.add_parser("mem", help="universal memory")
    m.add_argument("mem_verb", choices=["put", "get", "search", "list", "forget",
                                        "review", "purge", "export", "import", "sync",
                                        "link", "links", "unlink", "capture",
                                        "consolidate", "record-failure"])
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
    m.add_argument("--error-sig", dest="error_sig", help="record-failure: error signature")
    m.add_argument("--sig", help="record-failure: alias for --error-sig")
    m.add_argument("--outcome", default="failed", help="record-failure: outcome tag")
    m.add_argument("--threshold", type=float, default=0.55, help="consolidate: Jaccard similarity threshold")
    m.add_argument("--dry-run", dest="dry_run", action="store_true", help="consolidate: preview merges without writing")
    m.add_argument("--limit", type=int, default=250, help="consolidate: max candidates to inspect")
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
                            "run", "start", "verify", "check"])
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
    g.add_argument("--interactive", action="store_true",
                   help="check: prompt on TTY before proceeding when warnings exist")
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
    r.add_argument("--symbols", action="store_true",
                   help="context: expand matches along the code call/definition graph")
    r.add_argument("--diagnose", "--explain", dest="diagnose", action="store_true",
                   help="context: explain ranking, index status, and budget/limit drop reasons")
    r.add_argument("--expected-file", dest="expected_file",
                   help="context --diagnose: optional expected file path to inspect")
    r.add_argument("--expected-line", dest="expected_line", type=int, default=0,
                   help="context --diagnose: optional expected line number to inspect")
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
    c = sub.add_parser("code", help="code structure: symbols, outline, refs, syntax, index, graph, callers, audit, trace, lsp")
    c.add_argument("code_verb", choices=["symbols", "outline", "refs", "syntax", "index", "graph", "callers", "audit", "trace", "lsp"])
    c.add_argument("value", nargs="?", default=None,
                   help="symbol name for refs/graph/trace, action for lsp, or path for symbols/outline/syntax/index/audit")
    c.add_argument("path", nargs="?", default=None,
                   help="file or directory (default: .)")
    c.add_argument("--name", help="symbol name for refs/graph")
    c.add_argument("--path", dest="path_flag", help="file or directory override (default: .)")
    c.add_argument("--limit", type=int, default=50)
    c.add_argument("--depth", type=int, default=2, help="graph: BFS depth")
    c.add_argument("--graph-db", dest="graph_db", help="override code_graph.db path")
    c.add_argument("--line", type=int, default=1, help="lsp: 1-based line")
    c.add_argument("--col", type=int, default=1, help="lsp: 1-based column")
    c.add_argument("--symbol", help="symbol name for graph/callers/lsp")
    c.set_defaults(func=cmd_code)


def _add_prompt(sub) -> None:
    p = sub.add_parser("prompt", help="prompt management and agent prompt injection")
    p.add_argument("prompt_verb", choices=["inject", "render", "hash"])
    p.add_argument("name", nargs="?", default=None, help="prompt name")
    p.add_argument("--name", dest="name_flag", help="prompt name")
    p.add_argument("--no-taste", action="store_true", help="exclude taste rules from injection")
    p.add_argument("--no-flash", action="store_true", help="exclude pinned flash notes from injection")
    p.add_argument("--flash-scope", default="global", help="flash scope for pinned notes")
    p.add_argument("--query", "-q", help="search query to recall matching durable memories")
    p.add_argument("--mem-k", type=int, default=3, help="number of durable memories to recall")
    p.add_argument("--harness", choices=["auto", "dsh", "opencode", "generic"], default="auto",
                   help="target agent harness context")
    p.add_argument("--compact", action="store_true", help="produce dense, token-minimized output")
    p.add_argument("--token-budget", type=int, default=None, help="maximum token budget for injected context")
    p.add_argument("--var", action="append", default=[], help="variable substitution in KEY=VALUE format")
    p.set_defaults(func=cmd_prompt)


def _add_re(sub) -> None:
    r = sub.add_parser("re", help="binary inspection, native RE analysis, and project scaffolding")
    r.add_argument("re_verb", choices=["info", "overview", "functions", "xrefs-native", "dispatch-native", "disasm-native", "decompile-native", "needed", "sections", "symbols",
                                       "strings", "entropy", "pack",
                                       "ioc", "disasm", "graph",
                                       "pe", "cfg", "block", "view", "xrefs",
                                       "checksec", "hooks", "patch", "rtti", "diff",
                                       "capa", "crash",
                                       "annotate", "asar", "netcap", "apk",
                                       "decompile", "trace",
                                       "deep-elf", "anchors", "slice", "live-probe", "rbxm",
                                       "ida", "borer", "triage", "init-project", "llvm", "archives", "kernelcache", "pdb", "pdb-types", "demangle", "callgraph", "evidence", "search",
                                       "elfmeta", "wasm", "firmware", "managed",
                                       "formats", "devicetree", "kconfig", "lnk",
                                       "sqlite", "beam", "evm", "ips",
                                       "uefi", "nvram",
                                       "dex",
                                       "firmware", "fv", "uefi-firmware", "assetcatalog", "car", "unknowns", "obligations", "v8cache", "codecache", "ptrace", "playwright",
                                       "objc", "objc-classes", "objc-protocols",
                                       "keyed", "keyed-archive", "jvm", "maven",
                                       "nuget", "appbundle", "bundle",
                                       "bookmarks", "bulk"])
    r.add_argument("value", nargs="?", default=None,
                   help="binary path, new project directory, or subverb")
    r.add_argument("path", nargs="?", default=None)
    r.add_argument("extra", nargs="*", default=[], help="additional positional arguments")
    r.add_argument("--limit", type=int, default=200)
    r.add_argument("--min-len", dest="min_len", type=int, default=4)
    r.add_argument("--stack", action="store_true", help="strings: recover stack-constructed strings from disasm")
    r.add_argument("--xor", action="store_true", help="strings: brute-force single-byte XOR keys")
    r.add_argument("--block", type=int, default=0,
                   help="entropy: report per-block entropy of this size")
    r.add_argument("--count", type=int, default=32,
                   help="entropy: max blocks to report (disasm: instruction count)")
    r.add_argument("--symbol", help="disasm/cfg: target symbol")
    r.add_argument("--member", help="SYS: exact executable member path in an IPA archive")
    r.add_argument("--arch", help="SYS: select a slice of a universal Mach-O, or the architecture of a raw image (with --base)")
    r.add_argument("--base", type=lambda value: int(value, 0), default=None,
                   help="SYS: load address for a headerless raw image (decimal or 0x hex)")
    r.add_argument("--bytes", type=int, default=0, help="disasm-native: maximum bytes to inspect")
    r.add_argument("--flow", action="store_true", help="disasm-native: follow reachable direct branches")
    r.add_argument("--max-functions", type=int, default=0, help="xrefs-native: maximum functions to scan")
    r.add_argument("--section", help="disasm: disassemble one section")
    r.add_argument("--start", help="disasm: skip below this hex address")
    r.add_argument("--rva", help="cfg: function start RVA in hex (e.g. 0x1000)")
    r.add_argument("--engine", choices=["auto", "builtin", "rizin"], default="auto",
                   help="cfg: disassembly and graph engine")
    r.add_argument("--max-instructions", type=int, default=250,
                   help="cfg: maximum instructions to serialize in block graph")
    r.add_argument("--block-id", help="block: basic block id to fetch instructions for")
    r.add_argument("--out", help="view/patch: output path for companion HTML or patched binary")
    r.add_argument("--target", help="xrefs: target symbol or hex address")
    r.add_argument("--offset", help="patch: hex or decimal file offset to modify")
    r.add_argument("--patch-bytes", dest="patch_bytes", help="patch: hex bytes to write (e.g. 9090 or c3)")
    r.add_argument("--orig-bytes", dest="orig_bytes", help="patch: expected original hex bytes to verify")
    r.add_argument("--name", help="annotate: replacement symbol name; init-project: display title")
    r.add_argument("--orig", help="annotate: original symbol name")
    r.add_argument("--comment", help="annotate: analyst note at RVA")
    r.add_argument("--type-decl", dest="type_decl", help="annotate: C type declaration at RVA")
    r.add_argument("--confidence", type=float, default=1.0, help="annotate: confidence score")
    r.add_argument("--format", default="json", choices=["json", "r2", "ghidra"], help="annotate export format")
    r.add_argument("--grep", help="asar: filter archived paths")
    r.add_argument("--pattern",
                   help="search: text to find (default mode), or hex/regex with --hex/--regex")
    r.add_argument("--hex", dest="hex_pattern", action="store_true",
                   help="search: read --pattern as hex bytes; '??' matches any byte")
    r.add_argument("--regex", action="store_true",
                   help="search: read --pattern as a bytes regex (caller owns backtracking cost)")
    r.add_argument("--context", type=int, default=16,
                   help="search: bytes of context to show around each match")
    r.add_argument("--ignore-case", dest="ignore_case", action="store_true",
                   help="search: case-insensitive text/regex match")
    r.add_argument("--reveal", action="store_true", help="netcap: unmask sensitive headers")
    r.add_argument("--confirm", help="trace: confirm token")
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


def _add_test(sub) -> None:
    t = sub.add_parser("test", help="auto-detect and run project test suite")
    t.add_argument("path", nargs="?", default=".")
    t.add_argument("--pattern", default="", help="optional test filter pattern")
    t.set_defaults(func=cmd_test)


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
    s.add_argument("scan_verb", choices=["secrets", "patterns", "deps", "injection", "mcp"])
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
                                          "inject", "stats", "prune", "repair"])
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
    t.add_argument("--prompt-id", dest="prompt_id",
                   help="id of the prompt a signal came from; makes the "
                        "ingest idempotent, so one prompt is one signal")
    t.add_argument("--path", help="export directory or import file")
    t.add_argument("--limit", "--k", "-n", dest="limit", type=int, default=None)
    t.add_argument("--taste-db", dest="taste_db",
                   help="taste database path override")
    t.add_argument("--apply", action="store_true",
                   help="prune/repair: apply the change instead of reporting")
    t.set_defaults(func=cmd_taste)


def _add_loop(sub) -> None:
    l = sub.add_parser("loop", help="loop grammar and scheduling policy")
    l.add_argument("loop_verb", choices=["parse", "normalize", "markers", "next",
                                         "policy", "schedule", "list", "stop"])
    l.add_argument("value", nargs="?", default=None,
                   help="command text, interval, marker text, or loop id")
    l.add_argument("--body", help="next: the iteration's marker text")
    l.add_argument("--cmd", help="schedule: command to run")
    l.add_argument("--id", help="stop: scheduled task id")
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


def _add_design(sub) -> None:
    d = sub.add_parser("design", help="search the curated design library")
    d.add_argument("design_verb", choices=["search", "show", "check"])
    d.add_argument("value", nargs="?", default=None, help="query or entry id")
    d.add_argument("--id")
    d.add_argument("--query", "-q")
    d.add_argument("--kind", choices=["pattern", "anti"])
    d.add_argument("--limit", type=int, default=8)
    d.add_argument("--states", help="check: comma-separated states that must be covered")
    d.set_defaults(func=cmd_design)


def _add_knowledge(sub) -> None:
    k = sub.add_parser("knowledge", help="agent-contributed knowledge with lifecycle status")
    k.add_argument("knowledge_verb",
                   choices=["put", "get", "search", "verify", "revise", "link", "deprecate"])
    k.add_argument("value", nargs="?", default=None,
                   help="id for get/verify/revise/deprecate; query for search")
    k.add_argument("--id", help="record id")
    k.add_argument("--kind", help="fact|decision|procedure|error_pattern|problem|"
                                 "recovery|design|design_antipattern|discovery|"
                                 "environment|example")
    k.add_argument("--title")
    k.add_argument("--body")
    k.add_argument("--body-file", dest="body_file",
                   help="read the body from a file, or '-' for stdin")
    k.add_argument("--scope", default="global")
    k.add_argument("--status", help="observed|proposed (agents cannot assert "
                                    "verified directly)")
    k.add_argument("--project")
    k.add_argument("--target")
    k.add_argument("--evidence")
    k.add_argument("--author", help="authoring agent identity")
    k.add_argument("--version", action="append", help="applicable version (repeatable)")
    k.add_argument("--environment")
    k.add_argument("--tag", action="append")
    k.add_argument("--method", help="verify: how it was checked")
    k.add_argument("--result", choices=["pass", "fail", "inconclusive"],
                   help="verify: outcome of the check")
    k.add_argument("--checker", help="verify: identity of the check that ran")
    k.add_argument("--exit-status", dest="exit_status", type=int,
                   help="verify: exit status of the executed check")
    k.add_argument("--contradict", action="store_true",
                   help="verify: this check contradicts the record")
    k.add_argument("--relation", help="link: relates_to|part_of|depends_on|"
                                      "caused_by|fixes|contradicts|see_also")
    k.add_argument("--reason", help="deprecate: why")
    k.add_argument("--superseded-by", dest="superseded_by")
    k.add_argument("--query", "-q")
    k.add_argument("--k", type=int, default=8)
    k.set_defaults(func=cmd_knowledge)


def _add_artifact(sub) -> None:
    a = sub.add_parser("artifact", help="record and verify produced files")
    a.add_argument("artifact_verb", choices=["record", "check", "require", "show", "verify"])
    a.add_argument("path", help="path to the artifact")
    a.add_argument("--media-type", dest="media_type")
    a.add_argument("--producer", help="tool/attempt that produced it")
    a.add_argument("--check", help="check id (check verb), e.g. pdf-pages")
    a.add_argument("--result", choices=["pass", "fail", "skipped"], default="pass")
    a.add_argument("--detail", help="what the check observed")
    a.add_argument("--version", help="check implementation version")
    a.add_argument("--by", help="who ran it")
    a.add_argument("--checker", help="identity of the check implementation that "
                                     "actually ran, e.g. scripts/check-pdf.py@2")
    a.add_argument("--exit-status", dest="exit_status", type=int,
                   help="exit status of the executed checker; its presence marks "
                        "the check as executed rather than declared")
    a.add_argument("--evidence", help="path or reference to the checker's output")
    a.add_argument("--declared", action="store_true",
                   help="record an assertion only; a declared pass can never "
                        "produce 'verified'")
    a.add_argument("--requires", action="append", metavar="CHECK_ID",
                   help="declare a check that must pass for completion "
                        "(repeatable; used with the 'require' verb)")
    a.set_defaults(func=cmd_artifact)


def _add_recall(sub) -> None:
    r = sub.add_parser("recall", help="one query across mem, recon, flash and errors")
    r.add_argument("value", nargs="?", default=None, help="search text")
    r.add_argument("--query", "-q", help="search text (alias for the positional)")
    r.add_argument("--target", help="recon target label; findings are per-target")
    r.add_argument("--tool", help="tool name for error-memory lookup, e.g. bash")
    r.add_argument("--store", help="comma list to restrict sources: mem,recon,flash,errors")
    r.add_argument("--k", type=int, default=5, help="hits per source from mem (default 5)")
    r.add_argument("--limit", type=int, default=10, help="row cap per non-mem source")
    r.add_argument("--artifacts-root", action="append", dest="artifacts_root",
                   help="directory to search for artifact sidecars (repeatable; "
                        "defaults to the caller's working directory)")
    r.add_argument("--budget-chars", dest="budget_chars", type=int, default=0,
                   help="hard cap on returned content in characters (0 = no cap); "
                        "truncation is reported, never silent")
    r.add_argument("--loose", action="store_true",
                   help="accept the stores' raw ranking instead of filtering to rows "
                        "that share a token with the query")
    r.set_defaults(func=cmd_recall)


def _add_search(sub) -> None:
    s = sub.add_parser("search", help="federated search across code, memory, knowledge, web, CVEs, and tools")
    s.add_argument("value", nargs="?", default=None, help="search query text or sub-mode (web, cve, tool)")
    s.add_argument("path", nargs="?", default=None, help="directory for code search, or query when sub-mode given")
    s.add_argument("--query", "-q", help="search query text")
    s.add_argument("--path", dest="path_flag", help="directory for code search")
    s.add_argument("--web", action="store_true", help="search the web via local searchd (Google SERP) / SearXNG")
    s.add_argument("--cve", action="store_true", help="search CVEs, NVD, EPSS, and CISA KEV")
    s.add_argument("--tools", action="store_true", help="search external MCP tools and capabilities")
    s.add_argument("--all", action="store_true", help="search all stores including web, CVEs, and tools")
    s.add_argument("--limit", type=int, default=8, help="max results per category (default: 8)")
    s.add_argument("--stores", help="comma-separated stores: code,mem,flash,knowledge,recon,web,cve,tools")
    s.set_defaults(func=cmd_search)


def _add_tool(sub) -> None:
    t = sub.add_parser("tool", help="on-demand external MCP tool discovery and execution")
    t.add_argument("tool_verb", choices=["list", "search", "run"],
                   help="verb: list, search, run")
    t.add_argument("server", nargs="?", help="server name or search query")
    t.add_argument("tool_name", nargs="?", help="tool name (for run)")
    t.add_argument("arguments", nargs="?", help="JSON arguments string (for run)")
    t.add_argument("--query", "-q", help="search query")
    t.add_argument("--args-file", dest="args_file", help="path to JSON arguments file or '-' for stdin")
    t.add_argument("--timeout", type=int, default=60, help="execution timeout in seconds")
    t.set_defaults(func=cmd_tool)


def _add_mcp(sub) -> None:
    m = sub.add_parser("mcp", help="MCP servers, connect, audit, trust pinning, proxy, and gateway")
    m.add_argument("mcp_verb", nargs="?", default="status",
                   choices=["status", "advice", "configs", "serve", "audit",
                            "proxy", "trust", "connect", "journal"])
    m.add_argument("mcp_target", nargs="?", help="optional server name/alias (e.g. rea, craft-anything, borer)")
    m.add_argument("--state", help="journal: filter by state (never_started|unknown_outcome|completed)")
    m.add_argument("--key", help="journal: look up idempotency key")
    m.add_argument("--profile", help="only read this profile's cordis patch "
                                     "(default: every profile)")
    m.add_argument("--probe", action="store_true",
                   help="status: start each selected server and measure its "
                        "real tools/list payload (opt-in: this spawns processes)")
    m.add_argument("--timeout", type=float, default=20.0,
                   help="probe: seconds allowed per server")
    m.add_argument("--meta", action="store_true",
                   help="serve: expose 4-tool meta-gateway (~1.4KB) instead of 56 pinned tools")
    m.add_argument("--server", help="audit/proxy/trust/connect: logical server name or preset (rea, craft-anything, borer)")
    m.add_argument("--prefix", help="proxy: tool prefix (defaults to server name)")
    m.add_argument("--cmd", help="audit/proxy/trust/connect: stdio command for child server")
    m.add_argument("--trust-on-first", dest="trust_on_first", action="store_true",
                   help="audit/proxy: pin SHA-256 baseline on first inspection")
    m.set_defaults(func=cmd_mcp)


def _add_research(sub) -> None:
    r = sub.add_parser("research", help="parallel multi-source research dossier fan-out")
    r.add_argument("topic", nargs="?", default=None, help="research topic")
    r.add_argument("--query", "-q", help="alias for topic")
    r.add_argument("--path", default=".", help="workspace path for code evidence")
    r.add_argument("--k", "-k", type=int, default=5, help="hits per store")
    r.add_argument("--save", action="store_true", help="persist markdown dossier to XT_HOME/research")
    r.add_argument("--web", action="store_true", help="enable live web fan-out in native hub")
    r.set_defaults(func=cmd_research)


def _add_guard(sub) -> None:
    g = sub.add_parser("guard", help="permission mode (explore|ask|auto) and audit policy")
    g.add_argument("guard_verb", nargs="?", default="mode", choices=["mode"])
    g.add_argument("value", nargs="?", default=None, help="optional mode to set: explore|ask|auto")
    g.set_defaults(func=cmd_guard)


def _add_swarm(sub) -> None:
    s = sub.add_parser("swarm", help="high-concurrency binary analysis and speculative solving")
    s.add_argument("swarm_verb", choices=["map", "solve", "audit"], default="map")
    s.add_argument("target", nargs="?", default=None, help="target binary path")
    s.add_argument("--workers", type=int, default=8, help="parallel worker count")
    s.add_argument("--offset", help="solve: byte offset to test speculative decoding")
    s.add_argument("--size", type=int, default=256, help="solve: size of byte chunk to evaluate")
    s.add_argument("--hypotheses", help="solve: comma-separated list of decoding hypotheses")
    s.set_defaults(func=cmd_swarm)


def _add_session(sub) -> None:
    s = sub.add_parser("session", help="session checkpointing and recoverable call journal")
    s.add_argument("session_verb",
                   choices=["fork", "rewind", "list", "delete", "journal", "recover", "begin-call", "resolve-call"],
                   default="list", nargs="?")
    s.add_argument("target", nargs="?", default=None, help="checkpoint id, call_id, or idempotency key")
    s.add_argument("--name", help="descriptive name for checkpoint")
    s.add_argument("--state", help="journal: filter state (never_started|unknown_outcome|completed)")
    s.add_argument("--key", help="idempotency key")
    s.add_argument("--server", help="upstream server name")
    s.add_argument("--tool", help="upstream tool name")
    s.add_argument("--verify-tool", dest="verify_tool", help="read-only verification tool name")
    s.set_defaults(func=cmd_session)


def _add_skills(sub) -> None:
    sk = sub.add_parser("skills", help="list or install XT-Forge XTF-* skills")
    sk.add_argument("skills_verb", nargs="?", default="list", choices=["list", "path", "install"])
    sk.set_defaults(func=cmd_skills)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=app_name())
    p.add_argument("-V", "--version", action="version", version=f"{app_name()} {version_str()}")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.add_argument("--db", help="path to mem.db")
    p.add_argument("--flash-base", help="flash storage directory override")
    sub = p.add_subparsers(dest="noun")
    _add_search(sub)
    _add_tool(sub)
    _add_mem(sub)
    _add_recall(sub)
    _add_artifact(sub)
    _add_knowledge(sub)
    _add_design(sub)
    _add_mcp(sub)
    _add_research(sub)
    _add_guard(sub)
    _add_swarm(sub)
    _add_session(sub)
    _add_skills(sub)
    _add_flash(sub)
    _add_goal(sub)
    _add_build(sub)
    _add_route(sub)
    _add_code(sub)
    _add_prompt(sub)
    _add_re(sub)
    _add_docs(sub)
    _add_test(sub)
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


def _parse_cli_args(parser: argparse.ArgumentParser, argv: list[str]) -> argparse.Namespace:
    if any(h in argv for h in ("-h", "--help")):
        return parser.parse_args(argv)
    sub_action = next((a for a in parser._actions if isinstance(a, argparse._SubParsersAction)), None)
    if sub_action is not None:
        prefix: list[str] = []
        i = 0
        while i < len(argv):
            tok = argv[i]
            if tok == "--json":
                prefix.append(tok)
                i += 1
            elif tok in ("--db", "--flash-base") and i + 1 < len(argv):
                prefix.extend([tok, argv[i + 1]])
                i += 2
            elif tok.startswith("--db=") or tok.startswith("--flash-base="):
                prefix.append(tok)
                i += 1
            else:
                break
        if i < len(argv) and argv[i] in sub_action.choices:
            noun = argv[i]
            sub_p = sub_action.choices[noun]
            root_ns = parser.parse_args(prefix)
            sub_argv: list[str] = []
            j = i + 1
            opt_map = getattr(sub_p, "_option_string_actions", {})
            while j < len(argv):
                t = argv[j]
                act = opt_map.get(t)
                if act is not None and act.nargs != 0 and j + 1 < len(argv) and argv[j + 1].startswith("-"):
                    sub_argv.append(f"{t}={argv[j + 1]}")
                    j += 2
                else:
                    sub_argv.append(t)
                    j += 1
            sub_ns = sub_p.parse_intermixed_args(sub_argv)
            merged = argparse.Namespace(**vars(root_ns))
            merged.noun = noun
            for k, v in vars(sub_ns).items():
                setattr(merged, k, v)
            return merged
    return parser.parse_args(argv)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Shortcut: `xtforge --meta` or `xt-forge --meta` launches the sub-1KB MCP gateway directly.
    if "--meta" in argv and (not argv or argv[0].startswith("-")):
        argv = ["mcp", "serve"] + argv
    # --json is documented as global but argparse binds it to the root parser
    # only, so "xtforge version --json" used to fail. Accept it anywhere.
    force_json = len(argv) > 1 and "--json" in argv[1:]
    if force_json:
        argv = [argv[0]] + [a for a in argv[1:] if a != "--json"]
    parser = build_parser()
    args = _parse_cli_args(parser, argv)
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
