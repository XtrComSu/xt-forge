#!/usr/bin/env python3
"""xt-forge MCP server (stdio, newline-delimited JSON-RPC 2.0).

The 0.3.0 portable snapshot shipped `xtforge/` but excluded `adapters/`, so
the server referenced by `xtforge/adapters/sync.py` is restored here. It
exposes the CLI surface as MCP tools by invoking the Python reference
implementation (`python3 -m xtforge.cli`) in this repo.

Wire it into a harness with a local MCP entry:

    {"type": "local",
     "command": ["/usr/bin/python3", "<repo>/adapters/mcp/server.py"],
     "environment": {"XT_HOME": "<home>/.xt-forge"}}

Only JSON-RPC goes to stdout; diagnostics go to stderr.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TIMEOUT = 120
PROTOCOL_FALLBACK = "2025-06-18"


# ---------------------------------------------------------------- CLI bridge

def _env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("XT_HOME", str(Path.home() / ".xt-forge"))
    pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + pythonpath if pythonpath else "")
    return env


def _run(argv: list[str], stdin_text: str | None = None,
         timeout: int = DEFAULT_TIMEOUT) -> tuple[str, bool]:
    """Run one CLI command with --json and return (text, is_error)."""
    cmd = [sys.executable, "-m", "xtforge.cli", *argv, "--json"]
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), env=_env(), input=stdin_text,
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"xt-forge timed out after {timeout}s", True
    except OSError as exc:
        return f"cannot launch xt-forge: {exc}", True

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    payload: Any = None
    if stdout:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = stdout
    if payload is None:
        payload = stderr or "(no output)"
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    if stderr and proc.returncode != 0 and stderr not in text:
        text = f"{text}\n\nstderr:\n{stderr}"
    return text, proc.returncode != 0


# ------------------------------------------------------------ tool helpers

def _str(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if value is None:
        raise ValueError(f"missing required argument: {key}")
    return str(value)


def _opt(args: dict[str, Any], key: str, flag: str | None = None) -> list[str]:
    value = args.get(key)
    if value is None or value is False or value == "":
        return []
    if value is True:
        return [flag or f"--{key.replace('_', '-')}"]
    return [flag or f"--{key.replace('_', '-')}", str(value)]


def _tags(args: dict[str, Any], key: str = "tags") -> list[str]:
    out: list[str] = []
    for tag in args.get(key) or []:
        out.extend(["--tag", str(tag)])
    return out


def _paths(args: dict[str, Any], key: str = "roots") -> list[str]:
    out: list[str] = []
    for path in args.get(key) or []:
        out.extend(["--paths", str(path)])
    return out


def _tool(name: str, description: str, properties: dict[str, Any],
          required: list[str], build: Any, stdin: Any = None,
          timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties,
                        "required": required, "additionalProperties": False},
        "build": build,
        "stdin": stdin,
        "timeout": timeout,
    }


_TEXT = {"type": "string"}
_INT = {"type": "integer"}
_BOOL = {"type": "boolean"}
_OBJ = {"type": "object"}
_TAGS = {"type": "array", "items": {"type": "string"}}


# -------------------------------------------------------------- tool table

TOOLS: list[dict[str, Any]] = [
    # search & recall ---------------------------------------------------
    _tool(
        "search",
        "Federated search across codebase files, durable memories, knowledge base, web (Google SERP/SearXNG), CVE security intelligence, and external tools.",
        {"query": _TEXT, "path": _TEXT, "web": _BOOL, "cve": _BOOL, "tools": _BOOL, "all": _BOOL, "limit": _INT, "stores": _TEXT},
        ["query"],
        lambda a: ["search", _str(a, "query"),
                   *([a["path"]] if a.get("path") else []),
                   *_opt(a, "web", "--web"),
                   *_opt(a, "cve", "--cve"),
                   *_opt(a, "tools", "--tools"),
                   *_opt(a, "all", "--all"),
                   *_opt(a, "limit", "--limit"),
                   *_opt(a, "stores", "--stores")],
    ),
    _tool(
        "recall",
        "Unified cross-store query across memory, recon findings, flash notes, and artifacts.",
        {"query": _TEXT, "store": _TEXT, "k": _INT, "limit": _INT},
        ["query"],
        lambda a: ["recall", _str(a, "query"),
                   *_opt(a, "store", "--store"),
                   *_opt(a, "k", "--k"),
                   *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "tool_call",
        "Dispatch an on-demand external MCP tool (cad3d/OpenSCAD, photoeditor, glmocr, searchd) without mounting it permanently.",
        {"server": _TEXT, "tool": _TEXT, "arguments": _OBJ},
        ["server", "tool"],
        lambda a: ["tool", "run", _str(a, "server"), _str(a, "tool"),
                   *([json.dumps(a["arguments"])] if a.get("arguments") else [])],
    ),
    # mem ---------------------------------------------------------------
    _tool(
        "mem_put",
        "Store a durable memory record (fact, error pattern, decision, ...).",
        {"body": _TEXT, "title": _TEXT, "scope": _TEXT, "kind": _TEXT,
         "tags": _TAGS, "source": _TEXT, "confidence": {"type": "number"}},
        ["body"],
        lambda a: ["mem", "put", "--body-file", "-",
                   *_opt(a, "scope", "--scope"), *_opt(a, "kind", "--kind"),
                   *_opt(a, "title", "--title"), *_tags(a),
                   *_opt(a, "source", "--source"),
                   *_opt(a, "confidence", "--confidence")],
        stdin=lambda a: a["body"],
    ),
    _tool(
        "mem_get",
        "Fetch one memory record by id.",
        {"id": _TEXT}, ["id"],
        lambda a: ["mem", "get", "--id", _str(a, "id")],
    ),
    _tool(
        "mem_search",
        "BM25 + recency search across the shared memory store.",
        {"query": _TEXT, "k": _INT, "budget": _INT, "kind": _TEXT,
         "explain": _BOOL},
        ["query"],
        lambda a: ["mem", "search", "--query", _str(a, "query"),
                   *_opt(a, "k", "--k"), *_opt(a, "budget", "--budget"),
                   *_opt(a, "kind", "--kind"), *_opt(a, "explain", "--explain")],
    ),
    _tool(
        "mem_list",
        "List recent memory records.",
        {"scope": _TEXT, "limit": _INT, "kind": _TEXT}, [],
        lambda a: ["mem", "list", *_opt(a, "scope", "--scope"),
                   *_opt(a, "limit", "--k"), *_opt(a, "kind", "--kind")],
    ),
    _tool(
        "mem_forget",
        "Delete a memory record by id.",
        {"id": _TEXT}, ["id"],
        lambda a: ["mem", "forget", "--id", _str(a, "id")],
    ),
    _tool(
        "mem_review",
        "List pending memory records awaiting review.",
        {"limit": _INT}, [],
        lambda a: ["mem", "review", *_opt(a, "limit", "--k")],
    ),
    _tool(
        "mem_export",
        "Export memory records to JSONL (default path: all scopes).",
        {"path": _TEXT, "scope": _TEXT}, ["path"],
        lambda a: ["mem", "export", _str(a, "path"),
                   *_opt(a, "scope", "--scope")],
    ),
    _tool(
        "mem_import",
        "Import memory records from a JSONL file.",
        {"path": _TEXT}, ["path"],
        lambda a: ["mem", "import", _str(a, "path")],
    ),
    _tool(
        "mem_sync",
        "Union-merge memory records from a JSONL file.",
        {"path": _TEXT, "conflicts": _TEXT}, ["path"],
        lambda a: ["mem", "sync", _str(a, "path"),
                   *_opt(a, "conflicts", "--conflicts")],
    ),
    # flash -------------------------------------------------------------
    _tool(
        "flash_set",
        "Write a flash note (#tags, optional TTL). Sub-50ms key/value store.",
        {"text": _TEXT, "key": _TEXT, "scope": _TEXT, "tags": _TAGS,
         "ttl": _INT},
        ["text"],
        # The CLI takes ONE positional: either "TEXT" or "KEY=TEXT". Passing a
        # second positional key silently mis-parsed (the key was stored as a
        # GLB flag the last time this happened). Build "KEY=TEXT" here.
        lambda a: ["flash", "set",
                   (f"{_str(a, 'key')}=" if a.get("key") else "") + _str(a, "text"),
                   *_opt(a, "scope", "--scope"),
                   *_tags(a), *_opt(a, "ttl", "--ttl")],
    ),
    _tool(
        "flash_get",
        "Read a flash note by key (falls back to fuzzy hits).",
        {"key": _TEXT, "scope": _TEXT}, ["key"],
        lambda a: ["flash", "get", _str(a, "key"),
                   *_opt(a, "scope", "--scope")],
    ),
    _tool(
        "flash_list",
        "List recent flash notes.",
        {"scope": _TEXT, "n": _INT, "pin_only": _BOOL}, [],
        lambda a: ["flash", "list", *_opt(a, "scope", "--scope"),
                   *_opt(a, "n", "--n"), *_opt(a, "pin_only", "--pin-only")],
    ),
    _tool(
        "flash_pin",
        "Pin or unpin a flash note.",
        {"key": _TEXT, "scope": _TEXT}, ["key"],
        lambda a: ["flash", "pin", _str(a, "key"),
                   *_opt(a, "scope", "--scope")],
    ),
    _tool(
        "flash_delete",
        "Delete a flash note, or clear a scope with a confirm token.",
        {"key": _TEXT, "scope": _TEXT, "all": _BOOL, "confirm": _TEXT}, [],
        lambda a: ["flash", "delete",
                   *([] if a.get("all") else [_str(a, "key")]),
                   *_opt(a, "all", "--all"), *_opt(a, "scope", "--scope"),
                   *_opt(a, "confirm", "--confirm")],
    ),
    _tool(
        "flash_compact",
        "Compact a flash scope and report the result.",
        {"scope": _TEXT}, [],
        lambda a: ["flash", "compact", *_opt(a, "scope", "--scope")],
    ),
    # route -------------------------------------------------------------
    _tool(
        "route_tree",
        "Bounded directory tree (depth/max limits, token-capped).",
        {"path": _TEXT, "depth": _INT, "max": _INT}, [],
        lambda a: ["route", "tree", a.get("path") or ".",
                   *_opt(a, "depth", "--depth"), *_opt(a, "max", "--max")],
    ),
    _tool(
        "route_find",
        "Find files by name, regex, type or minimum size.",
        {"path": _TEXT, "name": _TEXT, "regex": _TEXT, "type": _TEXT,
         "min_size": _INT, "limit": _INT}, [],
        lambda a: ["route", "find", a.get("path") or ".",
                   *_opt(a, "name", "--name"), *_opt(a, "regex", "--regex"),
                   *_opt(a, "type", "--type"),
                   *_opt(a, "min_size", "--min-size"),
                   *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "route_grep",
        "Grep source files with bounded context and result count.",
        {"pattern": _TEXT, "path": _TEXT, "glob": _TEXT, "context": _INT,
         "limit": _INT},
        ["pattern"],
        lambda a: ["route", "grep", a.get("path") or ".",
                   "--pattern", _str(a, "pattern"),
                   *_opt(a, "glob", "--glob"),
                   *_opt(a, "context", "--context"),
                   *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "route_peek",
        "Read a file window (head/tail/range) without dumping the whole file.",
        {"path": _TEXT, "mode": _TEXT, "start": _INT, "count": _INT},
        ["path"],
        lambda a: ["route", "peek", _str(a, "path"),
                   *_opt(a, "mode", "--mode"), *_opt(a, "start", "--start"),
                   *_opt(a, "count", "--count")],
    ),
    _tool(
        "route_du",
        "Report the largest entries under a path.",
        {"path": _TEXT, "top": _INT}, [],
        lambda a: ["route", "du", a.get("path") or ".",
                   *_opt(a, "top", "--top")],
    ),
    _tool(
        "route_recent",
        "List files modified within the last N minutes.",
        {"roots": _TAGS, "minutes": _INT, "limit": _INT}, [],
        lambda a: ["route", "recent", *(_paths(a) or ["."]),
                   *_opt(a, "minutes", "--minutes"),
                   *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "route_where",
        "Locate a filename under the allowlisted roots.",
        {"name": _TEXT, "limit": _INT}, ["name"],
        lambda a: ["route", "where", _str(a, "name"),
                   *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "route_context",
        "Pack a directory into a token-budgeted context packet.",
        {"path": _TEXT, "token_budget": _INT, "file_limit": _INT}, [],
        lambda a: ["route", "context", a.get("path") or ".",
                   *_opt(a, "token_budget", "--token-budget"),
                   *_opt(a, "file_limit", "--file-limit")],
    ),
    _tool(
        "route_errors",
        "Extract error-bearing lines from a file or directory.",
        {"path": _TEXT, "max_lines": _INT, "token_budget": _INT}, [],
        lambda a: ["route", "errors", a.get("path") or "",
                   *_opt(a, "max_lines", "--max-lines"),
                   *_opt(a, "token_budget", "--token-budget")],
    ),
    # compress ----------------------------------------------------------
    _tool(
        "compress",
        "L0-L3 squeezer for tool output; never drops error lines.",
        {"text": _TEXT, "level": _TEXT, "stats": _BOOL, "legend": _BOOL},
        ["text"],
        lambda a: ["compress", a.get("level") or "L1", "--text", _str(a, "text"),
                   *_opt(a, "stats", "--stats"), *_opt(a, "legend", "--legend")],
    ),
    # taste -------------------------------------------------------------
    _tool(
        "taste_learn",
        "Record a preference as taste evidence (deterministic learner, no "
        "LLM). Confidence rises with supporting evidence and a contradiction "
        "marks the learning 'conflict' instead of overwriting it.",
        {"statement": _TEXT, "scope": _TEXT, "source": _TEXT}, ["statement"],
        lambda a: ["taste", "learn", "--body-file", "-",
                   *_opt(a, "scope", "--scope"), *_opt(a, "source", "--source")],
        stdin=lambda a: a["statement"],
    ),
    _tool(
        "taste_search",
        "Search learned preferences by text, category or status.",
        {"query": _TEXT, "category": _TEXT, "status": _TEXT, "limit": _INT},
        [],
        lambda a: (["taste", "search", str(a["query"])]
                   if a.get("query") else ["taste", "search"]) +
                  [*_opt(a, "category", "--category"),
                   *_opt(a, "status", "--status"),
                   *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "taste_show",
        "Show one learning with its evidence log and confidence arithmetic.",
        {"id": _TEXT}, ["id"],
        lambda a: ["taste", "show", "--id", _str(a, "id")],
    ),
    _tool(
        "taste_review",
        "List conflicts and weak hints: what a human should look at.",
        {"limit": _INT}, [],
        lambda a: ["taste", "review", *_opt(a, "limit", "--limit")],
    ),
    _tool(
        "taste_export",
        "Export taste as markdown packages (one file per category).",
        {"path": _TEXT, "scope": _TEXT}, ["path"],
        lambda a: ["taste", "export", "--path", _str(a, "path"),
                   *_opt(a, "scope", "--scope")],
    ),
    _tool(
        "taste_stats",
        "Taste profile summary: totals, statuses, categories.",
        {}, [], lambda a: ["taste", "stats"],
    ),
    # meta --------------------------------------------------------------
    _tool("version", "Report xt-forge version, codename and XT_HOME.",
          {}, [], lambda a: ["version"]),
    _tool("doctor", "Environment probe and integration diagnostics.",
          {}, [], lambda a: ["doctor"]),
    _tool("tools_status", "Detect external binaries with install hints.",
          {}, [], lambda a: ["tools", "status"]),
    _tool(
        "calibrate",
        "Reboot recalibration: WAL checkpoint, expiry purge, caps reprobe.",
        {"status": _BOOL, "force": _BOOL}, [],
        lambda a: ["calibrate", *_opt(a, "status", "--status"),
                   *_opt(a, "force", "--force")],
    ),
    _tool(
        "slash",
        "Run an xt-forge slash command (/m /mg /ml /mp /mx /mc /mw /mu /help).",
        {"text": _TEXT}, ["text"],
        lambda a: ["slash", _str(a, "text")],
    ),
    _tool(
        "ascii",
        "Render an XT-Forge ASCII banner.",
        {"style": _TEXT}, [],
        lambda a: ["ascii", a.get("style") or "signal"],
    ),
    # goal --------------------------------------------------------------
    _tool(
        "goal_status",
        "Report the latest (or a named) bounded goal run.",
        {"run_id": _TEXT}, [],
        lambda a: ["goal", "status", *_opt(a, "run_id", "--run-id")],
    ),
    _tool(
        "goal_run",
        "Start a bounded goal loop; requires a configured harness driver.",
        {"objective": _TEXT, "rounds": _INT, "criteria": _TAGS,
         "verify": _TEXT, "budget_tokens": _INT},
        ["objective"],
        lambda a: ["goal", "run", _str(a, "objective"),
                   *_opt(a, "rounds", "--rounds"),
                   *_opt(a, "criteria", "--criteria"),
                   *_opt(a, "verify", "--verify"),
                   *_opt(a, "budget_tokens", "--budget-tokens")],
    ),
    _tool(
        "goal_verify",
        "Independently verify a <goal-done> completion claim. Replays "
        "approved commands, checks claimed files, and rejects unproven 'done' "
        "claims. An unapproved command is never executed and is not proof.",
        {"marker": _TEXT, "criteria": _TEXT, "approved_cmd": _TAGS,
         "verify_cmd": _TEXT, "workdir": _TEXT},
        ["marker"],
        lambda a: ["goal", "verify", "--body-file", "-",
                   *_opt(a, "criteria", "--criteria"),
                   *_opt(a, "verify_cmd", "--verify"),
                   *_opt(a, "workdir", "--workdir"),
                   *sum((["--approved-cmd", str(cmd)]
                         for cmd in (a.get("approved_cmd") or [])), [])],
        stdin=lambda a: a["marker"],
    ),
    # build -------------------------------------------------------------
    _tool("build_list", "List build workflows.",
          {}, [], lambda a: ["build", "list"]),
    _tool(
        "build_status",
        "Status of one build run.",
        {"workflow": _TEXT, "run_id": _TEXT, "workdir": _TEXT}, ["workflow"],
        lambda a: ["build", "status", _str(a, "workflow"),
                   *_opt(a, "run_id", "--run-id"),
                   *_opt(a, "workdir", "--workdir")],
    ),
    _tool(
        "build_run",
        "Run a build workflow (fake driver unless XT_BUILD_CMD is set).",
        {"workflow": _TEXT, "run_id": _TEXT, "workdir": _TEXT,
         "dry_run": _BOOL},
        ["workflow"],
        lambda a: ["build", "run", _str(a, "workflow"),
                   *_opt(a, "run_id", "--run-id"),
                   *_opt(a, "workdir", "--workdir"),
                   *_opt(a, "dry_run", "--dry-run")],
    ),
    _tool(
        "build_graph",
        "Render a workflow DAG as ASCII.",
        {"workflow": _TEXT}, ["workflow"],
        lambda a: ["build", "graph", _str(a, "workflow")],
    ),
    _tool(
        "build_lint",
        "Validate all workflows, or one spec file.",
        {"path": _TEXT}, [],
        lambda a: ["build", "lint", *_opt(a, "path", "--path")],
    ),
    # reverse engineering -----------------------------------------------
    _tool(
        "re_inspect",
        "Inspect binary structures: format headers, sections with entropy, imports, exports, or PE TLS callbacks.",
        {"path": _TEXT, "verb": {"type": "string", "enum": ["info", "sections", "symbols", "pe_info", "pe_sections", "pe_imports", "pe_exports", "pe_tls", "ioc"]}, "limit": _INT},
        ["path"],
        lambda a: (["re", "pe", a.get("verb", "info")[3:], _str(a, "path"), *_opt(a, "limit", "--limit")]
                   if a.get("verb", "").startswith("pe_")
                   else ["re", a.get("verb") or "info", _str(a, "path"), *_opt(a, "limit", "--limit")]),
    ),
    _tool(
        "re_cfg",
        "Reconstruct function basic block Control Flow Graph (CFG), block disassembly, or cross-references in token-bounded JSON.",
        {"path": _TEXT, "symbol": _TEXT, "rva": _TEXT, "engine": {"type": "string", "enum": ["auto", "builtin", "rizin"]},
         "max_instructions": _INT, "block_id": _TEXT, "target": _TEXT},
        ["path"],
        lambda a: (["re", "block", _str(a, "path"), "--block-id", _str(a, "block_id"),
                    *_opt(a, "symbol", "--symbol"), *_opt(a, "rva", "--rva"), *_opt(a, "engine", "--engine")]
                   if a.get("block_id")
                   else (["re", "xrefs", _str(a, "path"), "--target", _str(a, "target")]
                         if a.get("target")
                         else ["re", "cfg", _str(a, "path"),
                               *_opt(a, "symbol", "--symbol"), *_opt(a, "rva", "--rva"),
                               *_opt(a, "engine", "--engine"), *_opt(a, "max_instructions", "--max-instructions")])),
    ),
]

_TOOL_MAP = {tool["name"]: tool for tool in TOOLS}


# ------------------------------------------------------------- JSON-RPC core

class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _version() -> str:
    try:
        for line in (ROOT / "VERSION").read_text().splitlines():
            if line.startswith("version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "0.0.0"


def _send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    tool = _TOOL_MAP.get(name)
    if tool is None:
        raise RpcError(-32602, f"unknown tool: {name}")
    missing = [key for key in tool["inputSchema"]["required"]
               if arguments.get(key) in (None, "")]
    if missing:
        raise RpcError(-32602, "missing required argument(s): " + ", ".join(missing))
    try:
        argv = tool["build"](arguments)
        stdin_text = tool["stdin"](arguments) if tool["stdin"] else None
    except ValueError as exc:
        raise RpcError(-32602, str(exc)) from exc
    text, is_error = _run(argv, stdin_text=stdin_text, timeout=tool["timeout"])
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


META_TOOLS = [
    {
        "name": "xt_discover",
        "description": "Search XT-Forge tools & CLI capabilities by keyword (~1.4KB gateway mode).",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "default": 12}},
        },
    },
    {
        "name": "xt_schema",
        "description": "Inspect the full JSON inputSchema for one named XT-Forge tool.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "xt_call",
        "description": "Execute any XT-Forge MCP tool or CLI subcommand through the meta-gateway.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "arguments": {"type": "object"},
                "argv": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "xt_batch",
        "description": "Run up to 10 XT-Forge calls in one round trip and return clipped/spilled results.",
        "inputSchema": {
            "type": "object",
            "properties": {"calls": {"type": "array", "items": {"type": "object"}}},
            "required": ["calls"],
        },
    },
]

_TOOL_MAP = {t["name"]: t for t in TOOLS}
_UPSTREAM_POOL: dict[str, Any] = {}


def _get_py_upstream(server: str):
    from xtforge.core.mcp_proxy import PythonUpstreamSession
    from xtforge.core.mcp_registry import canonical_upstream_name, resolve_upstream_cmd
    canon = canonical_upstream_name(server)
    sess = _UPSTREAM_POOL.get(canon)
    if sess is not None:
        return sess
    resolved, argv, err = resolve_upstream_cmd(canon)
    if err or not argv:
        raise RuntimeError(err or f"cannot resolve upstream: {server}")
    sess = PythonUpstreamSession(resolved, argv)
    sess.start()
    _UPSTREAM_POOL[resolved] = sess
    return sess


def _split_upstream_ref(raw: str) -> tuple[str, str] | None:
    if ":" not in raw:
        return None
    srv, tool = raw.split(":", 1)
    srv, tool = srv.strip(), tool.strip()
    if not srv or not tool:
        return None
    from xtforge.core.mcp_registry import canonical_upstream_name
    return canonical_upstream_name(srv), tool


def _handle_meta_call(name: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
    from xtforge.core.compress import clip_or_spill
    from xtforge.core.mcp_registry import (
        canonical_upstream_name,
        known_upstreams,
        load_cached_catalog,
    )
    if name == "xt_discover":
        q = str(arguments.get("query") or "").lower().strip()
        up_raw = str(arguments.get("upstream") or "").strip().lower()
        lim = int(arguments.get("limit") or 12)
        matches = []
        if up_raw in ("", "all", "xt-forge"):
            matches = [
                {"name": t["name"], "description": t["description"]}
                for t in TOOLS
                if not q or q in t["name"].lower() or q in t["description"].lower()
            ][:lim]
        upstream_matches = []
        if up_raw != "xt-forge":
            targets = [canonical_upstream_name(up_raw)] if up_raw not in ("", "all") else known_upstreams()
            for srv in targets:
                tools = load_cached_catalog(srv)
                if not tools and (up_raw not in ("", "all") or srv in q or (srv == "craft-anything" and "craft" in q)):
                    try:
                        tools = _get_py_upstream(srv).get_tools()
                    except Exception:
                        tools = []
                for t in tools:
                    hay = f"{srv} {t.get('name', '')} {t.get('description', '')}".lower()
                    if not q or all(w in hay for w in q.split()):
                        upstream_matches.append({
                            "name": f"{srv}:{t.get('name')}",
                            "upstream": srv,
                            "tool": t.get("name"),
                            "description": str(t.get("description", ""))[:140],
                        })
                        if len(upstream_matches) >= lim:
                            break
        return {"content": [{"type": "text", "text": json.dumps({
            "ok": True,
            "count": len(matches),
            "total_catalog": len(TOOLS),
            "tools": matches,
            "upstream_matches": upstream_matches[:lim],
            "known_upstreams": known_upstreams(),
        })}], "isError": False}
    if name == "xt_schema":
        tname = str(arguments.get("name") or "")
        ref = _split_upstream_ref(tname)
        if ref is not None:
            srv, tool_name = ref
            tools = load_cached_catalog(srv)
            if not tools:
                try:
                    tools = _get_py_upstream(srv).get_tools()
                except Exception as exc:
                    return {"content": [{"type": "text", "text": json.dumps({"ok": False, "err": str(exc)})}], "isError": True}
            for item in tools:
                if item.get("name") == tool_name:
                    return {"content": [{"type": "text", "text": json.dumps({
                        "ok": True, "upstream": srv, "name": f"{srv}:{tool_name}",
                        "tool": tool_name, "description": item.get("description", ""),
                        "inputSchema": item.get("inputSchema", {}),
                    })}], "isError": False}
            return {"content": [{"type": "text", "text": json.dumps({"ok": False, "err": f"unknown tool {tname}"})}], "isError": True}
        t = _TOOL_MAP.get(tname)
        if not t:
            return {"content": [{"type": "text", "text": json.dumps({"ok": False, "err": f"unknown tool: {tname}"})}], "isError": True}
        return {"content": [{"type": "text", "text": json.dumps({"ok": True, "tool": t})}], "isError": False}
    if name == "xt_call":
        target = str(arguments.get("name") or "")
        srv_arg = str(arguments.get("server") or "").strip()
        tool_arg = str(arguments.get("tool") or "").strip()
        call_args = arguments.get("arguments") or {}
        if srv_arg and tool_arg:
            try:
                res, is_err = _get_py_upstream(srv_arg).call_tool(tool_arg, call_args)
                return {"content": [{"type": "text", "text": json.dumps(clip_or_spill(res), ensure_ascii=False)}], "isError": is_err}
            except Exception as exc:
                return {"content": [{"type": "text", "text": json.dumps({"ok": False, "err": str(exc)})}], "isError": True}
        ref = _split_upstream_ref(target)
        if ref is not None:
            try:
                res, is_err = _get_py_upstream(ref[0]).call_tool(ref[1], call_args)
                return {"content": [{"type": "text", "text": json.dumps(clip_or_spill(res), ensure_ascii=False)}], "isError": is_err}
            except Exception as exc:
                return {"content": [{"type": "text", "text": json.dumps({"ok": False, "err": str(exc)})}], "isError": True}
        if target in _TOOL_MAP:
            return _call_tool(target, call_args)
        argv = list(arguments.get("argv") or [])
        if not argv and target:
            argv = target.split(".", 1) if "." in target else target.split(" ", 1)
        if argv:
            text, is_err = _run(_xtforge_cmd() + argv + ["--json"])
            return {"content": [{"type": "text", "text": text}], "isError": is_err}
        return {"content": [{"type": "text", "text": json.dumps({"ok": False, "err": f"unknown tool or empty argv: {target}"})}], "isError": True}
    if name == "xt_batch":
        calls = list(arguments.get("calls") or [])[:10]
        outs = []
        for c in calls:
            if isinstance(c, dict):
                res = _handle_meta_call("xt_call", c)
                txt = (res.get("content") or [{}])[0].get("text", "")
                outs.append(clip_or_spill({"output": txt, "isError": res.get("isError", False)}))
        return {"content": [{"type": "text", "text": json.dumps({"ok": True, "results": outs})}], "isError": False}
    raise RpcError(-32601, f"unknown meta tool: {name}")


def _handle(message: dict[str, Any], meta_mode: bool = False) -> dict[str, Any] | None:
    method = message.get("method")
    msg_id = message.get("id")
    if not isinstance(method, str) or msg_id is None:
        return None  # notification or client response: no reply
    if method == "initialize":
        params = message.get("params") or {}
        requested = params.get("protocolVersion")
        result = {
            "protocolVersion": requested if isinstance(requested, str)
            else PROTOCOL_FALLBACK,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "xt-forge" + ("-meta" if meta_mode else ""), "version": _version()},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        src = META_TOOLS if meta_mode else TOOLS
        result = {"tools": [{"name": tool["name"],
                             "description": tool["description"],
                             "inputSchema": tool["inputSchema"]}
                            for tool in src]}
    elif method == "tools/call":
        params = message.get("params") or {}
        if meta_mode:
            result = _handle_meta_call(params.get("name"), params.get("arguments") or {})
        else:
            result = _call_tool(params.get("name"), params.get("arguments") or {})
    elif method == "shutdown":
        result = None
    else:
        raise RpcError(-32601, f"method not found: {method}")
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main(argv: list[str] | None = None) -> int:
    cli_args = list(sys.argv[1:] if argv is None else argv)
    meta_mode = "--meta" in cli_args
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                _send({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(message, dict):
                continue
            if message.get("method") == "exit":
                break
            try:
                reply = _handle(message, meta_mode=meta_mode)
            except RpcError as exc:
                reply = {"jsonrpc": "2.0", "id": message.get("id"),
                         "error": {"code": exc.code, "message": exc.message}}
            except Exception as exc:  # never leak a traceback to stdout
                print(f"xt-forge mcp: {exc!r}", file=sys.stderr)
                reply = {"jsonrpc": "2.0", "id": message.get("id"),
                         "error": {"code": -32603, "message": "internal error"}}
            if reply is not None:
                _send(reply)
        return 0
    finally:
        for sess in list(_UPSTREAM_POOL.values()):
            try:
                sess.close()
            except Exception:
                pass
        _UPSTREAM_POOL.clear()


if __name__ == "__main__":
    raise SystemExit(main())
