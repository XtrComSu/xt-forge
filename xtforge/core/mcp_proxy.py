"""Python fallback for MCP audit, probe, connect, and audit-and-compress proxy."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Any

from .compress import clip_or_spill
from .mcp_audit import evaluate_tools
from .mcp_registry import (
    _read_rpc_by_id,
    canonical_upstream_name,
    close_subprocess,
    resolve_upstream_cmd,
    save_cached_catalog,
    save_upstream,
    split_cmd,
)
from .route import guard


class PythonUpstreamSession:
    """Persistent stdio JSON-RPC session to one external MCP server."""

    def __init__(self, name: str, argv: list[str], timeout: float = 45.0) -> None:
        self.name = canonical_upstream_name(name)
        self.argv = argv
        self.timeout = timeout
        self.proc: subprocess.Popen[str] | None = None
        self.next_id = 1
        self.tools: list[dict[str, Any]] = []
        self._dirty = False

    def start(self) -> None:
        resolved = shutil.which(self.argv[0]) or self.argv[0]
        if not os.path.exists(resolved):
            raise FileNotFoundError(f"upstream binary not found: {self.argv[0]}")
        self.proc = subprocess.Popen(
            [resolved, *self.argv[1:]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
        init_res = self._call("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "xt-forge-proxy", "version": "0.4.0"},
        })
        if "error" in init_res:
            raise RuntimeError(str(init_res["error"]))
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()
        self.refresh_tools()

    def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert self.proc is not None and self.proc.stdin is not None and self.proc.stdout is not None
        rid = self.next_id
        self.next_id += 1
        req = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        msg, changed = _read_rpc_by_id(self.proc.stdout, rid, time.monotonic() + self.timeout)
        if changed:
            self._dirty = True
        if msg is None:
            return {"error": f"timeout or EOF waiting for {method} from {self.name}"}
        return msg

    def refresh_tools(self) -> list[dict[str, Any]]:
        msg = self._call("tools/list", {})
        if "error" in msg:
            raise RuntimeError(str(msg["error"]))
        tools = list((msg.get("result") or {}).get("tools") or [])
        self.tools = tools
        self._dirty = False
        save_cached_catalog(self.name, tools)
        return tools

    def get_tools(self) -> list[dict[str, Any]]:
        if self._dirty:
            try:
                return self.refresh_tools()
            except Exception:
                pass
        return self.tools

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
        msg = self._call("tools/call", {"name": tool_name, "arguments": arguments})
        if "error" in msg:
            return msg["error"], True
        if self._dirty or tool_name in ("enable_toolset", "disable_toolset"):
            try:
                self.refresh_tools()
            except Exception:
                pass
        return msg.get("result", {}), False

    def close(self) -> None:
        close_subprocess(self.proc)
        self.proc = None


def probe_child_tools(cmd: str | list[str], server_name: str = "child", timeout: float = 30.0) -> tuple[list[dict[str, Any]], str | None]:
    """Perform initialize -> notifications/initialized -> tools/list against a child MCP server."""
    argv = list(cmd) if isinstance(cmd, list) else split_cmd(cmd)
    if not argv:
        return [], "empty command"
    sess = PythonUpstreamSession(server_name, argv, timeout=timeout)
    try:
        sess.start()
        return sess.tools, None
    except Exception as exc:
        return [], str(exc)
    finally:
        sess.close()


def audit_child_server(server: str, cmd: str | list[str] | None = None, *, trust_on_first: bool = False) -> dict[str, Any]:
    explicit = " ".join(cmd) if isinstance(cmd, list) else cmd
    canon, argv, err = resolve_upstream_cmd(server, explicit_cmd=explicit)
    if err or not argv:
        return {"ok": False, "server": canon, "err": err or "missing command", "engine": "python"}
    tools, probe_err = probe_child_tools(argv, server_name=canon)
    if probe_err:
        return {"ok": False, "server": canon, "err": probe_err, "engine": "python"}
    report = evaluate_tools(canon, tools, trust_on_first=trust_on_first)
    guard.audit_log(tool="mcp.audit", args={"server": canon}, outcome="ok" if report["ok"] else "flagged")
    return report


def connect_server(server: str, cmd: str | None = None) -> dict[str, Any]:
    """Resolve, handshake, audit/pin, save to $XT_HOME/mcp_upstreams.json, and cache tools."""
    canon, argv, err = resolve_upstream_cmd(server, explicit_cmd=cmd)
    if err or not argv:
        return {"ok": False, "server": canon, "err": err or "missing command", "engine": "python"}
    tools, probe_err = probe_child_tools(argv, server_name=canon)
    if probe_err:
        return {"ok": False, "server": canon, "err": probe_err, "engine": "python"}
    report = evaluate_tools(canon, tools, trust_on_first=True)
    if not report.get("ok"):
        return {**report, "ok": False}
    save_upstream(canon, argv, source="connect")
    save_cached_catalog(canon, tools)
    return {
        "ok": True,
        "server": canon,
        "command": argv,
        "status": "trusted",
        "sha256": report["sha256"],
        "tool_count": len(tools),
        "engine": "python",
    }


def _is_mutating_tool(name: str) -> bool:
    low = name.lower()
    return any(k in low for k in ("write", "delete", "remove", "patch", "modify", "update_", "install", "uninstall", "exec", "sign_in", "sign_out", "rebuild"))


def serve_proxy_lite(server: str, cmd: str | None = None, *, trust_on_first: bool = False, prefix: str | None = None) -> int:
    """Persistent stdio 3-tool proxy mirroring Go `ServeProxy` when Go hub isn't used."""
    canon, argv, err = resolve_upstream_cmd(server, explicit_cmd=cmd)
    if err or not argv:
        sys.stderr.write(json.dumps({"ok": False, "err": err}) + "\n")
        return 1
    pfx = (prefix or canon.replace("-", "_")) or "proxy"
    sess = PythonUpstreamSession(canon, argv)
    try:
        sess.start()
    except Exception as exc:
        sys.stderr.write(json.dumps({"ok": False, "err": str(exc)}) + "\n")
        return 1

    try:
        report = evaluate_tools(canon, sess.tools, trust_on_first=trust_on_first)
        if not report.get("ok"):
            sys.stderr.write(json.dumps(report) + "\n")
            return 1
        proxy_tools = [
            {"name": f"{pfx}_search", "description": f"Search {len(sess.tools)} tools on proxied MCP server '{pfx}' by keyword.",
             "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["query"]}},
            {"name": f"{pfx}_list", "description": f"List tool names and summaries on proxied MCP server '{pfx}'.",
             "inputSchema": {"type": "object", "properties": {"offset": {"type": "integer"}, "limit": {"type": "integer"}}}},
            {"name": f"{pfx}_call", "description": f"Execute a tool on '{pfx}' with automatic compression and artifact spilling.",
             "inputSchema": {"type": "object", "properties": {"tool": {"type": "string"}, "arguments": {"type": "object"}}, "required": ["tool"]}},
        ]
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                req = json.loads(raw)
            except json.JSONDecodeError:
                continue
            rid = req.get("id")
            method = req.get("method", "")
            if method == "exit":
                break
            if rid is None:
                continue
            if method == "initialize":
                resp = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": f"xtforge-proxy:{canon}", "version": "0.4.0"}}
            elif method == "tools/list":
                resp = {"tools": proxy_tools}
            elif method == "tools/call":
                params = req.get("params") or {}
                tname = str(params.get("name") or "")
                targs = params.get("arguments") or {}
                tools_now = sess.get_tools()
                is_err = False
                if tname == f"{pfx}_search":
                    q = str(targs.get("query") or "").lower().strip()
                    lim = int(targs.get("limit") or 10)
                    hits = [
                        {"name": t.get("name"), "description": str(t.get("description", ""))[:140], "inputSchema": t.get("inputSchema")}
                        for t in tools_now
                        if not q or q in (str(t.get("name", "")) + " " + str(t.get("description", ""))).lower()
                    ][:lim]
                    out = clip_or_spill({"server": pfx, "total_tools": len(tools_now), "matches": hits})
                elif tname == f"{pfx}_list":
                    off = int(targs.get("offset") or 0)
                    lim = int(targs.get("limit") or 30)
                    rows = [{"name": t.get("name"), "description": str(t.get("description", ""))[:100]} for t in tools_now[off:off + lim]]
                    out = {"server": pfx, "total": len(tools_now), "tools": rows}
                elif tname == f"{pfx}_call":
                    target = str(targs.get("tool") or targs.get("name") or "")
                    call_args = targs.get("arguments") or {}
                    if os.environ.get("XT_PERM_MODE", "").lower() == "explore" and _is_mutating_tool(target):
                        out, is_err = {"ok": False, "err": f"denied: XT_PERM_MODE=explore forbids {target}"}, True
                    else:
                        res, is_err = sess.call_tool(target, call_args)
                        out = clip_or_spill(res)
                else:
                    out, is_err = {"ok": False, "err": f"unknown proxy tool: {tname}"}, True
                resp = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "isError": is_err}
            elif method == "ping":
                resp = {}
            elif method == "shutdown":
                resp = None
            else:
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}}) + "\n")
                sys.stdout.flush()
                continue
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": resp}) + "\n")
            sys.stdout.flush()
        return 0
    finally:
        sess.close()
