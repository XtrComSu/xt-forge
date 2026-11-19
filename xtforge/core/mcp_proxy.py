"""Python fallback for MCP audit, probe, connect, and audit-and-compress proxy."""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

from .call_journal import run_recoverable_upstream_call
from .compress import clip_or_spill
from .mcp_audit import evaluate_tools
from .mcp_registry import (
    _read_rpc_by_id,
    canonical_upstream_name,
    close_subprocess,
    load_upstreams,
    resolve_upstream_cmd,
    save_cached_catalog,
    save_upstream,
    split_cmd,
)
from .route import guard


class PythonUpstreamSession:
    """Persistent stdio JSON-RPC session to one external MCP server."""

    def __init__(self, name: str, argv: list[str], timeout: float | None = None) -> None:
        self.name = canonical_upstream_name(name)
        self.argv = argv
        if timeout is None:
            env_to = os.environ.get("XT_MCP_TIMEOUT", "").strip()
            timeout = float(env_to) if env_to.isdigit() and int(env_to) > 0 else 45.0
        self.timeout = timeout
        self.proc: subprocess.Popen[str] | None = None
        self.next_id = 1
        self.tools: list[dict[str, Any]] = []
        self._dirty = False
        self._write_lock = threading.Lock()
        self._call_lock = threading.Lock()
        self._lines: queue.Queue[str | None] = queue.Queue()

    def _read_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                self._lines.put(line)
        except Exception:
            pass
        finally:
            self._lines.put(None)

    def start(self) -> None:
        resolved = shutil.which(self.argv[0]) or self.argv[0]
        if not os.path.exists(resolved):
            raise FileNotFoundError(f"upstream binary not found: {self.argv[0]}")
        env = os.environ.copy()
        saved = load_upstreams()
        entry = saved.get(self.name) or {}
        if isinstance(entry.get("env"), dict):
            for k, v in entry["env"].items():
                env[str(k)] = str(v)
        self.proc = subprocess.Popen(
            [resolved, *self.argv[1:]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
            env=env,
        )
        threading.Thread(target=self._read_loop, daemon=True).start()
        init_res, _, _, _ = self._call("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "xt-forge-proxy", "version": "0.4.3"},
        })
        if "error" in init_res:
            raise RuntimeError(str(init_res["error"]))
        assert self.proc.stdin is not None
        with self._write_lock:
            self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            self.proc.stdin.flush()
        self.refresh_tools()

    def send_cancel(self, request_id: int, reason: str = "") -> bool:
        if self.proc is None or self.proc.stdin is None or request_id <= 0:
            return False
        params: dict[str, Any] = {"requestId": request_id}
        if reason:
            params["reason"] = reason
        try:
            with self._write_lock:
                self.proc.stdin.write(json.dumps({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": params,
                }) + "\n")
                self.proc.stdin.flush()
            return True
        except OSError:
            return False

    def _call(
        self,
        method: str,
        params: dict[str, Any],
        *,
        cancel_event: threading.Event | None = None,
    ) -> tuple[dict[str, Any], int, bool, bool]:
        assert self.proc is not None and self.proc.stdin is not None
        if cancel_event is not None and cancel_event.is_set():
            return {"error": f"request cancelled before dispatch ({method})"}, 0, False, False

        with self._call_lock:
            if cancel_event is not None and cancel_event.is_set():
                return {"error": f"request cancelled before dispatch ({method})"}, 0, False, False
            rid = self.next_id
            self.next_id += 1
            req = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
            try:
                with self._write_lock:
                    self.proc.stdin.write(json.dumps(req) + "\n")
                    self.proc.stdin.flush()
            except OSError as exc:
                return {"error": f"write failed for {method}: {exc}"}, rid, False, False

            deadline = time.monotonic() + self.timeout
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    notified = self.send_cancel(rid, "caller cancelled")
                    return {"error": f"cancelled waiting for {method}"}, rid, True, notified
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    notified = self.send_cancel(rid, f"upstream timeout waiting for {method}")
                    return {"error": f"timeout waiting for {method} from {self.name}"}, rid, True, notified
                try:
                    raw_line = self._lines.get(timeout=min(0.05, remaining))
                except queue.Empty:
                    continue
                if raw_line is None:
                    return {"error": f"EOF waiting for {method} from {self.name}"}, rid, True, False
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    msg = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("id") is None:
                    if msg.get("method") == "notifications/tools/list_changed":
                        self._dirty = True
                    continue
                if msg.get("id") == rid:
                    return msg, rid, True, False

    def refresh_tools(self) -> list[dict[str, Any]]:
        msg, _, _, _ = self._call("tools/list", {})
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

    def call_tool_detailed(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        cancel_event: threading.Event | None = None,
    ) -> tuple[Any, bool, int, bool, bool]:
        msg, rid, started, cancel_notified = self._call(
            "tools/call", {"name": tool_name, "arguments": arguments}, cancel_event=cancel_event,
        )
        if "error" in msg:
            return msg["error"], True, rid, started, cancel_notified
        if self._dirty or tool_name in ("enable_toolset", "disable_toolset"):
            try:
                self.refresh_tools()
            except Exception:
                pass
        return msg.get("result", {}), False, rid, started, cancel_notified

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
        res, is_err, _, _, _ = self.call_tool_detailed(tool_name, arguments)
        return res, is_err

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
            {"name": f"{pfx}_call", "description": f"Execute a tool on '{pfx}' with compression, spill, and journal recovery.",
             "inputSchema": {"type": "object", "properties": {
                 "tool": {"type": "string"}, "arguments": {"type": "object"},
                 "idempotency_key": {"type": "string"}, "verify_tool": {"type": "string"}, "verify_args": {"type": "object"},
             }, "required": ["tool"]}},
        ]
        out_lock = threading.Lock()
        active_lock = threading.Lock()
        active: dict[str, threading.Event] = {}
        workers: list[threading.Thread] = []

        def _write(obj: dict[str, Any]) -> None:
            with out_lock:
                sys.stdout.write(json.dumps(obj) + "\n")
                sys.stdout.flush()

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
                with active_lock:
                    for ev in active.values():
                        ev.set()
                break
            if rid is None:
                if method == "notifications/cancelled":
                    cid = str((req.get("params") or {}).get("requestId", ""))
                    with active_lock:
                        if cid in active:
                            active[cid].set()
                continue
            if method == "initialize":
                resp = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": f"xtforge-proxy:{canon}", "version": "0.4.3"}}
            elif method == "tools/list":
                resp = {"tools": proxy_tools}
            elif method == "tools/call":
                params = req.get("params") or {}
                tname = str(params.get("name") or "")
                targs = params.get("arguments") or {}
                cancel_ev = threading.Event()
                key_id = str(rid)
                with active_lock:
                    active[key_id] = cancel_ev

                def _handle_call(req_id: Any = rid, kid: str = key_id, tn: str = tname, ta: dict[str, Any] = targs, ev: threading.Event = cancel_ev) -> None:
                    try:
                        tools_now = sess.get_tools()
                        is_err = False
                        if tn == f"{pfx}_search":
                            q = str(ta.get("query") or "").lower().strip()
                            lim = int(ta.get("limit") or 10)
                            hits = [
                                {"name": t.get("name"), "description": str(t.get("description", ""))[:140], "inputSchema": t.get("inputSchema")}
                                for t in tools_now
                                if not q or q in (str(t.get("name", "")) + " " + str(t.get("description", ""))).lower()
                            ][:lim]
                            out = clip_or_spill({"server": pfx, "total_tools": len(tools_now), "matches": hits})
                        elif tn == f"{pfx}_list":
                            off = int(ta.get("offset") or 0)
                            lim = int(ta.get("limit") or 30)
                            rows = [{"name": t.get("name"), "description": str(t.get("description", ""))[:100]} for t in tools_now[off:off + lim]]
                            out = {"server": pfx, "total": len(tools_now), "tools": rows}
                        elif tn == f"{pfx}_call":
                            target = str(ta.get("tool") or ta.get("name") or "")
                            call_args = ta.get("arguments") or {}
                            out, is_err = run_recoverable_upstream_call(
                                sess,
                                canon,
                                target,
                                call_args,
                                idempotency_key=str(ta.get("idempotency_key") or ""),
                                verify_tool=str(ta.get("verify_tool") or ""),
                                verify_args=ta.get("verify_args") if isinstance(ta.get("verify_args"), dict) else None,
                                cancel_event=ev,
                                clip_fn=clip_or_spill,
                            )
                        else:
                            out, is_err = {"ok": False, "err": f"unknown proxy tool: {tn}"}, True
                        if not ev.is_set():
                            _write({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "isError": is_err},
                            })
                    finally:
                        with active_lock:
                            active.pop(kid, None)

                th = threading.Thread(target=_handle_call, daemon=True)
                workers.append(th)
                th.start()
                continue
            elif method == "ping":
                resp = {}
            elif method == "shutdown":
                with active_lock:
                    for ev in active.values():
                        ev.set()
                resp = None
            else:
                _write({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"method not found: {method}"}})
                continue
            _write({"jsonrpc": "2.0", "id": rid, "result": resp})
        for w in workers:
            w.join(timeout=2.0)
        return 0
    finally:
        sess.close()
