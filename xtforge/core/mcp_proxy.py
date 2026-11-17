"""Python fallback for MCP audit-and-compress proxy (`mcp proxy`)."""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
from typing import Any

from .compress import clip_or_spill
from .mcp_audit import evaluate_tools
from .route import guard


def probe_child_tools(cmd: str) -> tuple[list[dict[str, Any]], str | None]:
    """Perform a single initialize + tools/list stdio handshake against a child MCP server."""
    argv = shlex.split(cmd)
    if not argv:
        return [], "empty command"
    reqs = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "xt-forge-proxy", "version": "0.4.0"}}}) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
    )
    try:
        proc = subprocess.run(argv, input=reqs, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], str(exc)

    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == 2 and isinstance(msg.get("result"), dict):
            return list(msg["result"].get("tools") or []), None
    return [], "child server returned no tools/list response"


def audit_child_server(server: str, cmd: str, *, trust_on_first: bool = False) -> dict[str, Any]:
    tools, err = probe_child_tools(cmd)
    if err:
        return {"ok": False, "server": server, "err": err, "engine": "python"}
    report = evaluate_tools(server, tools, trust_on_first=trust_on_first)
    guard.audit_log(tool="mcp.audit", args={"server": server}, outcome="ok" if report["ok"] else "flagged")
    return report


def serve_proxy_lite(server: str, cmd: str, *, trust_on_first: bool = False) -> int:
    """Minimal stdio 3-tool wrapper mirroring Go `ServeProxy` when Go hub isn't used."""
    report = audit_child_server(server, cmd, trust_on_first=trust_on_first)
    if not report.get("ok"):
        sys.stderr.write(json.dumps(report) + "\n")
        return 1
    tools, _ = probe_child_tools(cmd)
    proxy_tools = [
        {"name": "proxy_list_tools", "description": "List audited tools on the proxied server",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "proxy_call", "description": "Call an audited tool with compressed/spilled output",
         "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "arguments": {"type": "object"}}, "required": ["name"]}},
        {"name": "proxy_audit_status", "description": "Return SHA-256 trust & finding status",
         "inputSchema": {"type": "object", "properties": {}}},
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
        if method == "initialize":
            resp = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                    "serverInfo": {"name": f"xtforge-proxy:{server}", "version": "0.4.0"}}
        elif method == "tools/list":
            resp = {"tools": proxy_tools}
        elif method == "tools/call":
            tname = (req.get("params") or {}).get("name", "")
            if tname == "proxy_list_tools":
                out = clip_or_spill({"tools": tools})
            elif tname == "proxy_audit_status":
                out = report
            else:
                out = {"ok": False, "err": "live child forwarding requires xtforge-hub; inspected manifest only"}
            resp = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}]}
        elif rid is None:
            continue
        else:
            resp = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": resp}) + "\n")
        sys.stdout.flush()
    return 0
