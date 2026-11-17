"""Measure what an MCP server really costs the model.

Two numbers matter and they are not the same:

  * wire cost — the `tools/list` JSON a client receives
  * seen cost — what the model reads in its tool catalog on every request

For a directly mounted server they are equal. For a server behind the lite
proxy they diverge: the proxy holds a large catalog and shows the model four
small meta-tools, so probing the proxy measures the *seen* cost and tells you
nothing about the catalog it hides. That distinction is why this module
records which side of the proxy it talked to instead of reporting one number
and letting the caller guess.

Nothing here runs by default. Starting an MCP server is a process, sometimes a
network call and occasionally a bill, so it happens only under an explicit
`--probe`. Stdio servers are started exactly the way the harness would start
them, and always killed afterwards.

The transport is newline-delimited JSON-RPC 2.0 over stdio:
    -> initialize, then notifications/initialized, then tools/list
    <- one JSON object per line
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any

from .mcp import McpServer

#: Protocol revision this client speaks. Servers answer with their own; the
#: value only has to be one they recognise.
PROTOCOL_VERSION = "2025-06-18"

#: How long a single server may take to answer `tools/list`.
DEFAULT_TIMEOUT = 20.0


def _rpc(request_id: int, method: str, params: dict[str, Any] | None = None) -> str:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    return json.dumps(body) + "\n"


def _read_message(stream, deadline: float) -> dict[str, Any] | None:
    """Read one JSON-RPC object, skipping log noise on stdout.

    Servers are allowed to print to stderr, but some print banners to stdout
    as well; a line that is not JSON is skipped rather than fatal.
    """
    while time.monotonic() < deadline:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed):
            return parsed
        # A notification or a server-initiated request: not the answer we want.
        if isinstance(parsed, dict) and parsed.get("id") is None and "method" in parsed:
            continue
    return None


def probe_stdio(server: McpServer, timeout: float = DEFAULT_TIMEOUT
                ) -> dict[str, Any]:
    """Start one stdio server, ask for its tool list, and kill it.

    Returns the measured payload size, the tool names, and — when the server
    is proxied — a note that the measurement is the proxy's meta-tools rather
    than the catalog behind it.
    """
    if not server.command:
        return {"ok": False, "error": "no command declared"}
    resolved = shutil.which(server.command) or server.command
    argv = [resolved, *server.args]
    # Start the server with the env the harness would give it. Without this the
    # lite proxy fell back to its default prefix ("rea") for EVERY proxied
    # server, so probing `xt-forge` reported `rea_search`/`rea_call` — the
    # right byte count for the wrong server.
    env = dict(os.environ, **server.env)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=env,
        )
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"spawn failed: {type(exc).__name__}: {exc}"}

    deadline = started + timeout
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(_rpc(1, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "xtforge-mcp-probe", "version": "1"},
        }))
        proc.stdin.flush()
        init = _read_message(proc.stdout, deadline)
        if init is None:
            return {"ok": False, "error": "no answer to initialize"}
        if "error" in init:
            return {"ok": False, "error": f"initialize refused: {init['error']}"}

        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.write(_rpc(2, "tools/list", {}))
        proc.stdin.flush()

        listing = _read_message(proc.stdout, deadline)
        if listing is None:
            return {"ok": False, "error": "no answer to tools/list"}
        if "error" in listing:
            return {"ok": False, "error": f"tools/list refused: {listing['error']}"}

        tools = (listing.get("result") or {}).get("tools") or []
        payload = json.dumps(listing)
        elapsed = round(time.monotonic() - started, 3)
        return {
            "ok": True,
            "tools": len(tools),
            "bytes": len(payload.encode("utf-8")),
            "toolNames": [t.get("name") for t in tools if isinstance(t, dict)],
            "serverVersion": ((init.get("result") or {}).get("serverInfo") or {}).get("version"),
            "seconds": elapsed,
            "measuredSurface": "proxy meta-tools" if server.proxied else "server catalog",
        }
    finally:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 - the probe must never leak a child
            pass
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass


def probe_servers(servers: list[McpServer], timeout: float = DEFAULT_TIMEOUT
                  , only: list[str] | None = None) -> list[McpServer]:
    """Probe each selected server in place and attach its measurements."""
    wanted = {n.lower() for n in only} if only else None
    for server in servers:
        if wanted is not None and server.name.lower() not in wanted:
            continue
        if server.transport != "stdio":
            server.probe_error = f"transport {server.transport!r} not probed"
            continue
        result = probe_stdio(server, timeout=timeout)
        if result.get("ok"):
            server.tools = result["tools"]
            server.bytes = result["bytes"]
            server.tool_names = result.get("toolNames") or []
            server.probe_error = None
        else:
            server.probe_error = str(result.get("error"))
    return servers
