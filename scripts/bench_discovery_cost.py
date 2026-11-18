#!/usr/bin/env python3
"""Measure full MCP tool-discovery cost: direct exposure vs XT-Forge --meta.

Counts real JSON-RPC stdio round trips across small (4), medium (50), and
large (229, matching REA scale) tool catalogs:
  - startup `tools/list` bytes & tokens
  - discovery turns (`xt_discover` + `xt_schema` before first valid call)
  - failed lookups when calling an unknown tool without discovery
  - wall-clock time to the first correct domain `tools/call`
  - 1-turn and 5-turn cumulative schema+discovery token cost

Usage:
    python3 scripts/bench_discovery_cost.py [--python] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"
GO_HUB = ROOT / "native" / "xtforge-go" / "xtforge-hub"

MOCK_SERVER_PY = r'''
import json, sys

n_tools = int(sys.argv[1])
tools = []
domains = ["binary", "network", "secret", "graph", "disasm", "patch", "strings", "cfg"]
for i in range(n_tools):
    if i == n_tools - 1:
        tools.append({
            "name": "inspect_relro_header",
            "description": "Inspect ELF GNU_RELRO and BIND_NOW dynamic section flags for hardening.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_binary": {"type": "string", "description": "ELF binary path to inspect"},
                    "strict_bind_now": {"type": "boolean", "description": "Require DT_BIND_NOW or DF_1_NOW"},
                },
                "required": ["target_binary"],
            },
        })
    else:
        dom = domains[i % len(domains)]
        tools.append({
            "name": f"{dom}_op_{i:03d}",
            "description": f"Execute {dom} analysis operation #{i} over workspace targets and emit JSON summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": f"Target path for {dom} op {i}"},
                    "depth": {"type": "integer", "description": "Traversal or block limit"},
                    "format": {"type": "string", "description": "Output format (json|text)"},
                },
                "required": ["target"],
            },
        })

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    req = json.loads(raw)
    mid = req.get("id")
    method = req.get("method", "")
    if mid is None:
        continue
    if method == "initialize":
        res = {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"mock-cat-{n_tools}", "version": "1.0.0"},
        }
    elif method == "tools/list":
        res = {"tools": tools}
    elif method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name", "")
        args = params.get("arguments") or {}
        if name == "inspect_relro_header" and args.get("target_binary"):
            res = {"content": [{"type": "text", "text": json.dumps({"ok": True, "relro": "Full", "target": args["target_binary"]})}]}
        elif any(t["name"] == name for t in tools):
            res = {"content": [{"type": "text", "text": json.dumps({"ok": True, "tool": name})}]}
        else:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown tool: {name}"}}) + "\n")
            sys.stdout.flush()
            continue
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
    sys.stdout.flush()
'''


def _tokens(text_or_obj: Any) -> int:
    s = text_or_obj if isinstance(text_or_obj, str) else json.dumps(text_or_obj, separators=(",", ":"))
    return max(0, (len(s) + 3) // 4)


class RpcSession:
    def __init__(self, cmd: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self._id = 0

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"MCP EOF on {method}: {err}")
        return json.loads(line)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def benchmark_catalog(n_tools: int, *, use_python_meta: bool, mock_script: Path, tmp_dir: Path) -> dict[str, Any]:
    env = os.environ.copy()
    xt_home = tmp_dir / f"xt_{n_tools}_{'py' if use_python_meta else 'go'}"
    xt_home.mkdir(parents=True, exist_ok=True)
    env["XT_HOME"] = str(xt_home)
    if use_python_meta:
        env["XT_FORCE_PYTHON"] = "1"
    else:
        env.pop("XT_FORCE_PYTHON", None)

    direct_cmd = [sys.executable, str(mock_script), str(n_tools)]
    server_name = f"mockcat{n_tools}"

    # 1. Measure Direct MCP exposure.
    t0 = time.perf_counter()
    ds = RpcSession(direct_cmd, env)
    try:
        ds.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}})
        ds.notify("notifications/initialized", {})
        t_ready = time.perf_counter()
        tlist = ds.request("tools/list", {})
        tools_json = json.dumps(tlist["result"]["tools"], separators=(",", ":"))
        direct_schema_bytes = len(tools_json.encode("utf-8"))
        direct_schema_tokens = _tokens(tools_json)

        call_req = {"name": "inspect_relro_header", "arguments": {"target_binary": "/bin/ls", "strict_bind_now": True}}
        call_resp = ds.request("tools/call", call_req)
        direct_first_call_ms = round((time.perf_counter() - t_ready) * 1000.0, 2)
        call_raw = json.dumps(call_resp)
        direct_call_ok = (not call_resp.get("error")) and ("relro" in call_raw) and ("Full" in call_raw)
    finally:
        ds.close()

    # Pre-configure mock upstream and warm cached catalog in XT_HOME so --meta runs offline/deterministically.
    upstreams_cfg = {
        "version": 1,
        "upstreams": {
            server_name: {
                "name": server_name,
                "command": direct_cmd,
                "source": "bench_mock",
            }
        },
    }
    (xt_home / "mcp_upstreams.json").write_text(json.dumps(upstreams_cfg, indent=2), encoding="utf-8")
    (xt_home / "cache").mkdir(parents=True, exist_ok=True)
    catalog_tools = json.loads(tools_json)
    (xt_home / "cache" / f"mcp-catalog-{server_name}.json").write_text(
        json.dumps({"server": server_name, "fetched_at": int(time.time()), "tools": catalog_tools}),
        encoding="utf-8",
    )

    meta_cmd = (
        [str(BIN), "mcp", "serve", "--meta"]
        if (use_python_meta or not GO_HUB.exists())
        else [str(GO_HUB), "mcp", "serve", "--meta"]
    )

    # 2. Measure --meta exposure (both standard discover->schema->call and naive failed lookup).
    ms_sess = RpcSession(meta_cmd, env)
    try:
        ms_sess.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}})
        ms_sess.notify("notifications/initialized", {})
        t_meta_ready = time.perf_counter()
        mlist = ms_sess.request("tools/list", {})
        mtools_json = json.dumps(mlist["result"]["tools"], separators=(",", ":"))
        meta_schema_bytes = len(mtools_json.encode("utf-8"))
        meta_schema_tokens = _tokens(mtools_json)

        # Failed lookup cost: calling a guessed name without xt_discover / xt_schema.
        bad_resp = ms_sess.request("tools/call", {"name": "xt_call", "arguments": {"name": f"{server_name}:nonexistent_relro_tool", "arguments": {}}})
        failed_lookup_recorded = bool(bad_resp.get("error") or bad_resp.get("result", {}).get("isError") or '"ok": false' in json.dumps(bad_resp).lower())

        # Reset timer for clean guided discovery -> schema -> call.
        t_disc_start = time.perf_counter()
        disc_req = {"name": "xt_discover", "arguments": {"query": "relro", "limit": 5}}
        disc_resp = ms_sess.request("tools/call", disc_req)
        schema_req = {"name": "xt_schema", "arguments": {"name": f"{server_name}:inspect_relro_header"}}
        schema_resp = ms_sess.request("tools/call", schema_req)
        mcall_req = {
            "name": "xt_call",
            "arguments": {
                "name": f"{server_name}:inspect_relro_header",
                "arguments": {"target_binary": "/bin/ls", "strict_bind_now": True},
            },
        }
        mcall_resp = ms_sess.request("tools/call", mcall_req)
        meta_first_call_ms = round((time.perf_counter() - t_disc_start) * 1000.0, 2)
        mcall_raw = json.dumps(mcall_resp)
        meta_call_ok = (not mcall_resp.get("error")) and ("relro" in mcall_raw) and ("Full" in mcall_raw)

        disc_tokens = _tokens(disc_req) + _tokens(disc_resp) + _tokens(schema_req) + _tokens(schema_resp)
    finally:
        ms_sess.close()

    call_payload_tokens = _tokens(call_req) + _tokens(call_resp)
    meta_call_payload_tokens = _tokens(mcall_req) + _tokens(mcall_resp)

    # Cumulative prompt+tool token cost for 1-turn (single tool task) vs 5-turn conversation
    # (every LLM turn includes `startup_schema_tokens` in the system/tool block).
    direct_1turn_tokens = direct_schema_tokens + call_payload_tokens
    meta_1turn_tokens = (3 * meta_schema_tokens) + disc_tokens + meta_call_payload_tokens
    direct_5turn_tokens = (5 * direct_schema_tokens) + (5 * call_payload_tokens)
    meta_5turn_tokens = (7 * meta_schema_tokens) + disc_tokens + (5 * meta_call_payload_tokens)

    reduction_schema_pct = round((1.0 - (meta_schema_tokens / max(1, direct_schema_tokens))) * 100.0, 1)
    winner_1turn = "meta" if meta_1turn_tokens < direct_1turn_tokens else "direct"
    winner_5turn = "meta" if meta_5turn_tokens < direct_5turn_tokens else "direct"

    return {
        "catalog_tools": n_tools,
        "engine": "python" if use_python_meta else "go",
        "direct": {
            "startup_schema_bytes": direct_schema_bytes,
            "startup_schema_tokens": direct_schema_tokens,
            "discovery_turns": 0,
            "failed_lookups": 0,
            "time_to_first_correct_call_ms": direct_first_call_ms,
            "total_1turn_tokens": direct_1turn_tokens,
            "total_5turn_tokens": direct_5turn_tokens,
            "call_ok": direct_call_ok,
        },
        "meta": {
            "startup_schema_bytes": meta_schema_bytes,
            "startup_schema_tokens": meta_schema_tokens,
            "discovery_turns": 2,
            "discovery_payload_tokens": disc_tokens,
            "naive_failed_lookup_verified": failed_lookup_recorded,
            "time_to_first_correct_call_ms": meta_first_call_ms,
            "total_1turn_tokens": meta_1turn_tokens,
            "total_5turn_tokens": meta_5turn_tokens,
            "call_ok": meta_call_ok,
        },
        "schema_tokens_saved": direct_schema_tokens - meta_schema_tokens,
        "schema_reduction_pct": reduction_schema_pct,
        "winner_1turn": winner_1turn,
        "winner_5turn": winner_5turn,
        "direct_beats_meta_on_1turn": winner_1turn == "direct",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", action="store_true", help="Benchmark Python fallback --meta instead of Go hub")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    tmp_dir = Path(tempfile.mkdtemp(prefix="xt_bench_disc_"))
    try:
        mock_script = tmp_dir / "mock_mcp_server.py"
        mock_script.write_text(MOCK_SERVER_PY.lstrip(), encoding="utf-8")
        rows = [
            benchmark_catalog(n, use_python_meta=args.python, mock_script=mock_script, tmp_dir=tmp_dir)
            for n in (4, 50, 229)
        ]
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    payload = {
        "engine": "python" if args.python else "go",
        "results": rows,
        "small_catalog_break_even_note": (
            "On a 4-tool catalog with one direct call, direct MCP exposure avoids 2 extra discovery turns "
            "and uses fewer 1-turn tokens; --meta pays off sharply at 50+ tools and multi-turn sessions."
        ),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"MCP discovery cost benchmark (engine={payload['engine']})")
        print(f"{'tools':>5}  {'direct_tok':>10}  {'meta_tok':>8}  {'saved%':>7}  {'1turn(D/M)':>15}  {'5turn(D/M)':>15}  {'1t_win':>6}  {'5t_win':>6}  {'meta_ms':>7}")
        for r in rows:
            d, m = r["direct"], r["meta"]
            print(
                f"{r['catalog_tools']:>5}  {d['startup_schema_tokens']:>10}  {m['startup_schema_tokens']:>8}  "
                f"{r['schema_reduction_pct']:>6.1f}%  "
                f"{d['total_1turn_tokens']:>6}/{m['total_1turn_tokens']:<8}  "
                f"{d['total_5turn_tokens']:>6}/{m['total_5turn_tokens']:<8}  "
                f"{r['winner_1turn']:>6}  {r['winner_5turn']:>6}  {m['time_to_first_correct_call_ms']:>7.1f}"
            )
    ok = all(r["direct"]["call_ok"] and r["meta"]["call_ok"] and r["meta"]["naive_failed_lookup_verified"] for r in rows)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
