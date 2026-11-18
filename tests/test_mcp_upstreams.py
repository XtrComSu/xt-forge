"""Tests for REA and Craft Anything MCP preset resolution, connect, proxy, and --meta routing."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xtforge.core import mcp_proxy, mcp_registry

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"

MOCK_SERVER_PY = r"""
import json, sys

initialized = False
opened = None
enabled = False

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "mock-mcp", "version": "1.0"},
        }}), flush=True)
    elif method == "notifications/initialized":
        initialized = True
    elif method == "tools/list":
        if not initialized:
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32002, "message": "not initialized"}}), flush=True)
            continue
        tools = [
            {"name": "open_binary", "description": "Open a target binary cleanly.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "enable_toolset", "description": "Enable extra tools.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}},
            {"name": "status_check", "description": "Check persisted target.", "inputSchema": {"type": "object"}},
        ]
        if enabled:
            tools.append({"name": "core_evidence_browse", "description": "Browse retained evidence.", "inputSchema": {"type": "object"}})
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}), flush=True)
    elif method == "tools/call":
        if not initialized:
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32002, "message": "not initialized"}}), flush=True)
            continue
        p = msg.get("params") or {}
        tname = p.get("name")
        args = p.get("arguments") or {}
        if tname == "open_binary":
            opened = args.get("path")
            res = {"content": [{"type": "text", "text": f"opened={opened}"}]}
        elif tname == "enable_toolset":
            enabled = True
            print(json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}), flush=True)
            res = {"content": [{"type": "text", "text": "toolset_enabled"}]}
        elif tname == "status_check":
            res = {"content": [{"type": "text", "text": f"opened={opened}|enabled={enabled}"}]}
        elif tname == "core_evidence_browse":
            res = {"content": [{"type": "text", "text": "evidence_ok"}]}
        else:
            res = {"content": [{"type": "text", "text": f"unknown:{tname}"}], "isError": True}
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}), flush=True)
"""


def _write_mock_wrapper(tmp: Path, name: str) -> Path:
    srv = tmp / "mock_srv.py"
    srv.write_text(MOCK_SERVER_PY, encoding="utf-8")
    wrapper = tmp / name
    wrapper.write_text(
        f"#!/usr/bin/env python3\nimport runpy, sys\nrunpy.run_path({str(srv)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return wrapper


class TestMcpUpstreamsPython(unittest.TestCase):
    def setUp(self) -> None:
        self._old_home = os.environ.get("XT_HOME")
        self._old_rea = os.environ.get("REA_CMD")
        self._old_craft = os.environ.get("CRAFT_ANYTHING_CMD")
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        os.environ["XT_HOME"] = str(self.tmp_path / "xt_home")

    def tearDown(self) -> None:
        if self._old_home is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old_home
        for k, v in (("REA_CMD", self._old_rea), ("CRAFT_ANYTHING_CMD", self._old_craft)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def test_resolve_and_connect_rea_and_craft_anything(self):
        rea_bin = _write_mock_wrapper(self.tmp_path, "rea-agents")
        craft_bin = _write_mock_wrapper(self.tmp_path, "craft-anything-cli")
        os.environ["REA_CMD"] = str(rea_bin)
        os.environ["CRAFT_ANYTHING_CMD"] = str(craft_bin)

        res_rea = mcp_proxy.connect_server("rea")
        self.assertTrue(res_rea["ok"], res_rea)
        self.assertEqual(res_rea["server"], "rea")
        self.assertEqual(res_rea["tool_count"], 3)

        res_craft = mcp_proxy.connect_server("craft")
        self.assertTrue(res_craft["ok"], res_craft)
        self.assertEqual(res_craft["server"], "craft-anything")

        hits = mcp_registry.search_tools("open_binary")
        self.assertTrue(any(h["server"] == "rea" for h in hits), hits)

        exec_res = mcp_registry.execute_tool("rea", "open_binary", {"path": "/tmp/sample.elf"})
        self.assertTrue(exec_res["ok"], exec_res)
        self.assertEqual(exec_res["result"]["content"][0]["text"], "opened=/tmp/sample.elf")

    def test_python_meta_server_persistent_upstream_session(self):
        craft_bin = _write_mock_wrapper(self.tmp_path, "craft-anything-cli")
        os.environ["CRAFT_ANYTHING_CMD"] = str(craft_bin)
        mcp_proxy.connect_server("craft-anything")

        reqs = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "xt_discover", "arguments": {"query": "open_binary", "upstream": "craft-anything"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "craft-anything:open_binary", "arguments": {"path": "/app/bin"}}}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "craft-anything:enable_toolset", "arguments": {"name": "evidence"}}}}),
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "craft-anything:status_check", "arguments": {}}}}),
            json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "xt_schema", "arguments": {"name": "craft-anything:core_evidence_browse"}}}),
        ]) + "\n"

        proc = subprocess.run(
            [sys.executable, "-m", "adapters.mcp.server", "--meta"],
            cwd=str(ROOT),
            input=reqs,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [json.loads(line) for line in proc.stdout.strip().splitlines()]
        self.assertEqual(len(lines), 6)

        disc = json.loads(lines[1]["result"]["content"][0]["text"])
        self.assertTrue(any(m["name"] == "craft-anything:open_binary" for m in disc["upstream_matches"]), disc)

        state_payload = json.loads(lines[4]["result"]["content"][0]["text"])
        self.assertEqual(state_payload["content"][0]["text"], "opened=/app/bin|enabled=True")

        schema_payload = json.loads(lines[5]["result"]["content"][0]["text"])
        self.assertEqual(schema_payload["name"], "craft-anything:core_evidence_browse")

    def test_native_go_connect_and_proxy_cli(self):
        rea_bin = _write_mock_wrapper(self.tmp_path, "rea-agents")
        env = dict(os.environ)
        env["XT_HOME"] = str(self.tmp_path / "xt_home_go")
        env["REA_CMD"] = str(rea_bin)
        env.pop("XT_FORCE_PYTHON", None)

        r = subprocess.run(
            [str(BIN), "mcp", "connect", "rea", "--json"],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["server"], "rea")
        self.assertEqual(data["tool_count"], 3)

        proxy_reqs = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "rea_call", "arguments": {"tool": "open_binary", "arguments": {"path": "/bin/sh"}}}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rea_call", "arguments": {"name": "status_check", "arguments": {}}}}),
        ]) + "\n"
        rp = subprocess.run(
            [str(BIN), "mcp", "proxy", "--server", "rea", "--trust-on-first"],
            cwd=str(ROOT),
            env=env,
            input=proxy_reqs,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(rp.returncode, 0, rp.stderr)
        plines = [json.loads(line) for line in rp.stdout.strip().splitlines()]
        self.assertEqual([t["name"] for t in plines[1]["result"]["tools"]], ["rea_search", "rea_list", "rea_call"])
        self.assertIn("opened=/bin/sh", plines[3]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
