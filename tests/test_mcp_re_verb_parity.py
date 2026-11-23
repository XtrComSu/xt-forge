"""MCP must advertise every RE verb it can actually dispatch.

The dispatcher forwards an arbitrary `verb` to the CLI, so `callgraph`, `pdb-types` and
`demangle` all worked when called by hand — but the published `re_inspect` schema listed a
fixed enum that stopped at `ioc`. A client reading the schema would never discover them,
which makes the capability invisible even though it is present.

This test compares the advertised enum against the CLI's own verb list.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

# Verbs that are CLI-only or handled by dedicated MCP tools, so they need not appear in
# re_inspect's enum.
# borer/ida/cfg have dedicated MCP tools; pe is reached through the pe_* verbs.
EXEMPT = {"mcp", "doctor", "version", "test", "init-project", "annotate", "diff",
          "borer", "ida", "cfg", "pe",
          "capa", "crash", "usca", "graph", "block", "view", "checksec", "hooks",
          "patch", "rtti", "entropy", "pack", "strings", "needed", "disasm",
          "decompile", "trace", "triage", "slice", "live-probe", "rbxm", "deep-elf",
          "anchors", "asar", "netcap", "apk"}


def _re_verbs() -> set[str]:
    out = subprocess.run([sys.executable, "-m", "xtforge.cli", "re", "--help"],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            return {part for part in stripped.strip("{}").split(",")}
    return set()


def _mcp_verbs() -> set[str]:
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    proc = subprocess.run([sys.executable, "-m", "xtforge.cli", "mcp", "serve"],
                          input=json.dumps(request) + "\n",
                          capture_output=True, text=True, timeout=60)
    payload = [l for l in proc.stdout.splitlines() if l.strip().startswith("{")][-1]
    tools = json.loads(payload)["result"]["tools"]
    for tool in tools:
        if tool["name"] == "re_inspect":
            return set(tool["inputSchema"]["properties"]["verb"]["enum"])
    raise AssertionError("re_inspect tool not published")


class TestMcpReVerbParity(unittest.TestCase):
    def test_new_verbs_are_advertised(self) -> None:
        advertised = _mcp_verbs()
        for verb in ("callgraph", "demangle", "pdb-types", "archives", "kernelcache"):
            self.assertIn(verb, advertised,
                          f"re_inspect does not advertise {verb}, so no client can find it")

    def test_no_cli_verb_is_invisible(self) -> None:
        missing = _re_verbs() - _mcp_verbs() - EXEMPT
        # pe_* verbs are exposed through re_pe, not re_inspect.
        missing = {m for m in missing if not m.startswith("pe_")}
        self.assertEqual(missing, set(),
                         f"CLI verbs with no MCP route: {sorted(missing)}")
