"""The MCP tool surface is pinned.

Shipping the taste plugin added tools to the MCP server. Adding is fine;
silently dropping or renaming one is not — every other surface (the CLI, the
plugin, the skills) is built on these names, and a tool that disappears from
one surface while another still calls it is a broken release.

So the surface is pinned here by name. Changing it means changing this file
in the same commit, which is the point: the change becomes visible.

The cap comes from `docs/TOOL-BACKLOG.md`: MCP promotion requires retiring
or merging another tool, with a ceiling of 56 tools in `0.4.0`.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "adapters" / "mcp" / "server.py"

# The surface, by group. The taste plugin added `taste` and `goal`; the rest
# predates it and must keep working unchanged.
PINNED: dict[str, list[str]] = {
    "search": ["search", "recall", "tool_call"],
    "mem": ["mem_put", "mem_get", "mem_search", "mem_list", "mem_forget",
            "mem_review", "mem_export", "mem_import", "mem_sync"],
    "flash": ["flash_set", "flash_get", "flash_list", "flash_pin",
              "flash_delete", "flash_compact"],
    "route": ["route_tree", "route_find", "route_grep", "route_peek",
              "route_du", "route_recent", "route_where", "route_context",
              "route_errors"],
    "compress": ["compress"],
    "repos": ["repos_search", "repos_show", "repos_domains", "repos_suggest",
              "repos_plan", "repos_stats"],
    "taste": ["taste_learn", "taste_search", "taste_show", "taste_review",
              "taste_export", "taste_stats"],
    "goal": ["goal_status", "goal_run", "goal_verify"],
    "build": ["build_list", "build_status", "build_run", "build_graph",
              "build_lint"],
    "ops": ["version", "doctor", "tools_status", "calibrate", "slash",
            "ascii"],
    "re": ["re_inspect", "re_cfg"],
}

TOOL_CAP = 56


def load_tools() -> list[dict]:
    spec = importlib.util.spec_from_file_location("xtforge_mcp_surface", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TOOLS


class TestMcpSurface(unittest.TestCase):
    def setUp(self):
        self.tools = load_tools()
        self.names = [tool["name"] for tool in self.tools]

    def test_surface_matches_the_pinned_list(self):
        pinned = [name for group in PINNED.values() for name in group]
        self.assertEqual(sorted(self.names), sorted(pinned),
                         "the MCP tool surface changed; update this file in "
                         "the same commit, and say why in the changelog")

    def test_tool_names_are_unique(self):
        self.assertEqual(len(self.names), len(set(self.names)))

    def test_surface_stays_under_the_cap(self):
        """MCP promotion must retire or merge a tool, not just add one."""
        self.assertLessEqual(len(self.names), TOOL_CAP,
                             f"{len(self.names)} tools exceeds the "
                             f"{TOOL_CAP}-tool cap for 0.4.0")

    def test_every_tool_has_a_description_and_a_schema(self):
        for tool in self.tools:
            with self.subTest(tool=tool["name"]):
                self.assertTrue(tool.get("description", "").strip())
                self.assertIsInstance(tool.get("inputSchema"), dict)
                self.assertEqual(tool["inputSchema"].get("type"), "object")
