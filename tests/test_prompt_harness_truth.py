"""The injected prompt must describe the harness that is actually running.

The previous version hardcoded a `memos` MCP server and two
`mcp__memos__*` tools. The live `dsh-tui` profile mounts no such server — its
memory surface is `xt-forge`, proxied as `xt` — so every agent was told to call
tools that do not exist, and was never told about the ones that do.

These tests pin the behaviour that replaced it: read the profile, name what is
mounted, and when the answer cannot be known, say so instead of inventing a
tool name. A wrong tool name in a system prompt is worse than no tool name,
because the model will confidently try to call it.

Run: python3 -m unittest tests.test_prompt_harness_truth -v
"""
from __future__ import annotations

import unittest
from unittest import mock

from xtforge.core import mcp as mcp_module
from xtforge.core import prompts
from xtforge.core.mcp import McpServer


def server(name: str, *, proxied: bool = False, prefix: str | None = None,
           tool_names: list[str] | None = None) -> McpServer:
    s = McpServer(name=name, profile="test", config_path="/tmp/x.yml", line=1,
                  command="/usr/bin/python3", args=["/srv/x.py"])
    if proxied:
        s.env["LITE_PREFIX"] = prefix or name
    s.tool_names = list(tool_names or [])
    if tool_names:
        s.tools = len(tool_names)
        s.bytes = 1900
    return s


def inventory_returning(servers: list[McpServer]):
    """Patch the inventory the helper reads, without touching a real profile."""
    return mock.patch.object(
        mcp_module, "inventory",
        return_value={"servers": servers, "activeProfile": "test", "summary": {}})


class MountedSummaryTest(unittest.TestCase):
    def _summary_for(self, servers: list[McpServer]) -> dict:
        with inventory_returning(servers):
            return prompts._mounted_mcp_summary()

    def test_names_every_mounted_server(self):
        summary = self._summary_for([server("github"), server("xt-forge")])
        self.assertEqual(summary["names"], "github,xt-forge")

    def test_proxied_memory_server_is_reached_through_its_call_tool(self):
        """A proxied server exposes meta-tools, not the tools behind them."""
        memory = server("xt-forge", proxied=True, prefix="xt",
                        tool_names=["xt_search", "xt_call"])
        summary = self._summary_for([memory])
        self.assertEqual(summary["tools"], "xt_call")
        self.assertEqual(summary["memory_tools"][0][0], "xt_call")

    def test_direct_memory_server_names_its_real_tools(self):
        memory = server("memos", tool_names=["mem_put", "mem_search"])
        summary = self._summary_for([memory])
        self.assertEqual(summary["tools"],
                         "mcp__memos__mem_put,mcp__memos__mem_search")

    def test_unprobed_direct_server_invents_no_tool_names(self):
        summary = self._summary_for([server("memos", tool_names=[])])
        self.assertEqual(summary["tools"], "")
        self.assertEqual(summary["memory_tools"], [])

    def test_no_servers_reports_empty_rather_than_a_guess(self):
        summary = self._summary_for([])
        self.assertEqual(summary["names"], "")
        self.assertEqual(summary["tools"], "")

    def test_unreadable_config_degrades_to_unknown(self):
        """A failed config read must not invent servers or tools.

        The active profile is still reported: which profile this process runs
        under is read from the environment and remains true even when its file
        cannot be parsed. What must stay empty is everything that would have
        come FROM the file.
        """
        with mock.patch.object(mcp_module, "inventory",
                               side_effect=RuntimeError("config unreadable")):
            summary = prompts._mounted_mcp_summary()
        self.assertEqual(summary["names"], "")
        self.assertEqual(summary["tools"], "")
        self.assertEqual(summary["memory_tools"], [])


class RenderedPromptTest(unittest.TestCase):
    """The rendered block must never mention a server that is not mounted."""

    def _render(self, proxied: bool = True) -> str:
        tools = "xt_call" if proxied else ""
        memory_tools = ([("xt_call", "run any xt-forge tool")] if proxied else [])
        fake = {
            "profile": "test",
            "names": "xt-forge",
            "tools": tools,
            "memory_tools": memory_tools,
        }
        with mock.patch.object(prompts, "_mounted_mcp_summary",
                               return_value=fake):
            return prompts.build_agent_context(include_taste=False,
                                               include_flash=False)

    def test_prompt_names_the_mounted_server(self):
        rendered = self._render()
        self.assertIn("xt-forge", rendered)
        self.assertIn("xt_call", rendered)

    def test_prompt_does_not_claim_a_memos_server(self):
        self.assertNotIn("mcp__memos__", self._render())

    def test_compact_rendering_also_omits_memos(self):
        fake = {"profile": "test", "names": "xt-forge", "tools": "xt_call",
                "memory_tools": [("xt_call", "run any xt-forge tool")]}
        with mock.patch.object(prompts, "_mounted_mcp_summary",
                               return_value=fake):
            rendered = prompts.build_agent_context(include_taste=False,
                                                   include_flash=False,
                                                   compact=True)
        self.assertNotIn("memos", rendered)


if __name__ == "__main__":
    unittest.main()
