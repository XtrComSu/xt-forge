"""The MCP inventory must read the config the harness actually mounts.

Why this file exists
--------------------
`xtforge/core/mcp` parses cordis patch YAML with a small stdlib reader instead
of a YAML library, because xt-forge ships with no dependencies. A hand-written
reader is exactly the kind of code that silently returns a plausible wrong
answer, and it did: the first version treated every key at the `serverName`
indent as the end of the record, so each server came back with no `command`, no
`args` and no `env`. Nothing crashed — the command cheerfully printed 18
servers, all "direct", all costless. The bug was invisible until the numbers
were compared against the real config.

So the assertions here are about the facts that report depended on:

  * sibling keys are read (`transport`, `command`, `args`, `env`)
  * a server is recognised as proxied in BOTH spellings that occur in practice
    (an explicit `LITE_PREFIX`, and the lite proxy script with no prefix)
  * unknown cost stays unknown instead of becoming zero

Run: python3 -m unittest tests.test_mcp_inventory -v
"""
from __future__ import annotations

import textwrap
import unittest

from xtforge.core.mcp import (
    PROXY_META_BYTES,
    McpServer,
    parse_servers,
    proxy_advice,
    summarise,
)

#: A file shaped exactly like the real profiles: `serverName` and its siblings
#: sit at the SAME indent, nested under a patch-list `- id:` entry.
SAMPLE = textwrap.dedent("""\
    - insert:
        - id: mcp-github
          name: '@deepseek-ai/dsh-mcp-client'
          config:
            serverName: github
            transport: stdio
            command: /usr/bin/python3
            args:
              - /path/to/rea_lite.py
            env:
              LITE_PREFIX: gh
              LITE_LABEL: GitHub
            failOnStartupError: false

        - id: mcp-rea
          name: '@deepseek-ai/dsh-mcp-client'
          config:
            serverName: rea
            transport: stdio
            command: /usr/bin/python3
            args:
              - /path/to/rea_lite.py
            failOnStartupError: false

        - id: mcp-context7
          name: '@deepseek-ai/dsh-mcp-client'
          config:
            serverName: context7
            transport: streamable-http
            url: https://mcp.context7.com/mcp
            failOnStartupError: false

    - id: credentials
      disabled: false
    """)


class ParseServersTest(unittest.TestCase):
    def setUp(self) -> None:
        self.servers = parse_servers(SAMPLE, "test", "/tmp/test.yml")
        self.by_name = {s.name: s for s in self.servers}

    def test_finds_every_server_and_stops_at_the_next_patch_entry(self):
        self.assertEqual([s.name for s in self.servers],
                         ["github", "rea", "context7"])

    def test_reads_sibling_keys(self):
        github = self.by_name["github"]
        self.assertEqual(github.transport, "stdio")
        self.assertEqual(github.command, "/usr/bin/python3")
        self.assertEqual(github.args, ["/path/to/rea_lite.py"])

    def test_reads_env_block(self):
        self.assertEqual(self.by_name["github"].env.get("LITE_PREFIX"), "gh")
        self.assertEqual(self.by_name["github"].env.get("LITE_LABEL"), "GitHub")

    def test_http_transport_keeps_its_url_and_has_no_command(self):
        context7 = self.by_name["context7"]
        self.assertEqual(context7.transport, "streamable-http")
        self.assertEqual(context7.url, "https://mcp.context7.com/mcp")
        self.assertIsNone(context7.command)

    def test_explicit_prefix_marks_a_server_proxied(self):
        self.assertTrue(self.by_name["github"].proxied)
        self.assertEqual(self.by_name["github"].proxy_prefix, "gh")

    def test_proxy_script_without_prefix_is_still_proxied(self):
        """`rea` declares no LITE_PREFIX; the proxy defaults it to "rea".

        Missing this reported the largest catalog in the profile (229 tools,
        273 KB) as a direct 273 KB mount instead of three meta-tools.
        """
        rea = self.by_name["rea"]
        self.assertTrue(rea.proxied)
        self.assertEqual(rea.proxy_prefix, "rea")

    def test_plain_stdio_server_is_not_proxied(self):
        direct = McpServer(name="x", profile="p", config_path="c", line=1,
                           command="/usr/bin/python3", args=["/srv/thing.py"])
        self.assertFalse(direct.proxied)
        self.assertIsNone(direct.proxy_prefix)


class CostHonestyTest(unittest.TestCase):
    def test_unmeasured_server_reports_no_number(self):
        server = McpServer(name="x", profile="p", config_path="c", line=1,
                           command="/usr/bin/python3", args=["/srv/thing.py"])
        self.assertIsNone(server.effective_bytes())
        self.assertIsNone(server.tokens)

    def test_unmeasured_servers_are_counted_separately_not_as_zero(self):
        measured = McpServer(name="a", profile="p", config_path="c", line=1)
        measured.bytes = 4000
        unmeasured = McpServer(name="b", profile="p", config_path="c", line=2)
        summary = summarise([measured, unmeasured])
        self.assertEqual(summary["knownBytes"], 4000)
        self.assertEqual(summary["unmeasured"], ["b"])

    def test_proxied_server_costs_the_meta_tool_preamble_not_a_guess(self):
        server = McpServer(name="rea", profile="p", config_path="c", line=1,
                           command="/usr/bin/python3", args=["/path/rea_lite.py"])
        self.assertEqual(server.effective_bytes(), PROXY_META_BYTES)

    def test_advice_refuses_to_judge_an_unmeasured_server(self):
        server = McpServer(name="x", profile="p", config_path="c", line=1,
                           command="/usr/bin/python3", args=["/srv/thing.py"])
        verdict = proxy_advice(server)
        self.assertEqual(verdict["verdict"], "unknown")
        self.assertIn("status --probe", verdict["reason"])

    def test_advice_keeps_a_small_catalog_direct(self):
        server = McpServer(name="x", profile="p", config_path="c", line=1)
        server.bytes = 600
        verdict = proxy_advice(server)
        self.assertEqual(verdict["verdict"], "keep-direct")
        self.assertEqual(verdict["savesBytes"], 0)

    def test_advice_recommends_the_proxy_for_a_large_catalog(self):
        server = McpServer(name="x", profile="p", config_path="c", line=1)
        server.bytes = 6000
        verdict = proxy_advice(server)
        self.assertEqual(verdict["verdict"], "proxy-worthwhile")
        self.assertEqual(verdict["savesBytes"], 6000 - PROXY_META_BYTES)


if __name__ == "__main__":
    unittest.main()
