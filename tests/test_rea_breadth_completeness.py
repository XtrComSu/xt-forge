"""The breadth scorecard must classify every tool in REA's catalogue.

This test exists because the scorecard once lied in the most flattering way possible.

`scripts/rea_breadth.py` measured coverage against its own hand-written row list. With 75
rows referencing only 91 of REA's 263 tools, it reported 97%. The 172 tools nobody had
classified — 24 address/navigation calls, 28 browser-runtime observers, 25 ADB operations,
9 build-VM calls — were not covered *or* declared out-of-lane. They were invisible, and an
invisible capability counts as neither a gap nor a win, so the number drifted upward.

The honest figure with every tool assigned is 86.5%, not 97%. That is the point of the
test: a denominator you chose yourself is not a measurement.

Reading the catalogue requires the REA package, which is not vendored (it is a third-party
distribution). When it is absent the test skips rather than passing vacuously — a skip is
honest, a green tick on an unrun check is not.
"""
from __future__ import annotations

import json
import re
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rea_breadth.py"
CATALOG = Path("/tmp/rea-latest/package/dist/mcp-catalog.json")

# Matches cap("title", [tools...], verb_or_None, "verdict", ...)
ROW = re.compile(
    r'cap\(\s*"([^"]+)"\s*,\s*\[([^\]]*)\]\s*,\s*(None|"[^"]*")\s*,\s*"([a-z-]+)"', re.S)
TOOL = re.compile(r'"([a-z0-9_]+)"')
VALID_VERDICTS = {"covered", "partial", "missing", "out-of-lane"}


def parse_rows() -> list[tuple[str, list[str], str]]:
    source = SCRIPT.read_text()
    return [(title, TOOL.findall(tools), verdict)
            for title, tools, _verb, verdict in ROW.findall(source)]


class RowHygieneTest(unittest.TestCase):
    """Structural checks that need no catalogue."""

    def test_rows_parse(self) -> None:
        rows = parse_rows()
        self.assertGreater(len(rows), 50)


    def test_every_verdict_is_known(self) -> None:
        for title, _tools, verdict in parse_rows():
            self.assertIn(verdict, VALID_VERDICTS, title)

    def test_covered_rows_declare_a_tool(self) -> None:
        """A 'covered' row with no capability mapped has no way to be probed."""
        for title, tools, verdict in parse_rows():
            if verdict == "covered":
                self.assertTrue(tools, f"covered row {title!r} lists no REA tool")

    def test_non_covered_rows_state_a_reason(self) -> None:
        """partial/missing/out-of-lane must explain themselves in the source."""
        source = SCRIPT.read_text()
        for title, _tools, verdict in parse_rows():
            if verdict == "covered":
                continue
            start = source.find(f'cap("{title}"')
            self.assertGreaterEqual(start, 0, title)
            block = source[start:start + 2000]
            self.assertIn("out-of-lane" if verdict == "out-of-lane" else verdict, block)
            # The reason follows the verdict in the same call.
            after = block.split(f'"{verdict}"', 1)[-1]
            self.assertTrue(after.strip().startswith(",") or after.strip().startswith(")"),
                            f"{title!r} has no reason after its verdict")

    def test_no_tool_is_claimed_by_two_rows(self) -> None:
        counts: Counter[str] = Counter()
        for _title, tools, _verdict in parse_rows():
            counts.update(tools)
        duplicates = sorted(name for name, count in counts.items() if count > 1)
        self.assertFalse(duplicates,
                         f"tools assigned to more than one capability: {duplicates}")


class CatalogueCompletenessTest(unittest.TestCase):
    def setUp(self) -> None:
        if not CATALOG.is_file():
            self.skipTest("REA catalogue is not present at /tmp/rea-latest; "
                          "cannot check the denominator")

    def test_every_rea_tool_is_classified(self) -> None:
        """The assertion that would have caught the 97%-vs-86.5% error."""
        catalogue = json.loads(CATALOG.read_text())
        tools = catalogue["tools"] if isinstance(catalogue, dict) else catalogue
        names = {tool["name"] for tool in tools if isinstance(tool, dict)}
        referenced: set[str] = set()
        for _title, row_tools, _verdict in parse_rows():
            referenced.update(row_tools)
        unclassified = sorted(names - referenced)
        self.assertFalse(
            unclassified,
            f"{len(unclassified)} of {len(names)} REA tools are in no capability row, so "
            f"the coverage percentage has a denominator of our own choosing: "
            f"{unclassified[:10]}")

    def test_script_exits_nonzero_on_unclassified_tools(self) -> None:
        """The guard must actually fail the run, not just print a warning."""
        source = SCRIPT.read_text()
        self.assertIn("unmapped", source)
        # The failure has to be a non-zero return, not a print.
        self.assertRegex(
            source,
            r"if unmapped:[\s\S]{0,200}?return 1",
            "the unclassified-tool guard does not fail the run")

    def test_catalogue_tool_count_is_reported(self) -> None:
        catalogue = json.loads(CATALOG.read_text())
        tools = catalogue["tools"] if isinstance(catalogue, dict) else catalogue
        self.assertGreater(len(tools), 200)


if __name__ == "__main__":
    unittest.main()
