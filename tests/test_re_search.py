"""`re search` — byte/text pattern search with offset-to-address mapping.

The engine could say what text is in a file (`re strings`) and what is named in
it (`re symbols`), but never *where a byte sequence is*, which is the question
that comes before a patch or a signature. REA ships `search_bytes`; this is the
equivalent, and these tests hold it to the same rule as the rest of the engine:
a match reports an address only when a section table actually maps it.

Two traps this file pins, both found while wiring it:

* the engine reports section ``offset``/``addr`` as **hex strings** ("0x388"),
  so an ``int()`` on them silently drops every section and every match comes
  back with ``va: null``;
* ``.bss`` is ``SHT_NOBITS`` — a size, an offset, and no file bytes. Its offset
  range overlaps real bytes, so mapping by ``size`` alone would attribute a
  match to a section that cannot contain it. ``file_size`` is the bound.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xtforge.core.re import search as research  # noqa: E402


class TestPatternCompilation(unittest.TestCase):
    def test_hex_wildcard_matches_any_byte(self) -> None:
        regex = research.compile_pattern("7f 45 ?? 46", "hex")
        self.assertIsNotNone(regex.search(b"\x7f\x45\x4c\x46"))
        self.assertIsNone(regex.search(b"\x7f\x45\x4c\x47"))

    def test_hex_metacharacter_is_literal(self) -> None:
        # 0x28 is '(' — appending raw bytes to a regex would make it a group.
        regex = research.compile_pattern("28", "hex")
        self.assertIsNotNone(regex.search(b"("))
        self.assertIsNone(regex.search(b"x"))

    def test_odd_digit_count_is_named(self) -> None:
        with self.assertRaisesRegex(research.SearchError, "odd number of digits"):
            research.compile_pattern("484", "hex")

    def test_nibble_wildcard_is_refused_not_approximated(self) -> None:
        with self.assertRaisesRegex(research.SearchError, "nibble wildcard"):
            research.compile_pattern("4?", "hex")

    def test_empty_pattern_is_refused(self) -> None:
        with self.assertRaisesRegex(research.SearchError, "needs a pattern"):
            research.compile_pattern("", "text")

    def test_pattern_that_can_match_nothing_is_refused(self) -> None:
        with self.assertRaisesRegex(research.SearchError, "empty string"):
            research.compile_pattern("a*", "regex")


class TestSearchBehaviour(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "blob.bin"
        #              0    1    2    3    4    5    6    7
        self.path.write_bytes(b"aaaa" + b"needle" + b"\x48\x8b\xc3" + b"tail")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_overlapping_matches_are_all_reported(self) -> None:
        result = research.search_file(self.path, "aa", mode="text", limit=10)
        self.assertEqual([m["offset"] for m in result["matches"]], [0, 1, 2],
                         "a scan that resumes after the match end under-reports overlaps")

    def test_hex_search_finds_the_instruction_bytes(self) -> None:
        result = research.search_file(self.path, "48 8b ??", mode="hex")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["offset"], 10)

    def test_regex_mode_uses_bytes(self) -> None:
        result = research.search_file(self.path, r"\x48.\xc3", mode="regex")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["offset"], 10)

    def test_no_match_is_an_answer_not_an_error(self) -> None:
        result = research.search_file(self.path, "absent", mode="text")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)
        self.assertFalse(result["truncated"])

    def test_truncation_is_stated(self) -> None:
        result = research.search_file(self.path, "a", mode="text", limit=2)
        self.assertEqual(result["count"], 2)
        self.assertTrue(result["truncated"],
                        "hitting the limit must say so rather than silently shortening")

    def test_context_window_stays_in_bounds(self) -> None:
        payload = self.path.read_bytes()
        result = research.search_file(self.path, "needle", mode="text", context=999)
        match = result["matches"][0]
        self.assertEqual(match["window_offset"], 0,
                         "context wider than the file clamps to the file, not past it")
        self.assertEqual(len(match["hex"].split()), len(payload))

    def test_directory_is_refused_with_a_usable_reason(self) -> None:
        with self.assertRaisesRegex(research.SearchError, "is a directory"):
            research.search_file(Path(self.tmp.name), "x", mode="text")


class TestOffsetToAddress(unittest.TestCase):
    SECTIONS = [
        {"name": "", "type": "native", "addr": "0x0", "offset": "0x0", "size": 0,
         "file_size": 0},
        # The engine's own shape: offset and addr arrive as hex strings.
        {"name": ".text", "type": "native", "addr": "0x1000", "offset": "0x400",
         "size": 256, "file_size": 256},
        # A NOBITS section whose offset range overlaps .text's file bytes.
        {"name": ".bss", "type": "native", "addr": "0x2000", "offset": "0x400",
         "size": 4096, "file_size": 0},
    ]

    def test_hex_string_fields_map_to_an_address(self) -> None:
        address, section = research._map_offset(self.SECTIONS, 0x410)
        self.assertEqual(address, 0x1010)
        self.assertEqual(section, ".text")

    def test_nobits_never_claims_a_file_byte(self) -> None:
        address, section = research._map_offset(self.SECTIONS, 0x500)
        self.assertIsNone(address, ".bss has no file bytes; it must not map one")
        self.assertEqual(section, "")

    def test_unmapped_offset_reports_none_not_an_invented_address(self) -> None:
        address, section = research._map_offset(self.SECTIONS, 0x10)
        self.assertIsNone(address)
        self.assertEqual(section, "")


class TestSearchCli(unittest.TestCase):
    def _run(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "re", *argv],
            capture_output=True, text=True, cwd=str(ROOT), env={**os.environ})

    def test_cli_reports_offsets_and_a_section_for_a_real_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "blob.bin"
            blob.write_bytes(b"\x00\x01needle\x02\x03")
            proc = self._run("search", str(blob), "--pattern", "needle", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["matches"][0]["offset"], 2)
            self.assertIsNone(payload["matches"][0]["va"],
                              "a headerless blob has no section table; va stays null")

    def test_missing_pattern_is_a_usage_error_naming_the_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "blob.bin"
            blob.write_bytes(b"x")
            proc = self._run("search", str(blob), "--json")
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--pattern", proc.stdout)

    def test_help_lists_the_new_flags(self) -> None:
        proc = self._run("--help")
        self.assertIn("--pattern", proc.stdout)
        self.assertIn("--hex", proc.stdout)


if __name__ == "__main__":
    unittest.main()
