"""The handoff's stated numbers must match the tree.

Last round its opening table claimed 78 files and 268 tests when the tree had 109 files and
269. Every later claim in a document inherits the credibility of its first table, so the
mismatch is checked rather than remembered.

This runs the fast checks only (file and line counts, HEAD). The slower ones — Go test
passes, Python test count — need `scripts/check_handoff_numbers.py --full`.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestHandoffContents(unittest.TestCase):
    """The table of contents must list every heading, with a matching anchor.

    The handoff is over a thousand lines; without a contents block a reader cannot find the
    section they need. A contents block that silently misses a section is worse than none,
    because it implies the document is shorter than it is.
    """

    def test_every_heading_is_listed(self) -> None:
        import re

        text = (ROOT / "docs" / "superpowers" / "HANDOFF-2026-11-23.md").read_text(
            encoding="utf-8")
        headings = [line.lstrip("#").strip() for line in text.splitlines()
                    if re.match(r"^#{2,3} ", line)]

        def anchor(title: str) -> str:
            slug = re.sub(r"[`*_]", "", title.lower())
            slug = re.sub(r"[^a-z0-9 \-]", "", slug)
            return re.sub(r"\s+", "-", slug.strip())

        toc = re.findall(r"^\s*- \[(.*?)\]\(#(.*?)\)$", text, re.M)
        listed = {title for title, _ in toc}
        missing = [h for h in headings if h != "Contents" and h not in listed]
        self.assertEqual(missing, [], f"headings missing from the contents: {missing}")
        wrong = [title for title, slug in toc if anchor(title) != slug]
        self.assertEqual(wrong, [], f"anchors that do not match their heading: {wrong}")


class TestHandoffNumbers(unittest.TestCase):
    def test_static_facts_match(self) -> None:
        script = ROOT / "scripts" / "check_handoff_numbers.py"
        self.assertTrue(script.is_file(), "the checker is missing")
        completed = subprocess.run([sys.executable, str(script)],
                                   capture_output=True, text=True, cwd=str(ROOT),
                                   timeout=300)
        self.assertEqual(
            completed.returncode, 0,
            "the handoff states numbers the tree no longer has:\n"
            f"{completed.stdout}{completed.stderr}")
        self.assertIn("rows checked", completed.stdout)
