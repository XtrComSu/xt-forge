"""No committed source may name a developer's home directory.

A hardcoded `/home/xtrcom/...` works on exactly one machine and leaks the author's
environment into the repository. One survived in `scripts/bench_three_tier.py` as a `node`
fallback for a long time because nothing checked for it; the handoff's own commit checklist
told a human to grep by hand before committing.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH_ROOTS = ("native", "xtforge", "scripts", "tests", "bin", "adapters")
SUFFIXES = {".go", ".py", ".sh", ".mjs", ".cmd", ".ps1", ".rs"}
PATTERN = re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/")


class TestNoHardcodedHomePaths(unittest.TestCase):
    def test_no_source_names_a_home_directory(self) -> None:
        offenders: list[str] = []
        for root in SEARCH_ROOTS:
            base = ROOT / root
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if not path.is_file() or path.suffix not in SUFFIXES:
                    continue
                if path.name == Path(__file__).name:
                    # This file quotes an example path to explain what it forbids.
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for number, line in enumerate(text.splitlines(), 1):
                    if PATTERN.search(line):
                        offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:100]}")
        self.assertEqual(offenders, [],
                         "hardcoded home directories in committed source:\n"
                         + "\n".join(offenders))
