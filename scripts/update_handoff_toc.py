#!/usr/bin/env python3
"""Regenerate the handoff's contents block from its headings.

The contents block went stale within minutes of being written — by the same edit that added
the section describing it. Regenerating is mechanical, so it is a script rather than a rule
to remember; `tests/test_handoff_numbers.py` checks the result.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "docs" / "superpowers" / "HANDOFF-2026-11-23.md"


def anchor(title: str) -> str:
    slug = re.sub(r"[`*_]", "", title.lower())
    slug = re.sub(r"[^a-z0-9 \-]", "", slug)
    return re.sub(r"\s+", "-", slug.strip())


def main() -> int:
    lines = HANDOFF.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index("## Contents")
    except ValueError:
        print("no '## Contents' heading to replace", file=sys.stderr)
        return 2
    end = start + 1
    while end < len(lines) and not lines[end].startswith("## "):
        end += 1
    headings = [(i, line) for i, line in enumerate(lines) if re.match(r"^#{2,3} ", line)]
    entries = ["## Contents", ""]
    for index, line in headings:
        if line.startswith("## Contents"):
            continue
        depth = line.count("#", 0, 3) - 2
        title = line.lstrip("#").strip()
        entries.append("  " * max(depth, 0) + f"- [{title}](#{anchor(title)})")
    entries.append("")
    updated = lines[:start] + entries + lines[end:]
    HANDOFF.write_text("\n".join(updated) + "\n", encoding="utf-8")
    print(f"contents rebuilt: {len(entries) - 3} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
