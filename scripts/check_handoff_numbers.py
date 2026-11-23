#!/usr/bin/env python3
"""Re-measure the numbers the handoff states, and report any that no longer hold.

A handoff whose first table is wrong is worse than no table: every later claim inherits the
doubt, and a reader cannot tell which figures were measured today from which were copied
forward. Last round that table claimed 78 files and 268 tests when the tree had 109 files
and 269. This script turns that from a thing to remember into a thing to run.

Fast checks (default) are static: file counts, line counts, HEAD, dirty paths.
`--full` also runs the Go and Python suites, which takes about a minute.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "docs" / "superpowers" / "HANDOFF-2026-11-23.md"
GO_DIR = ROOT / "native" / "xtforge-go"


def shell(argv: list[str], cwd: Path | None = None, timeout: int = 900) -> str:
    # unittest writes its summary to stderr, so both streams are captured.
    completed = subprocess.run(argv, cwd=str(cwd or ROOT), capture_output=True,
                               text=True, timeout=timeout)
    return completed.stdout + completed.stderr


def handoff_text() -> str:
    if not HANDOFF.is_file():
        raise SystemExit(f"handoff not found: {HANDOFF}")
    return HANDOFF.read_text(encoding="utf-8")


def stated(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def measurements(full: bool) -> dict[str, str]:
    files = sorted((GO_DIR / "internal" / "sysimage").glob("*.go"))
    lines = sum(len(path.read_text(encoding="utf-8", errors="replace").splitlines())
                for path in files)
    facts = {
        "head": shell(["git", "rev-parse", "--short", "HEAD"], ROOT).strip(),
        "dirty": str(len([l for l in shell(["git", "status", "--short"], ROOT).splitlines() if l.strip()])),
        "files": str(len(files)),
        "lines": f"{lines:,}",
    }
    if full:
        go_output = shell(["go", "test", "./internal/sysimage/", "-count=1", "-v"], GO_DIR)
        facts["go_pass"] = str(len(re.findall(r"^--- PASS", go_output, re.M)))
        facts["go_skip"] = str(len(re.findall(r"^--- SKIP", go_output, re.M)))
        facts["go_fail"] = str(len(re.findall(r"^--- FAIL", go_output, re.M)))
        py_output = shell([sys.executable, "-m", "unittest", "discover", "-s", "tests"], ROOT)
        match = re.search(r"Ran (\d+) tests", py_output)
        facts["python_tests"] = match.group(1) if match else "?"
    return facts


# Rows compared for correctness. Dirty-path count is deliberately absent: it changes the
# moment anyone edits a file, so checking it would fail on every run and teach the reader to
# ignore the script.
CHECKS = [
    ("head", r"\| HEAD \| `([0-9a-f]{7})"),
    ("go_pass", r"\| Go tests, `internal/sysimage` \| \*\*(\d+) pass\*\*"),
    ("go_skip", r"\| Go tests, `internal/sysimage` \| \*\*\d+ pass\*\*, (\d+) skip"),
    ("python_tests", r"\| Python suite \| \*\*(\d+) tests"),
    ("files", r"`internal/sysimage` \*\*(\d+) files"),
    ("lines", r"\*\*\d+ files / ([\d,]+) lines\*\*"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true",
                        help="also run the Go and Python suites (about a minute)")
    args = parser.parse_args()

    text = handoff_text()
    facts = measurements(args.full)
    claimed_dirty = stated(text, r"\| Dirty paths \| \*\*(\d+)\*\*")
    if claimed_dirty is not None:
        print(f"  info  dirty          handoff says {claimed_dirty}, tree has {facts['dirty']} "
              f"(not compared: this changes with every edit)")
    failures = 0
    checked = 0
    for key, pattern in CHECKS:
        claimed = stated(text, pattern)
        if claimed is None:
            continue
        if key not in facts:
            print(f"  SKIP  {key:14} claimed {claimed} (needs --full)")
            continue
        checked += 1
        actual = facts[key]
        if claimed.replace(",", "") == actual.replace(",", ""):
            print(f"  ok    {key:14} {actual}")
        else:
            failures += 1
            print(f"  WRONG {key:14} handoff says {claimed}, tree has {actual}")
    if checked == 0:
        print("no comparable rows found; has the table moved?")
        return 2
    print(f"\n{checked} rows checked, {failures} wrong")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
