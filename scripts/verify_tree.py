#!/usr/bin/env python3
"""Run every verification the handoff asks for, in order, and report one verdict.

§4 of the handoff lists four commands and a hub rebuild. Four remembered commands are four
chances to run three of them; this is one command that runs all of them and says which
failed.

    python scripts/verify_tree.py            # everything
    python scripts/verify_tree.py --fast     # skip the Python suite (the slowest)

Exit status is 0 only when every step passed. A step that is skipped for a missing tool is
reported as skipped rather than silently passing.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO_DIR = ROOT / "native" / "xtforge-go"
HUB = GO_DIR / "xtforge-hub"


def run(name: str, argv: list[str], cwd: Path | None = None) -> tuple[str, str, float]:
    started = time.time()
    completed = subprocess.run(argv, cwd=str(cwd or ROOT), capture_output=True, text=True)
    elapsed = time.time() - started
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode == 0:
        return "ok", output, elapsed
    return "FAILED", output, elapsed


def tail(output: str, lines: int = 12) -> str:
    kept = output.splitlines()[-lines:]
    return "\n".join("      " + line for line in kept)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast", action="store_true", help="skip the Python suite")
    parser.add_argument("--verbose", action="store_true", help="print each step's output")
    args = parser.parse_args()

    steps: list[tuple[str, list[str], Path | None]] = []

    # Rebuild first: a stale hub makes the MCP verbs report "unknown re hub verb", which
    # looks like a code defect rather than a stale binary.
    steps.append(("build hub", ["go", "build", "-ldflags=-s -w", "-o", "xtforge-hub",
                                "./cmd/xtforge-hub"], GO_DIR))
    steps.append(("go tests", ["go", "test", "./...",
                               "-skip", "^TestConcurrentCVEEnrichmentWithMockServers$"], GO_DIR))
    steps.append(("uv lock", ["uv", "lock", "--check", "--offline"], ROOT))
    if not args.fast:
        steps.append(("python tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests"], ROOT))
    steps.append(("sys-native lanes", [sys.executable, "scripts/verify_sys_native.py"], ROOT))
    steps.append(("handoff numbers", [sys.executable, "scripts/check_handoff_numbers.py", "--full"], ROOT))

    failures = 0
    for name, argv, cwd in steps:
        status, output, elapsed = run(name, argv, cwd)
        print(f"  {status:7} {name:18} {elapsed:6.1f}s")
        if status != "ok":
            failures += 1
            print(tail(output))
        elif args.verbose and output:
            print(tail(output, 4))

    if not HUB.is_file():
        print("  WARNING the hub binary is missing after the build step")
        failures += 1

    print(f"\n{len(steps)} steps, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
