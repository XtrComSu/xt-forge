#!/usr/bin/env python3
"""Reproduction: concurrent taste writes lose evidence.

The store absorbs a signal by reading the learning, adding to it and writing
it back. SQLite gives a deferred transaction: the read happens outside the
write lock, so two processes can both read the same row and both write it
back. The second write overwrites the first's counter — one piece of evidence
is gone, and the rule never reaches `enforced`.

    python3 scripts/repro_taste_lost_update.py [--writers=4] [--json]

Exits non-zero when evidence was lost.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.taste.store import TasteStore  # noqa: E402

STATEMENT = "Always use --json for command output."


def writer(db: str, index: int) -> None:
    """One process, one learning, one commit."""
    store = TasteStore(db)
    try:
        store.learn(STATEMENT)
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--writers", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    tmp = tempfile.mkdtemp(prefix="taste-race-")
    db = str(Path(tmp) / "taste.db")

    procs = [subprocess.Popen([sys.executable, __file__, "--child", db,
                               str(i)]) for i in range(args.writers)]
    for proc in procs:
        proc.wait()

    store = TasteStore(db)
    try:
        row = store.search(query="json command output")[0]
    finally:
        store.close()

    result = {
        "writers": args.writers,
        "expected_evidence": args.writers,
        "actual_evidence": row["evidence"],
        "expected_alpha": 0.5 + args.writers,
        "actual_alpha": row["alpha"],
        "status": row["status"],
        "lost": row["evidence"] < args.writers,
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"writers: {result['writers']}")
        print(f"  evidence: {result['actual_evidence']} "
              f"(expected {result['expected_evidence']})")
        print(f"  alpha:    {result['actual_alpha']} "
              f"(expected {result['expected_alpha']})")
        print(f"  status:   {result['status']}")
        print("  LOST UPDATE" if result["lost"] else "  ok")
    return 1 if result["lost"] else 0


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--child":
        writer(sys.argv[2], int(sys.argv[3]))
        sys.exit(0)
    sys.exit(main())
