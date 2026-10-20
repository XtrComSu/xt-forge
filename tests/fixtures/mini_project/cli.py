"""Command-line entry point.

Thin by design: parse, dispatch, print. Anything interesting lives in the
modules it wires together.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mini")
    parser.add_argument("--json", action="store_true", help="machine output")
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser("run", help="drain the queue")
    run.add_argument("--limit", type=int, default=100)
    run.add_argument("--db", default="mini.db")
    stats = sub.add_parser("stats", help="show metrics")
    stats.add_argument("--db", default="mini.db")
    return parser


def emit(payload: Any, as_json: bool) -> None:
    """Print a result; JSON when asked, otherwise a short human summary."""
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
        return 0
    if args.command == "run":
        emit({"status": "noop", "limit": args.limit}, args.json)
        return 0
    emit({"status": "noop"}, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
