#!/usr/bin/env python3
"""Measure memory retrieval: lexical (FTS5) vs hybrid (FTS + embeddings).

Round 4 acceptance: recall@5 improves on a 50-query fixture and the
FTS-only path stays unchanged. This script reports both, from the same
fixture, in one run.

Usage:
    python3 scripts/bench_mem_recall.py [--fixture tests/fixtures/mem_recall.json]
                                       [--k 5] [--json]

Exit code 0 when hybrid >= lexical on recall@k, 1 otherwise (so it can gate a
release), unless --no-gate is passed.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.mem.embed import Embedder  # noqa: E402
from xtforge.core.mem.search import search  # noqa: E402
from xtforge.core.mem.store import Store  # noqa: E402


def build_store(path: Path, records: list[dict]) -> Store:
    store = Store(path)
    for rec in records:
        store.put(scope=rec.get("scope", "global"), kind=rec["kind"],
                  title=rec.get("title", ""), body=rec["body"],
                  tags=rec.get("tags", []), source="fixture",
                  id=rec["id"], pending=False)
    return store


def evaluate(store: Store, queries: list[dict], k: int,
             hybrid: bool, embedder: Embedder | None) -> dict:
    hits = 0
    reciprocal = 0.0
    misses: list[str] = []
    for item in queries:
        expected = set(item["expect"])
        out = search(store, item["q"], k=k, hybrid=hybrid, embedder=embedder,
                     token_budget=4000)
        ranked = [r["record"]["id"] for r in out["results"]]
        rank = next((i + 1 for i, rid in enumerate(ranked) if rid in expected), 0)
        if 0 < rank <= k:
            hits += 1
            reciprocal += 1.0 / rank
        else:
            misses.append(item["q"])
    total = max(1, len(queries))
    return {
        "queries": len(queries),
        "recall": round(hits / total, 4),
        "mrr": round(reciprocal / total, 4),
        "misses": misses,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default=str(ROOT / "tests" / "fixtures" / "mem_recall.json"))
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-gate", action="store_true",
                    help="report but do not fail on regression")
    args = ap.parse_args(argv)

    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    records, queries = fixture["records"], fixture["queries"]

    with tempfile.TemporaryDirectory(prefix="memrecall-") as tmp:
        lexical = build_store(Path(tmp) / "lexical.db", records)
        lex = evaluate(lexical, queries, args.k, hybrid=False,
                       embedder=Embedder(mode="off"))
        hybrid_store = build_store(Path(tmp) / "hybrid.db", records)
        hyb = evaluate(hybrid_store, queries, args.k, hybrid=True,
                       embedder=Embedder())
        lexical.close()
        hybrid_store.close()

    payload = {
        "fixture": args.fixture,
        "k": args.k,
        "records": len(records),
        "queries": len(queries),
        "lexical": {key: lex[key] for key in ("recall", "mrr")},
        "hybrid": {key: hyb[key] for key in ("recall", "mrr")},
        "delta": round(hyb["recall"] - lex["recall"], 4),
        "hybrid_misses": hyb["misses"],
        "lexical_misses": lex["misses"],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"mem recall@{args.k}  ({len(records)} records, "
              f"{len(queries)} queries)")
        print(f"  lexical (fts only)  recall {lex['recall']:.3f}  mrr {lex['mrr']:.3f}")
        print(f"  hybrid  (fts+embed)  recall {hyb['recall']:.3f}  mrr {hyb['mrr']:.3f}")
        print(f"  delta {payload['delta']:+.3f}")
        if hyb["misses"]:
            print(f"  hybrid still misses {len(hyb['misses'])} queries:")
            for q in hyb["misses"][:8]:
                print(f"    - {q}")
    if args.no_gate:
        return 0
    return 0 if hyb["recall"] >= lex["recall"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
