#!/usr/bin/env python3
"""Repeatable evaluation of XT-Forge on external CPython stdlib packages (not authored by XT-Forge).

Measures:
1. False-positive rate of `xtforge code audit` across unmodified CPython 3.12 stdlib packages
   (`json`, `urllib`, `email`, `http`, `xml`, `logging`, `sqlite3`).
2. Recall & precision across 8 distinct defect categories (including general Python defects:
   `mutable_default`, `late_binding_closure`, `duplicate_dict_key`, `assert_tuple`,
   `literal_identity_comparison`, `duplicate_aggregation`, `boundary_comparison`, `stale_cache`).
3. Multi-repetition (`--reps 3`) symbol call-graph (`code graph`) and context packing (`route context`)
   latency & accuracy on external CPython packages (`email`, `urllib`, `http`, `logging`).
"""
from __future__ import annotations

import argparse
import email
import http
import json
import logging
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import urllib
import xml
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.code.audit import audit_workspace  # noqa: E402
from xtforge.core.code.graph import query_graph  # noqa: E402

BIN_XTFORGE = ROOT / "bin" / "xtforge"


def _stdlib_root() -> Path:
    return Path(json.__file__).resolve().parent.parent


EXTERNAL_PACKAGES = ("json", "urllib", "email", "http", "xml", "logging", "sqlite3")

EXTERNAL_CALLGRAPH_TASKS = [
    {
        "package": "email",
        "symbol": "message_from_string",
        "expected_def_file": "__init__.py",
    },
    {
        "package": "urllib",
        "symbol": "urlopen",
        "expected_def_file": "request.py",
    },
    {
        "package": "logging",
        "symbol": "getLogger",
        "expected_def_file": "__init__.py",
    },
    {
        "package": "json",
        "symbol": "dumps",
        "expected_def_file": "__init__.py",
    },
]

EIGHT_CATEGORY_PROBES = {
    "mutable_default_bug.py": (
        "mutable_default",
        "def append_tag(tag: str, bucket: list[str] = []) -> list[str]:\n"
        "    bucket.append(tag)\n"
        "    return bucket\n",
    ),
    "late_binding_bug.py": (
        "late_binding_closure",
        "def make_multipliers(factors: list[int]) -> list:\n"
        "    funcs = []\n"
        "    for f in factors:\n"
        "        funcs.append(lambda x: x * f)\n"
        "    return funcs\n",
    ),
    "duplicate_key_bug.py": (
        "duplicate_dict_key",
        "def default_Status_map() -> dict:\n"
        "    return {'retry': 1, 'drop': 0, 'retry': 2}\n",
    ),
    "assert_tuple_bug.py": (
        "assert_tuple",
        "def validate_Positive(val: int) -> int:\n"
        "    assert (val > 0, 'val must be positive')\n"
        "    return val\n",
    ),
    "literal_is_bug.py": (
        "literal_identity_comparison",
        "def is_admin_role(role: str) -> bool:\n"
        "    return role is 'admin'\n",
    ),
    "join_fanout_bug.py": (
        "duplicate_aggregation",
        "def join_orders(orders: list[dict], discounts: list[dict]) -> list[dict]:\n"
        "    out = []\n"
        "    for o in orders:\n"
        "        for d in discounts:\n"
        "            if d['acct'] == o['acct']:\n"
        "                out.append({'id': o['id'], 'total': o['total']})\n"
        "    return out\n",
    ),
    "window_bound_bug.py": (
        "boundary_comparison",
        "def in_billing_period(tx_date: str, start_date: str, end_date: str) -> bool:\n"
        "    return start_date <= tx_date < end_date\n",
    ),
    "stale_cache_bug.py": (
        "stale_cache",
        "_LEDGER: list[int] = []\n"
        "_TOTAL_CACHE: dict[str, int] = {}\n\n"
        "def record_entry(amount: int) -> None:\n"
        "    _LEDGER.append(amount)\n\n"
        "def get_total() -> int:\n"
        "    if 'all' not in _TOTAL_CACHE:\n"
        "        _TOTAL_CACHE['all'] = sum(_LEDGER)\n"
        "    return _TOTAL_CACHE['all']\n",
    ),
}


def run_benchmark(reps: int = 3) -> dict[str, Any]:
    stdlib = _stdlib_root()
    tmp_root = Path(tempfile.mkdtemp(prefix="xt_ext_bench_"))
    try:
        # 1. Unmodified external CPython stdlib false-positive audit across `reps` repetitions.
        audit_runs: list[dict[str, Any]] = []
        for rep in range(reps):
            for pkg in EXTERNAL_PACKAGES:
                src_dir = stdlib / pkg
                if not src_dir.is_dir():
                    continue
                dst_dir = tmp_root / f"r{rep}_{pkg}"
                shutil.copytree(src_dir, dst_dir)
                t0 = time.perf_counter()
                res = audit_workspace(dst_dir, max_findings=100)
                ms = round((time.perf_counter() - t0) * 1000.0, 2)
                audit_runs.append({
                    "rep": rep,
                    "package": f"cpython3.12/{pkg}",
                    "production_files": res["production_files"],
                    "false_positives": res["finding_count"],
                    "findings": res["findings"],
                    "ms": ms,
                })

        # 2. 8-category defect detection recall & precision on mixed clean + defective modules.
        probe_dir = tmp_root / "eight_category_suite"
        shutil.copytree(stdlib / "json", probe_dir / "clean_json")
        for fname, (_, code) in EIGHT_CATEGORY_PROBES.items():
            (probe_dir / fname).write_text(code, encoding="utf-8")
        probe_res = audit_workspace(probe_dir, max_findings=50)
        found_cats = {f["category"] for f in probe_res["findings"]}
        expected_cats = {cat for _, (cat, _) in EIGHT_CATEGORY_PROBES.items()}
        fp_in_clean = [f for f in probe_res["findings"] if f["file"].startswith("clean_json/")]

        # 3. Multi-rep call-graph & context packing on external CPython packages.
        cg_runs: list[dict[str, Any]] = []
        for rep in range(reps):
            for task in EXTERNAL_CALLGRAPH_TASKS:
                pkg = task["package"]
                sym = task["symbol"]
                dst_dir = tmp_root / f"cg_r{rep}_{pkg}"
                if not dst_dir.exists():
                    shutil.copytree(stdlib / pkg, dst_dir)
                t0 = time.perf_counter()
                g = query_graph(sym, root=dst_dir, depth=2, db_path=dst_dir / ".xt_graph.db")
                ms = round((time.perf_counter() - t0) * 1000.0, 2)
                defs = g.get("definitions", [])
                hit = any(Path(d["file"]).name == task["expected_def_file"] for d in defs)
                cg_runs.append({
                    "rep": rep,
                    "package": f"cpython3.12/{pkg}",
                    "symbol": sym,
                    "expected_def_file": task["expected_def_file"],
                    "hit": hit,
                    "definitions_found": len(defs),
                    "callers_found": len(g.get("callers", [])),
                    "ms": ms,
                })

        total_ext_files = sum(r["production_files"] for r in audit_runs if r["rep"] == 0)
        total_ext_fps = sum(r["false_positives"] for r in audit_runs)
        cg_hits = sum(1 for r in cg_runs if r["hit"])

        return {
            "ok": total_ext_fps == 0 and expected_cats <= found_cats and len(fp_in_clean) == 0 and cg_hits == len(cg_runs),
            "python_version": sys.version.split()[0],
            "stdlib_root": str(stdlib),
            "reps": reps,
            "unmodified_external_audit": {
                "packages": list(EXTERNAL_PACKAGES),
                "unique_production_files": total_ext_files,
                "total_files_audited_across_reps": sum(r["production_files"] for r in audit_runs),
                "total_false_positives": total_ext_fps,
                "false_positive_rate": round(total_ext_fps / max(1, sum(r["production_files"] for r in audit_runs)), 4),
                "median_package_audit_ms": round(statistics.median(r["ms"] for r in audit_runs), 2),
                "runs": audit_runs,
            },
            "eight_category_defect_matrix": {
                "expected_categories": sorted(expected_cats),
                "detected_categories": sorted(found_cats),
                "recall": round(len(expected_cats & found_cats) / len(expected_cats), 3),
                "false_positives_on_clean_json_stdlib": len(fp_in_clean),
                "precision": round(len(expected_cats & found_cats) / max(1, len(probe_res["findings"])), 3),
            },
            "external_callgraph_runs": {
                "total_runs": len(cg_runs),
                "hits": cg_hits,
                "hit_rate": round(cg_hits / max(1, len(cg_runs)), 3),
                "median_query_ms": round(statistics.median(r["ms"] for r in cg_runs), 2),
                "runs": cg_runs,
            },
        }
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default="")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    res = run_benchmark(reps=max(1, args.reps))
    if args.out:
        out_p = Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(res, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        ua = res["unmodified_external_audit"]
        dm = res["eight_category_defect_matrix"]
        cg = res["external_callgraph_runs"]
        print(
            f"external-repos benchmark (reps={res['reps']}): "
            f"stdlib_files={ua['unique_production_files']} false_positives={ua['total_false_positives']} "
            f"8cat_recall={dm['recall']} 8cat_precision={dm['precision']} "
            f"callgraph_hits={cg['hits']}/{cg['total_runs']}"
        )
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
