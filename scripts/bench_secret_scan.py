#!/usr/bin/env python3
"""Round-6 acceptance: the safety scan finds every planted secret, reports
nothing on plausible-but-clean code, and never writes to disk.

Gate (exit 1 on failure):
  1. zero false negatives on the planted-secrets fixture
  2. zero findings on the decoy fixture
  3. every pattern rule fires on the unsafe-code fixture
  4. every manifest rule fires on the dependency fixture
  5. the fixture tree is byte-identical afterwards (no writes)

Usage:
    python3 scripts/bench_secret_scan.py [--fixture tests/fixtures/secret_hunt]
                                        [--json] [--no-gate]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import scan as scanmod  # noqa: E402

DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "secret_hunt"


def snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(root.rglob("*")) if p.is_file()}


def rules_found(result: dict) -> set[str]:
    return {item["rule"] for item in result.get("findings", [])}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-gate", action="store_true")
    args = ap.parse_args(argv)

    fixture = Path(args.fixture)
    expected = json.loads((fixture / "expected.json").read_text(encoding="utf-8"))
    before = snapshot(fixture)

    leak = scanmod.scan_file(fixture / expected["leak_file"], mode="secrets")
    decoy = scanmod.scan_file(fixture / expected["decoy_file"], mode="secrets")
    risky = scanmod.scan_file(fixture / expected["pattern_file"], mode="patterns")
    manifest = scanmod.scan_manifest(fixture / expected["manifest_file"])
    tree = scanmod.scan_tree(fixture, mode="secrets")

    after = snapshot(fixture)

    want_secrets = set(expected["must_find_rules"])
    got_secrets = rules_found(leak)
    missing_secrets = sorted(want_secrets - got_secrets)

    want_patterns = set(expected["pattern_must_find_rules"])
    got_patterns = rules_found(risky)
    missing_patterns = sorted(want_patterns - got_patterns)

    want_manifest = set(expected["manifest_must_find_rules"])
    got_manifest = rules_found(manifest)
    missing_manifest = sorted(want_manifest - got_manifest)

    decoy_findings = decoy.get("count", 0)
    tree_decoy_hits = [f for f in tree.get("findings", [])
                       if expected["decoy_file"] in f["path"]]
    writes_detected = before != after

    payload = {
        "fixture": str(fixture),
        "secrets": {
            "planted": len(want_secrets), "found": len(want_secrets & got_secrets),
            "false_negatives": missing_secrets,
        },
        "patterns": {
            "expected": len(want_patterns), "found": len(want_patterns & got_patterns),
            "false_negatives": missing_patterns,
        },
        "manifest": {
            "expected": len(want_manifest), "found": len(want_manifest & got_manifest),
            "false_negatives": missing_manifest,
        },
        "decoy_findings": decoy_findings,
        "tree_decoy_findings": len(tree_decoy_hits),
        "tree_findings": tree.get("count", 0),
        "writes_detected": writes_detected,
        "pass": not (missing_secrets or missing_patterns or missing_manifest
                     or decoy_findings or tree_decoy_hits or writes_detected),
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        s, p, m = payload["secrets"], payload["patterns"], payload["manifest"]
        print(f"secret scan — fixture {fixture.name}")
        print(f"  secrets  {s['found']}/{s['planted']} planted found"
              + (f"  MISSING {s['false_negatives']}" if s['false_negatives'] else ""))
        print(f"  patterns {p['found']}/{p['expected']} rules fired"
              + (f"  MISSING {p['false_negatives']}" if p['false_negatives'] else ""))
        print(f"  manifest {m['found']}/{m['expected']} rules fired"
              + (f"  MISSING {m['false_negatives']}" if m['false_negatives'] else ""))
        print(f"  decoy findings: {decoy_findings} "
              f"(tree reports {len(tree_decoy_hits)} on the decoy file)")
        print(f"  tree findings: {payload['tree_findings']}")
        print(f"  writes during scan: {'YES' if writes_detected else 'none'}")
        print(f"  RESULT {'PASS' if payload['pass'] else 'FAIL'}")
    if args.no_gate:
        return 0
    return 0 if payload["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
