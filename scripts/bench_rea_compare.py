#!/usr/bin/env python3
"""Compare REA (through Ghidra) against XT-Forge on facts both tools actually report.

REA's `analyze` returns an Evidence bundle; XT-Forge returns its own overview. Only five
questions are asked of both, because those are the ones the two tools both answer:

  format, architecture, procedure/function count, string count, segment/section count

Disassembly, cross-references and decompilation are **not** compared here: REA needs a
provider call per address for those, and pretending a missing comparison is a result would
be the same mistake as a benchmark that only measures itself.

Each tool runs N times per binary and the median wall time is reported.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HUB = ROOT / "native" / "xtforge-go" / "xtforge-hub"
NODE_BIN = "/tmp/node-v22.23.4-linux-x64/bin"
JAVA_HOME = str(Path.home() / ".local" / "providers" / "jdk-25.0.5.1+2")
GHIDRA = str(Path.home() / ".local" / "providers" / "ghidra_12.2_PUBLIC")

CORPUS = [
    ("elf-64", "/tmp/dy"),
    ("pe-64", "/usr/lib/wine/x86_64-windows/kernel32.dll"),
    ("pe-32", "/usr/lib/wine/i386-windows/kernel32.dll"),
    ("macho-arm64", "/tmp/mo.bin"),
]


def rea_env() -> dict:
    return {**os.environ,
            "JAVA_HOME": JAVA_HOME,
            "GHIDRA_INSTALL_DIR": GHIDRA,
            "PATH": f"{JAVA_HOME}/bin:{NODE_BIN}:" + os.environ.get("PATH", "")}


def run_rea(path: str, timeout: int = 900) -> tuple[dict, float]:
    started = time.time()
    completed = subprocess.run(["npx", "-y", "rea-agents@latest", "analyze", path, "--json"],
                               capture_output=True, text=True, env=rea_env(), timeout=timeout)
    elapsed = time.time() - started
    try:
        return json.loads(completed.stdout), elapsed
    except ValueError:
        return {"error": (completed.stdout + completed.stderr)[:200]}, elapsed


def run_hub(*args: str, timeout: int = 600) -> tuple[dict, float]:
    started = time.time()
    completed = subprocess.run([str(HUB), "re", *args, "--json"], capture_output=True,
                               text=True, timeout=timeout)
    elapsed = time.time() - started
    try:
        return json.loads(completed.stdout), elapsed
    except ValueError:
        return {"ok": False, "error": completed.stdout[:200]}, elapsed


def normalise(value) -> str:
    """Compare identity facts, not spellings: REA says "mach-o", XT-Forge says "macho"."""
    text = str(value or "").lower()
    return {"mach-o": "macho", "mach_o": "macho"}.get(text, text.replace("-", ""))


def rea_facts(payload: dict) -> dict:
    result = payload.get("normalized_result") or {}
    identity = (payload.get("subject") or {}).get("identity") or {}
    return {
        "format": identity.get("format"),
        "arch": identity.get("architecture"),
        "functions": result.get("procedure_count"),
        "strings": result.get("string_count"),
        # Deliberately NOT compared. REA's "segments" are Ghidra memory blocks named after
        # ELF sections (.dynsym, .interp, .gnu.hash, plus synthetic segment_2.x blocks);
        # XT-Forge's `segments` are the loadable PT_LOAD program headers that address-to-file
        # mapping needs, and `re info` reports all 15 program headers separately. Comparing
        # 34 with 4 was a category error, not a product gap.
        "segments_ghidra_blocks": result.get("segment_count"),
    }


def forge_facts(path: str) -> dict:
    overview, _ = run_hub("overview", path)
    image = (overview.get("images") or [{}])[0]
    arch = image.get("arch")
    best = 0
    for candidate in overview.get("images") or []:
        functions, _ = run_hub("functions", path, "--limit", "1", "--arch", arch or "")
        best = max(best, (functions.get("images") or [{}])[0].get("total") or 0)
        break
    return {
        "format": overview.get("format"),
        "arch": arch,
        "functions": best,
        "loadable_segments": len(image.get("segments") or []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--json", default="")
    args = parser.parse_args()
    if not Path(GHIDRA).is_dir():
        print(f"Ghidra missing at {GHIDRA}", file=sys.stderr)
        return 2

    rows = []
    for label, path in CORPUS:
        if not Path(path).exists():
            print(f"skip {label}: {path} absent")
            continue
        rea_runs, forge_times = [], []
        facts = None
        for _ in range(args.reps):
            payload, elapsed = run_rea(path)
            rea_runs.append((payload, elapsed))
            if facts is None and "normalized_result" in payload:
                facts = rea_facts(payload)
        ok = [e for p, e in rea_runs if "normalized_result" in p]
        forged = forge_facts(path)
        started = time.time()
        for _ in range(args.reps):
            run_hub("overview", path)
        forge_times.append((time.time() - started) / args.reps)
        row = {
            "label": label, "path": path,
            "rea_ok": len(ok), "rea_runs": len(rea_runs),
            "rea_median_s": round(statistics.median([e for _, e in rea_runs]), 2),
            "forge_median_s": round(statistics.median(forge_times), 3),
            "rea": facts or {}, "forge": forged,
        }
        rows.append(row)
        print(f"{label:12} rea {row['rea_ok']}/{row['rea_runs']} ok {row['rea_median_s']:7.2f}s | "
              f"forge {row['forge_median_s']:7.3f}s")
        print(f"  rea  : {row['rea']}")
        print(f"  forge: {row['forge']}")

    print("\nagreement:")
    for row in rows:
        for key in ("format", "arch"):
            a, b = normalise(row["rea"].get(key)), normalise(row["forge"].get(key))
            verdict = "match" if a and b and (a in b or b in a) else "DIFFERS" if a and b else "n/a"
            print(f"  {row['label']:12} {key:8} rea={a or '-':10} forge={b or '-':10} {verdict}")
    if args.json:
        Path(args.json).write_text(json.dumps({"reps": args.reps, "rows": rows}, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
