"""Reference targets must match the disassembler's own annotation.

Every backwards RIP-relative reference in a 64-bit binary was once off by 2^32: the vendored
decoder reports `Mem.Disp` unsigned, so `leaq -0x3f(%rip)` produced 0x100001070 instead of
0x1070. Branch targets were unaffected because `x86asm.Rel` is signed, which is exactly why
the bug had no obvious symptom.

This test compares every reference target against `llvm-objdump`'s `# 0x…` annotation for the
same site, so a future addressing error fails here instead of surfacing as a strange address
in a report.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE = """
#include <stdio.h>
static const char *message = "warn: %s\\n";
__attribute__((noinline)) void report(int v) { printf("value=%d\\n", v); }
__attribute__((noinline)) void warn(const char *m) { fprintf(stderr, message, m); }
int main(void) { report(7); warn("careful"); return 0; }
"""

SITE = re.compile(r"^\s+([0-9a-f]+):\s+(.*)$")
TARGET = re.compile(r"#\s*(0x[0-9a-f]+)")


def _oracle(path: Path) -> dict[int, int]:
    out = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", str(path)],
                         capture_output=True, text=True).stdout
    found: dict[int, int] = {}
    for line in out.splitlines():
        site = SITE.match(line)
        if not site:
            continue
        target = TARGET.search(site.group(2))
        if target:
            found[int(site.group(1), 16)] = int(target.group(1), 16)
    return found


def _ours(path: Path) -> dict[int, list[int]]:
    proc = subprocess.run([sys.executable, "-m", "xtforge.cli", "re", "xrefs-native",
                           str(path), "--max-functions", "20000", "--limit", "2000",
                           "--json"], capture_output=True, text=True, cwd=str(ROOT))
    payload = json.loads(proc.stdout)
    found: dict[int, list[int]] = {}
    for reference in payload.get("references") or []:
        found.setdefault(reference["site"], []).append(reference["target"])
    return found


@unittest.skipUnless(shutil.which("clang") and shutil.which("llvm-objdump"),
                     "clang and llvm-objdump required")
class TestReferenceTargets(unittest.TestCase):
    def test_targets_match_objdump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "r.c"
            source.write_text(SOURCE)
            binary = Path(tmp) / "r.bin"
            subprocess.run(["clang", "-O1", "-fno-inline", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            oracle = _oracle(binary)
            ours = _ours(binary)

        compared = sorted(set(oracle) & set(ours))
        self.assertGreaterEqual(len(compared), 5,
                                "too few references compared to be meaningful")
        mismatched = [(site, oracle[site], ours[site]) for site in compared
                      if oracle[site] not in ours[site]]
        self.assertEqual(mismatched, [],
                         "reference targets disagree with llvm-objdump: "
                         + ", ".join(f"{site:#x} want {want:#x} got {[hex(g) for g in got]}"
                                     for site, want, got in mismatched))

    def test_backwards_and_forwards_both_resolve(self) -> None:
        # A backwards reference is the case that was broken; a forwards one guards against
        # "fixing" it by simply negating every displacement.
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "r.c"
            source.write_text(SOURCE)
            binary = Path(tmp) / "r.bin"
            subprocess.run(["clang", "-O1", "-fno-inline", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            ours = _ours(binary)
        targets = [target for values in ours.values() for target in values]
        sites = [site for site, values in ours.items() for _ in values]
        backwards = [i for i, (site, target) in enumerate(zip(sites, targets)) if target < site]
        forwards = [i for i, (site, target) in enumerate(zip(sites, targets)) if target > site]
        self.assertTrue(backwards, "no backwards reference in the fixture")
        self.assertTrue(forwards, "no forwards reference in the fixture")
