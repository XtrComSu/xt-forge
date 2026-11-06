"""Tests for the high-concurrency swarm engine."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.swarm.worker import SwarmPool
from xtforge.core.swarm.mcts import speculative_solve
from xtforge.core.swarm.mapreduce import map_functions
from tests.test_re_pe import create_minimal_pe


def sample_job(x: int) -> int:
    return x * x


class TestSwarmEngine(unittest.TestCase):
    def test_swarm_pool_execution(self):
        pool = SwarmPool(workers=4)
        tasks = [lambda x=i: sample_job(x) for i in range(8)]
        results = pool.run_all(tasks)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r["ok"] for r in results))
        self.assertEqual([r["result"] for r in results], [i * i for i in range(8)])

    def test_speculative_solver_finds_xor_cipher(self):
        plain = b"SYSTEM_INTEGRITY_BYPASS_TOKEN_2026"
        key = 0x7A
        cipher = bytes(b ^ key for b in plain)
        blob = b"\x00" * 16 + cipher + b"\x00" * 16

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "data.bin"
            fpath.write_bytes(blob)

            res = speculative_solve(fpath, offset=16, size=len(cipher))
            self.assertTrue(res["ok"])
            self.assertEqual(res["winning_hypothesis"], "xor_single")
            self.assertEqual(res["key"], key)
            self.assertIn("SYSTEM_INTEGRITY_BYPASS_TOKEN_2026", res["decoded_sample"])

    def test_mapreduce_function_analysis(self):
        sec_code = b"\x90" * 0x1000
        pe_bytes = create_minimal_pe(
            bits=64,
            sections=[(".text", 0x1000, 0x1000, sec_code, 0x60000020)],
            exports=[("FnAlpha", 0x1010, 1), ("FnBeta", 0x1040, 2), ("FnGamma", 0x1080, 3)],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "sample.dll"
            fpath.write_bytes(pe_bytes)

            res = map_functions(fpath, workers=2)
            self.assertTrue(res["ok"])
            self.assertEqual(res["function_count"], 3)
            self.assertIn("FnAlpha", [f["name"] for f in res["functions"]])
            self.assertIn("FnBeta", [f["name"] for f in res["functions"]])
            self.assertIn("FnGamma", [f["name"] for f in res["functions"]])
