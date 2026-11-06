"""Tests for xtforge swarm CLI."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.test_re_pe import create_minimal_pe


class TestSwarmCLI(unittest.TestCase):
    def test_swarm_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "swarm", "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("map", res.stdout)
        self.assertIn("solve", res.stdout)

    def test_swarm_solve_json(self):
        plain = b"AUTHENTICATED_SESSION_KEY_ROBLOX"
        key = 0x42
        cipher = bytes(b ^ key for b in plain)
        blob = b"\x00" * 32 + cipher + b"\x00" * 32

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "cipher.bin"
            fpath.write_bytes(blob)

            res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "xtforge.cli",
                    "--json",
                    "swarm",
                    "solve",
                    str(fpath),
                    "--offset",
                    "32",
                    "--size",
                    str(len(cipher)),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertTrue(data.get("ok"))
            self.assertEqual(data.get("winning_hypothesis"), "xor_single")
            self.assertEqual(data.get("key"), 0x42)
