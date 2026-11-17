"""Tests for `xtforge goal check` metacognitive vibe-check & negative-memory warnings."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.goal.check import check_progress
from xtforge.core.mem.store import Store

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"


class TestGoalCheck(unittest.TestCase):
    def test_detects_scope_bloat_drift_and_negative_memory(self):
        with tempfile.TemporaryDirectory() as td:
            old_home = os.environ.get("XT_HOME")
            os.environ["XT_HOME"] = td
            try:
                st = Store(Path(td) / "mem.db")
                st.record_failure(
                    scope="global",
                    title="Do not skip SQLite WAL checkpoint",
                    body="Skipping checkpoint during backup causes truncated wal reads",
                    error_sig="ERR_WAL_TRUNC",
                )
                st.close()

                res = check_progress(
                    objective="Refactor SQLite WAL checkpoint handling",
                    plan_text="touch unrelated logging modules",
                    criteria=["checkpoint durability verified"],
                    files_touched=[f"f{i}.py" for i in range(10)],
                    file_cap=5,
                    root=td,
                    interactive=False,
                )
                self.assertTrue(res["ok"])
                kinds = {f["kind"] for f in res["findings"]}
                self.assertIn("scope_bloat", kinds)
                self.assertIn("criteria_drift", kinds)
                self.assertIn("negative_memory", kinds)
                self.assertEqual(res["status"], "caution")
            finally:
                if old_home is None:
                    os.environ.pop("XT_HOME", None)
                else:
                    os.environ["XT_HOME"] = old_home

    def test_cli_goal_check(self):
        with tempfile.TemporaryDirectory() as td:
            env = {**os.environ, "XT_HOME": td, "XT_NONINTERACTIVE": "1"}
            res = subprocess.run(
                [str(BIN), "goal", "check", "Verify authentication tests",
                 "--criteria", "oauth handshake passes", "--workdir", td, "--json"],
                capture_output=True, text=True, env=env, cwd=str(ROOT),
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertEqual(data["status"], "caution")


if __name__ == "__main__":
    unittest.main()
