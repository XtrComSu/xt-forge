"""Tests for session checkpointing (fork and rewind)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.session_checkpoint import (
    create_checkpoint,
    restore_checkpoint,
    list_checkpoints,
    delete_checkpoint,
)


class TestSessionCheckpoint(unittest.TestCase):
    def test_fork_and_rewind(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / ".xt-forge"
            home.mkdir()
            flash = home / "flash"
            flash.mkdir()

            mem_db = home / "mem.db"
            mem_db.write_text("initial memory state", encoding="utf-8")
            (flash / "note1.txt").write_text("initial flash note", encoding="utf-8")

            # Fork/Checkpoint 1
            res_cp = create_checkpoint(name="hypothesis_a", base_dir=home)
            self.assertTrue(res_cp["ok"])
            cp_id = res_cp["id"]

            # Mutate state
            mem_db.write_text("corrupted hypothesis state", encoding="utf-8")
            (flash / "note1.txt").write_text("corrupted note", encoding="utf-8")
            (flash / "extra.txt").write_text("junk", encoding="utf-8")

            # Check listing
            cps = list_checkpoints(base_dir=home)
            self.assertEqual(len(cps), 1)
            self.assertEqual(cps[0]["id"], cp_id)
            self.assertEqual(cps[0]["name"], "hypothesis_a")

            # Rewind to Checkpoint 1
            res_rewind = restore_checkpoint(cp_id, base_dir=home)
            self.assertTrue(res_rewind["ok"])

            # Verify memory and flash restored
            self.assertEqual(mem_db.read_text(encoding="utf-8"), "initial memory state")
            self.assertEqual((flash / "note1.txt").read_text(encoding="utf-8"), "initial flash note")
            self.assertFalse((flash / "extra.txt").exists())

            # Delete checkpoint
            res_del = delete_checkpoint(cp_id, base_dir=home)
            self.assertTrue(res_del["ok"])
            self.assertEqual(len(list_checkpoints(base_dir=home)), 0)

    def test_session_cli(self):
        import json
        import os
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["XT_HOME"] = tmpdir

            # Fork
            res = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "session", "fork", "--name", "cli_test"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            self.assertTrue(data.get("ok"))
            cp_id = data.get("id")

            # List
            res_list = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "session", "list"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res_list.returncode, 0, res_list.stderr)
            data_list = json.loads(res_list.stdout)
            self.assertEqual(data_list.get("count"), 1)
            self.assertEqual(data_list["checkpoints"][0]["id"], cp_id)

            # Rewind
            res_rewind = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "--json", "session", "rewind", cp_id],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res_rewind.returncode, 0, res_rewind.stderr)
            data_rewind = json.loads(res_rewind.stdout)
            self.assertTrue(data_rewind.get("ok"))

