"""Tests for `guard mode` (explore|ask|auto), explore-mode gating, and JSONL audit log."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.route import guard

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"


class TestGuardModes(unittest.TestCase):
    def test_python_guard_mode_and_audit(self):
        with tempfile.TemporaryDirectory() as td:
            old_home = os.environ.get("XT_HOME")
            old_mode = os.environ.get("XT_PERM_MODE")
            os.environ["XT_HOME"] = td
            os.environ.pop("XT_PERM_MODE", None)
            try:
                guard.set_perm_mode("explore")
                self.assertEqual(guard.perm_mode(), "explore")
                with self.assertRaises(guard.Denied) as ctx:
                    guard.check_write_mode()
                self.assertEqual(ctx.exception.code, "explore_mode")

                audit_files = list((Path(td) / "audit").glob("*.jsonl"))
                self.assertEqual(len(audit_files), 1)
                lines = audit_files[0].read_text().splitlines()
                self.assertGreaterEqual(len(lines), 2)
                self.assertEqual(json.loads(lines[-1])["outcome"], "denied_explore_mode")

                guard.set_perm_mode("auto")
                guard.check_write_mode()
            finally:
                if old_home is None:
                    os.environ.pop("XT_HOME", None)
                else:
                    os.environ["XT_HOME"] = old_home
                if old_mode is not None:
                    os.environ["XT_PERM_MODE"] = old_mode

    def test_cli_guard_mode_native_and_python(self):
        for force_py in ("0", "1"):
            with tempfile.TemporaryDirectory() as td:
                env = {**os.environ, "XT_HOME": td, "XT_FORCE_PYTHON": force_py}
                r1 = subprocess.run(
                    [str(BIN), "guard", "mode", "explore", "--json"],
                    capture_output=True, text=True, env=env, cwd=str(ROOT),
                )
                self.assertEqual(r1.returncode, 0, r1.stderr)
                self.assertEqual(json.loads(r1.stdout)["mode"], "explore")
                r2 = subprocess.run(
                    [str(BIN), "guard", "mode", "--json"],
                    capture_output=True, text=True, env=env, cwd=str(ROOT),
                )
                self.assertEqual(r2.returncode, 0, r2.stderr)
                self.assertEqual(json.loads(r2.stdout)["mode"], "explore")


if __name__ == "__main__":
    unittest.main()
