"""A goal belongs to the session that recorded it.

The plugin used to keep the active goal under one global storage key, so two
sessions in the same opencode instance overwrote each other's objective *and*
their approved check. The loser then saw its own completion claim rejected with
"evidence command is not approved" — for a command it had never chosen.

This test drives the real plugin file (the canon `xtforge sync` installs) with
a fake OpenCode context and asserts on the verdicts the context hook injects.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.plugin import manager  # noqa: E402

HARNESS = ROOT / "tests" / "plugin" / "goal_scope.mjs"


def canon() -> Path:
    """The plugin source `xtforge plugin install` ships."""
    return manager.source_dir() / "index.ts"


class TestGoalSessionScope(unittest.TestCase):
    """The goal record, and the approved check, belong to one session."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="goalscope-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.xt_home = self.tmp / "xt-home"
        self.xt_home.mkdir()

    def report(self) -> dict:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is required to drive the TS plugin")
        source = canon()
        if not source.is_file():
            self.skipTest(f"plugin canon missing: {source}")
        env = dict(os.environ)
        env.update({
            "XT_HOME": str(self.xt_home),
            "XT_FORGE_ROOT": str(ROOT),
            "XT_PYTHON": sys.executable,
            "XT_PLUGIN_PATH": str(source),
        })
        proc = subprocess.run(
            [node, str(HARNESS)], capture_output=True, text=True,
            cwd=str(ROOT), env=env, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr[-4000:])
        return json.loads(proc.stdout)

    def test_each_session_keeps_its_own_approved_check(self):
        report = self.report()
        self.assertEqual(report["aVerifyCmd"], "echo ses-a-approved")
        self.assertEqual(report["bVerifyCmd"], "echo ses-b-approved")
        self.assertEqual(report["aApproved"], ["echo ses-a-approved"])

    def test_a_claim_is_proved_by_its_own_sessions_check(self):
        report = self.report()
        self.assertEqual(report["aVerdict"], "pass",
                         "a session must verify against the check it recorded")

    def test_a_session_without_a_goal_approves_nothing(self):
        report = self.report()
        self.assertEqual(report["cVerdict"], "insufficient_evidence",
                         "a session must not inherit another session's check")

    def test_an_unapproved_command_is_not_proof(self):
        report = self.report()
        self.assertEqual(report["unapprovedVerdict"], "insufficient_evidence",
                         "only the approved list may prove a completion claim")


if __name__ == "__main__":
    unittest.main()
