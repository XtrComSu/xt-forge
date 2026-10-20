"""Contract tests for round 11: loop grammar and scheduling policy.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import loop as loopmod  # noqa: E402


class TestIntervals(unittest.TestCase):
    def test_parse_table(self):
        table = {
            "30s": 30, "5m": 300, "1h": 3600, "2h": 7200, "1d": 86400,
            "1w": 604800, "every 2 hours": 7200, "every 5m": 300,
            "hourly": 3600, "daily": 86400, "weekly": 604800,
            "2 hours": 7200, "3 days": 259200,
        }
        for text, seconds in table.items():
            self.assertEqual(loopmod.parse_interval(text), seconds, text)

    def test_bad_intervals(self):
        for text in ("", "often", "5", "m", "-3h", "5 lightyears"):
            self.assertIsNone(loopmod.parse_interval(text), text)

    def test_normalize_snaps_to_clean_steps(self):
        cases = [(60, 60, "1m"), (47 * 60, 3600, "1h"), (90, 120, "2m"),
                 (25 * 60, 30 * 60, "30m"), (5 * 3600, 6 * 3600, "6h"),
                 (2 * 86400, 2 * 86400, "2d"), (10 * 86400, 7 * 86400, "7d")]
        for raw, want_seconds, want_label in cases:
            seconds, label = loopmod.normalize_interval(raw)
            self.assertEqual((seconds, label), (want_seconds, want_label),
                             f"{raw}s")

    def test_normalize_is_deterministic(self):
        self.assertEqual(loopmod.normalize_interval(1234),
                         loopmod.normalize_interval(1234))

    def test_delay_is_clamped(self):
        self.assertEqual(loopmod.clamp_delay(5), 60)
        self.assertEqual(loopmod.clamp_delay(99999), 3600)
        self.assertEqual(loopmod.clamp_delay(None), 3600)


class TestCommandGrammar(unittest.TestCase):
    def test_interval_then_task(self):
        plan = loopmod.parse_command("2h check the CI")
        self.assertEqual(plan["mode"], "fixed")
        self.assertEqual(plan["task"], "check the CI")
        self.assertEqual(plan["interval"], 7200)

    def test_task_then_interval(self):
        plan = loopmod.parse_command("check the CI every 30m")
        self.assertEqual(plan["mode"], "fixed")
        self.assertEqual(plan["task"], "check the CI")
        self.assertEqual(plan["interval"], 1800)

    def test_task_only_is_self_paced(self):
        plan = loopmod.parse_command("tidy the notes")
        self.assertEqual(plan["mode"], "self-paced")
        self.assertEqual(plan["task"], "tidy the notes")
        self.assertIsNone(plan["interval"])

    def test_interval_only_uses_default_task(self):
        plan = loopmod.parse_command("2h", default_task="from loop.md")
        self.assertEqual(plan["mode"], "fixed")
        self.assertEqual(plan["task"], "from loop.md")

    def test_empty_uses_default_task(self):
        plan = loopmod.parse_command("", default_task="from loop.md")
        self.assertEqual(plan["mode"], "self-paced")
        self.assertEqual(plan["task"], "from loop.md")

    def test_task_is_fenced_not_instructions(self):
        """Task text is data: it is preserved verbatim and bounded."""
        plan = loopmod.parse_command('2h run tests && echo "done"')
        self.assertIn('echo "done"', plan["task"])
        self.assertLessEqual(len(plan["task"]), loopmod.MAX_TASK_CHARS)


class TestMarkers(unittest.TestCase):
    def test_next_marker(self):
        res = loopmod.parse_markers('<loop-next delay="300" reason="still running"/>')
        self.assertEqual(res["action"], "next")
        self.assertEqual(res["delay"], 300)
        self.assertEqual(res["reason"], "still running")

    def test_done_marker(self):
        res = loopmod.parse_markers('<loop-done reason="deploy is green"/>')
        self.assertEqual(res["action"], "done")
        self.assertEqual(res["reason"], "deploy is green")

    def test_conflicting_markers_stop(self):
        res = loopmod.parse_markers('<loop-next delay="60"/><loop-done/>')
        self.assertEqual(res["action"], "conflict")

    def test_missing_marker_is_a_gap(self):
        res = loopmod.parse_markers("I think we are finished.")
        self.assertIsNone(res["action"])
        self.assertIn("gap", res)

    def test_delay_out_of_range_is_clamped(self):
        res = loopmod.parse_markers('<loop-next delay="99999"/>')
        self.assertEqual(res["delay"], 3600)


class TestIterationPolicy(unittest.TestCase):
    def test_done_stops(self):
        res = loopmod.next_delay(300, loopmod.parse_markers('<loop-done reason="ok"/>'))
        self.assertEqual(res["action"], "stop")

    def test_next_schedules(self):
        res = loopmod.next_delay(300, loopmod.parse_markers('<loop-next delay="600"/>'))
        self.assertEqual(res["action"], "next")
        self.assertEqual(res["delay"], 600)

    def test_first_omission_gets_one_safety_check(self):
        res = loopmod.next_delay(300, loopmod.parse_markers("nothing"), omit_streak=0)
        self.assertEqual(res["action"], "safety_check")
        self.assertEqual(res["delay"], 1200)

    def test_second_omission_stops(self):
        res = loopmod.next_delay(300, loopmod.parse_markers("nothing"), omit_streak=1)
        self.assertEqual(res["action"], "stop")

    def test_quiet_streak_backs_off(self):
        marker = loopmod.parse_markers('<loop-next delay="600"/>')
        quiet0 = loopmod.next_delay(600, marker, quiet_streak=0)["delay"]
        quiet1 = loopmod.next_delay(600, marker, quiet_streak=1)["delay"]
        quiet3 = loopmod.next_delay(600, marker, quiet_streak=3)["delay"]
        self.assertEqual(quiet0, 600)
        self.assertEqual(quiet1, 1200)
        self.assertEqual(quiet3, 2400)      # capped at 4x


class TestSchedulePolicy(unittest.TestCase):
    def make(self, task: str = "check CI", mode: str = "fixed",
             interval: int = 300, session: str = "s1", now: int = 1000):
        return loopmod.create(task, mode, interval, session_id=session, now=now)

    def test_lifetime_is_seven_days(self):
        sched = self.make()
        self.assertEqual(sched.expires - sched.created,
                         loopmod.LIFETIME_SECONDS)
        self.assertTrue(loopmod.is_alive(sched, now=1001))
        self.assertFalse(loopmod.is_alive(sched, now=1000 + 8 * 86400))

    def test_task_cap_is_fifty(self):
        schedules = [self.make(task=f"t{i}", now=1000 + i) for i in range(60)]
        res = loopmod.enforce(schedules, session_id="s1", now=1001)
        mine = [s for s in res["kept"] if s.session_id == "s1"]
        self.assertEqual(len(mine), loopmod.MAX_TASKS)
        self.assertEqual(len(res["dropped"]), 10)

    def test_one_self_paced_per_conversation(self):
        schedules = [self.make(task=f"t{i}", mode="self-paced", interval=None,
                               now=1000 + i) for i in range(3)]
        res = loopmod.enforce(schedules, session_id="s1", now=1001)
        mine = [s for s in res["kept"] if s.session_id == "s1"]
        self.assertEqual(len(mine), 1)

    def test_expired_schedules_are_dropped(self):
        sched = self.make(now=1000)
        res = loopmod.enforce([sched], session_id="s1",
                              now=1000 + loopmod.LIFETIME_SECONDS + 1)
        self.assertEqual(res["kept"], [])
        self.assertEqual(res["dropped"][0]["reason"], "lifetime exceeded")

    def test_jitter_is_deterministic_and_bounded(self):
        a = loopmod.jitter("loop-abc", 1, 3600)
        b = loopmod.jitter("loop-abc", 1, 3600)
        self.assertEqual(a, b)
        self.assertLessEqual(abs(a), 15 * 60)
        self.assertNotEqual(a, loopmod.jitter("loop-abc", 2, 3600))

    def test_kill_switch(self):
        old = os.environ.get(loopmod.KILL_SWITCH)
        try:
            os.environ[loopmod.KILL_SWITCH] = "0"
            self.assertTrue(loopmod.disabled())
            os.environ[loopmod.KILL_SWITCH] = "1"
            self.assertFalse(loopmod.disabled())
        finally:
            if old is None:
                os.environ.pop(loopmod.KILL_SWITCH, None)
            else:
                os.environ[loopmod.KILL_SWITCH] = old

    def test_schedule_round_trips(self):
        sched = self.make()
        again = loopmod.Schedule.from_dict(sched.to_dict())
        self.assertEqual(again, sched)


class TestCliLoop(unittest.TestCase):
    def run_cli(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "loop", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc.stdout

    def test_parse_over_cli(self):
        payload = json.loads(self.run_cli("parse", "2h check the CI", "--json"))
        self.assertEqual(payload["mode"], "fixed")
        self.assertEqual(payload["interval"], 7200)

    def test_normalize_over_cli(self):
        payload = json.loads(self.run_cli("normalize", "47m", "--json"))
        self.assertEqual(payload["label"], "1h")

    def test_markers_over_cli(self):
        payload = json.loads(self.run_cli(
            "markers", '<loop-done reason="done"/>', "--json"))
        self.assertEqual(payload["action"], "done")

    def test_next_over_cli(self):
        payload = json.loads(self.run_cli(
            "next", "--body", '<loop-next delay="300"/>', "--base", "300",
            "--json"))
        self.assertEqual(payload["action"], "next")
        self.assertEqual(payload["delay"], 300)


if __name__ == "__main__":
    unittest.main()
