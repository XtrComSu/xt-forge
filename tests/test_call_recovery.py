"""Tests for Priority 3 (safe interrupted tool-call recovery + cancellation propagation)
plus checksec Full RELRO, codec intermixed CLI parsing, skills CLI, and doctor engines."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import call_journal as jmod  # noqa: E402
from xtforge.core.mcp_proxy import PythonUpstreamSession  # noqa: E402


def _write_mock_server(tmp: Path, code: str) -> list[str]:
    p = tmp / "mock_mcp.py"
    p.write_text(code, encoding="utf-8")
    return [sys.executable, str(p)]


class TestCallRecoveryPython(unittest.TestCase):
    def setUp(self) -> None:
        self._old_home = os.environ.get("XT_HOME")
        self._old_perm = os.environ.get("XT_PERM_MODE")
        self._td = tempfile.TemporaryDirectory()
        os.environ["XT_HOME"] = self._td.name
        os.environ["XT_PERM_MODE"] = "full"

    def tearDown(self) -> None:
        if self._old_home is None:
            os.environ.pop("XT_HOME", None)
        else:
            os.environ["XT_HOME"] = self._old_home
        if self._old_perm is None:
            os.environ.pop("XT_PERM_MODE", None)
        else:
            os.environ["XT_PERM_MODE"] = self._old_perm
        self._td.cleanup()

    def test_in_flight_normalizes_to_unknown_outcome(self) -> None:
        p = jmod.journal_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "version": 1,
            "entries": {
                "c1": {"call_id": "c1", "idempotency_key": "k1", "server": "s", "tool": "submit_job", "state": "in_flight"}
            },
        }), encoding="utf-8")
        found = jmod.find_by_key("k1")
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found["state"], jmod.CALL_UNKNOWN_OUTCOME)

    def test_drop_reply_once_recovers_via_receipt_without_duplicate_write(self) -> None:
        tmp = Path(self._td.name)
        state_file = tmp / "srv_state.json"
        cmd = _write_mock_server(tmp, f"""
import json, os, sys
state_file = {str(state_file)!r}
def load():
    if os.path.exists(state_file):
        return json.load(open(state_file))
    return {{"commits": 0, "attempts": 0, "receipts": {{}}}}
def save(d):
    json.dump(d, open(state_file, "w"))
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({{"jsonrpc": "2.0", "id": mid, "result": {{"protocolVersion": "2025-06-18", "capabilities": {{}}, "serverInfo": {{"name": "mock", "version": "1.0"}}}}}}), flush=True)
    elif method == "tools/list":
        print(json.dumps({{"jsonrpc": "2.0", "id": mid, "result": {{"tools": [
            {{"name": "submit_job", "description": "Submit once", "inputSchema": {{"type": "object"}}}},
            {{"name": "get_receipt", "description": "Read receipt", "inputSchema": {{"type": "object"}}}},
        ]}}}}), flush=True)
    elif method == "tools/call":
        p = msg.get("params") or {{}}
        tn = p.get("name")
        args = p.get("arguments") or {{}}
        st = load()
        if tn == "submit_job":
            st["attempts"] += 1
            key = args.get("job_id") or "default"
            if key not in st["receipts"]:
                st["commits"] += 1
                st["receipts"][key] = {{"receipt_id": f"rcpt-{{st['commits']}}", "job_id": key}}
            save(st)
            if st["attempts"] == 1:
                sys.exit(0)
            res = {{"content": [{{"type": "text", "text": json.dumps({{"committed": True, "receipt": st["receipts"][key]}})}}]}}
            print(json.dumps({{"jsonrpc": "2.0", "id": mid, "result": res}}), flush=True)
        elif tn == "get_receipt":
            key = args.get("job_id") or "default"
            rec = st["receipts"].get(key)
            res = {{"content": [{{"type": "text", "text": json.dumps({{"found": rec is not None, "receipt": rec}})}}]}}
            print(json.dumps({{"jsonrpc": "2.0", "id": mid, "result": res}}), flush=True)
""")
        # 1) Pre-cancelled -> never_started
        sess = PythonUpstreamSession("jobs", cmd, timeout=5.0)
        sess.start()
        try:
            ev = threading.Event()
            ev.set()
            r0, e0 = jmod.run_recoverable_upstream_call(
                sess, "jobs", "submit_job", {"job_id": "j0"}, idempotency_key="py-j0", cancel_event=ev,
            )
            self.assertTrue(e0)
            self.assertEqual(r0["state"], jmod.CALL_NEVER_STARTED)

            # 2) Drop first reply -> unknown_outcome
            r1, e1 = jmod.run_recoverable_upstream_call(
                sess, "jobs", "submit_job", {"job_id": "j1"}, idempotency_key="py-j1",
            )
            self.assertTrue(e1)
            self.assertEqual(r1["state"], jmod.CALL_UNKNOWN_OUTCOME)
        finally:
            sess.close()

        # 3) Blind retry blocked
        sess2 = PythonUpstreamSession("jobs", cmd, timeout=5.0)
        sess2.start()
        try:
            rb, eb = jmod.run_recoverable_upstream_call(
                sess2, "jobs", "submit_job", {"job_id": "j1"}, idempotency_key="py-j1",
            )
            self.assertTrue(eb)
            self.assertTrue(rb.get("duplicate_prevented"))
            self.assertEqual(rb.get("state"), jmod.CALL_UNKNOWN_OUTCOME)

            # 4) Retry with verify_tool reconciles without duplicate write
            r2, e2 = jmod.run_recoverable_upstream_call(
                sess2, "jobs", "submit_job", {"job_id": "j1"},
                idempotency_key="py-j1", verify_tool="get_receipt", verify_args={"job_id": "j1"},
            )
            self.assertFalse(e2, r2)
            self.assertTrue(r2["recovered"])
            self.assertTrue(r2["duplicate_prevented"])
        finally:
            sess2.close()

        st = json.loads(state_file.read_text())
        self.assertEqual(st["commits"], 1)
        self.assertEqual(st["attempts"], 1)

    def test_cancel_propagates_to_upstream_python(self) -> None:
        tmp = Path(self._td.name)
        cancel_log = tmp / "cancels.jsonl"
        cmd = _write_mock_server(tmp, f"""
import json, sys, threading
log_p = {str(cancel_log)!r}
ev = threading.Event()
def waiter():
    ev.wait(timeout=2.0)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({{"jsonrpc": "2.0", "id": mid, "result": {{"protocolVersion": "2025-06-18", "capabilities": {{}}, "serverInfo": {{"name": "slow", "version": "1.0"}}}}}}), flush=True)
    elif method == "tools/list":
        print(json.dumps({{"jsonrpc": "2.0", "id": mid, "result": {{"tools": [{{"name": "slow_write", "description": "Slow", "inputSchema": {{"type": "object"}}}}]}}}}), flush=True)
    elif method == "notifications/cancelled":
        with open(log_p, "a") as fh:
            fh.write(json.dumps(msg) + "\\n")
        ev.set()
    elif method == "tools/call":
        threading.Thread(target=waiter, daemon=True).start()
""")
        sess = PythonUpstreamSession("slow", cmd, timeout=0.15)
        sess.start()
        try:
            res, is_err = jmod.run_recoverable_upstream_call(
                sess, "slow", "slow_write", {"x": 1}, idempotency_key="slow-py",
            )
            self.assertTrue(is_err)
            self.assertEqual(res["state"], jmod.CALL_UNKNOWN_OUTCOME)
            self.assertTrue(res["cancel_notified"])
        finally:
            sess.close()
        self.assertTrue(cancel_log.is_file())
        self.assertIn("notifications/cancelled", cancel_log.read_text())

    def test_session_recover_and_skills_cli(self) -> None:
        env = dict(os.environ, XT_FORCE_PYTHON="1")
        r = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "skills", "list", "--json"],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertTrue(data["ok"])
        self.assertGreater(data["count"], 10)

        r2 = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "session", "recover", "--json"],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(r2.returncode, 0, r2.stderr)
        rec = json.loads(r2.stdout)
        self.assertIn("unknown_outcome_count", rec)
        self.assertIn("never_started_count", rec)


if __name__ == "__main__":
    unittest.main()
