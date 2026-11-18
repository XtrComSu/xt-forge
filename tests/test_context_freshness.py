"""Tests for Priority 1 (context diagnostics + unseen transfer) and Priority 2 (live freshness)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"


def _run_cli(args: list[str], *, force_python: bool, xt_home: Path) -> dict:
    env = os.environ.copy()
    env["XT_HOME"] = str(xt_home)
    if force_python:
        env["XT_FORCE_PYTHON"] = "1"
    else:
        env.pop("XT_FORCE_PYTHON", None)
    proc = subprocess.run(
        [str(BIN), *args],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"command failed ({proc.returncode}): {' '.join(args)}\nstderr={proc.stderr}\nstdout={proc.stdout}"
        )
    return json.loads(proc.stdout)


class TestContextDiagnosticsAndFreshness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xt_ctx_fresh_"))
        self.xt_home = self.tmp / "xt_home"
        self.xt_home.mkdir(parents=True, exist_ok=True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir(parents=True, exist_ok=True)
        (self.repo / "alpha.py").write_text(
            "def old_helper() -> int:\n"
            "    return 41\n",
            encoding="utf-8",
        )
        (self.repo / "caller_old.py").write_text(
            "from alpha import old_helper\n\n"
            "def execute_job() -> int:\n"
            "    return old_helper() + 1\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _assert_diagnose_and_digest(self, *, force_python: bool) -> None:
        fixture = ROOT / "tests" / "fixtures" / "mini_project"
        expected_worker = fixture / "worker.py"
        expected_sha = hashlib.sha256(expected_worker.read_bytes()).hexdigest()

        out = _run_cli(
            [
                "route", "context", str(fixture),
                "--query", "where is job latency recorded",
                "--token-budget", "1200",
                "--diagnose",
                "--expected-file", "worker.py",
                "--expected-line", "53",
                "--json",
            ],
            force_python=force_python,
            xt_home=self.xt_home,
        )
        data = out["data"]
        diag = data.get("diagnostic") or {}
        target = diag.get("target") or {}
        self.assertTrue(target.get("indexed"))
        self.assertIsNotNone(target.get("rank"))
        self.assertIn("breakdown", target)
        self.assertTrue(target.get("packed"))
        self.assertEqual(target.get("drop_reason"), "packed")

        worker_ev = [e for e in (data.get("evidence") or []) if Path(e["path"]).name == "worker.py"]
        self.assertTrue(worker_ev, f"expected worker.py evidence, got {data.get('evidence')}")
        for item in worker_ev:
            self.assertEqual(item.get("digest"), expected_sha)
            self.assertGreaterEqual(item.get("start_line", 0), 1)
            self.assertGreaterEqual(item.get("end_line", 0), item.get("start_line", 0))

        # Tight token budget must report why an un-packed file was dropped, plus missing-file diagnosis.
        tight = _run_cli(
            [
                "route", "context", str(fixture),
                "--query", "where is job latency recorded",
                "--token-budget", "150",
                "--diagnose",
                "--expected-file", "metrics.py",
                "--json",
            ],
            force_python=force_python,
            xt_home=self.xt_home,
        )
        tight_target = (tight["data"].get("diagnostic") or {}).get("target") or {}
        self.assertTrue(tight_target.get("indexed"))
        self.assertIn(
            tight_target.get("drop_reason"),
            ("packed", "token_budget_cut", "token_budget_exceeded", "evicted_during_budget_trim", "file_limit_exceeded", "zero_score_unmatched"),
        )

        missing = _run_cli(
            [
                "route", "context", str(fixture),
                "--query", "where is job latency recorded",
                "--diagnose",
                "--expected-file", "does_not_exist_xyz.py",
                "--json",
            ],
            force_python=force_python,
            xt_home=self.xt_home,
        )
        miss_target = (missing["data"].get("diagnostic") or {}).get("target") or {}
        self.assertFalse(miss_target.get("indexed"))
        self.assertEqual(miss_target.get("drop_reason"), "file_not_indexed")

    def _assert_live_edit_invalidation(self, *, force_python: bool) -> None:
        graph_db = self.xt_home / "code_graph.db"
        env_xt = self.xt_home / ("py" if force_python else "rs")
        env_xt.mkdir(parents=True, exist_ok=True)
        graph_db = env_xt / "code_graph.db"

        _run_cli(
            ["code", "index", str(self.repo), "--graph-db", str(graph_db), "--json"],
            force_python=force_python,
            xt_home=env_xt,
        )
        initial_graph = _run_cli(
            ["code", "graph", "old_helper", str(self.repo), "--graph-db", str(graph_db), "--json"],
            force_python=force_python,
            xt_home=env_xt,
        )
        callers = json.dumps(initial_graph)
        self.assertIn("caller_old.py", callers)

        # Rename symbol, move caller to a new file, and delete caller_old.py in the same live session.
        (self.repo / "alpha.py").write_text(
            "def new_helper() -> int:\n"
            "    return 99\n",
            encoding="utf-8",
        )
        (self.repo / "caller_new.py").write_text(
            "from alpha import new_helper\n\n"
            "def execute_job() -> int:\n"
            "    return new_helper() + 1\n",
            encoding="utf-8",
        )
        (self.repo / "caller_old.py").unlink()
        new_alpha_sha = hashlib.sha256((self.repo / "alpha.py").read_bytes()).hexdigest()

        # Without manual rebuild: next graph query + route context drop caller_old.py and pick up caller_new.py + new digest.
        updated_graph = _run_cli(
            ["code", "graph", "new_helper", str(self.repo), "--graph-db", str(graph_db), "--json"],
            force_python=force_python,
            xt_home=env_xt,
        )
        graph_text = json.dumps(updated_graph)
        self.assertIn("caller_new.py", graph_text)
        self.assertNotIn("caller_old.py", graph_text)

        ctx = _run_cli(
            [
                "route", "context", str(self.repo),
                "--query", "where is execute_job calling new_helper",
                "--symbols",
                "--json",
            ],
            force_python=force_python,
            xt_home=env_xt,
        )["data"]
        self.assertIn("caller_new.py", ctx["context"])
        self.assertIn("new_helper", ctx["context"])
        self.assertNotIn("caller_old.py", ctx["context"])
        self.assertNotIn("old_helper", ctx["context"])
        alpha_ev = [e for e in ctx["evidence"] if Path(e["path"]).name == "alpha.py"]
        self.assertTrue(alpha_ev)
        self.assertEqual(alpha_ev[0]["digest"], new_alpha_sha)

    def test_diagnose_and_digest_rust(self) -> None:
        self._assert_diagnose_and_digest(force_python=False)

    def test_diagnose_and_digest_python(self) -> None:
        self._assert_diagnose_and_digest(force_python=True)

    def test_live_edit_invalidation_rust(self) -> None:
        self._assert_live_edit_invalidation(force_python=False)

    def test_live_edit_invalidation_python(self) -> None:
        self._assert_live_edit_invalidation(force_python=True)

    def test_unseen_tasks_benchmark_passes(self) -> None:
        proc = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts" / "bench_context_pack.py"),
                "--tasks", str(ROOT / "tests" / "fixtures" / "context_tasks_unseen.json"),
                "--project", str(ROOT / "tests" / "fixtures" / "unseen_project"),
                "--json",
            ],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["pass"])
        self.assertEqual(payload["query_aware"]["missed"], [])


if __name__ == "__main__":
    unittest.main()
