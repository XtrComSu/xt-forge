"""Gateway & caller-lookup contract tests (Go hub --meta + Python fallback)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"
GO_HUB = ROOT / "native" / "xtforge-go" / "xtforge-hub"


def _rpc(cmd: list[str], reqs: list[dict], *, env: dict[str, str]) -> list[dict]:
    init = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "contract", "version": "1"},
        },
    }
    payload = "\n".join(json.dumps(r) for r in [init, *reqs]) + "\n"
    proc = subprocess.run(cmd, input=payload, text=True, capture_output=True, env=env, timeout=30)
    assert proc.returncode == 0, f"cmd={cmd} rc={proc.returncode} err={proc.stderr}"
    out: list[dict] = []
    for ln in proc.stdout.splitlines():
        if ln.strip():
            obj = json.loads(ln)
            if obj.get("id", 0) != 0:
                out.append(obj)
    out.sort(key=lambda r: r.get("id", 0))
    return out


class GatewayAndCallerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.ws = self.base / "dir with spaces"
        self.xt_home = self.base / "xt_home"
        self.xt_home.mkdir()
        (self.ws / "src" / "policy").mkdir(parents=True)
        (self.ws / "src" / "workers").mkdir(parents=True)
        (self.ws / "src" / "clients").mkdir(parents=True)
        (self.ws / "tests").mkdir(parents=True)
        (self.ws / "src" / "policy" / "retry_budget.py").write_text(
            "def should_retry_attempt(attempt: int, max_retries: int) -> bool:\n"
            "    return attempt < max_retries\n",
            encoding="utf-8",
        )
        (self.ws / "src" / "workers" / "job_runner.py").write_text(
            "from src.policy.retry_budget import should_retry_attempt\n\n"
            "def dispatch_job(job: dict) -> str:\n"
            "    return 'requeue' if should_retry_attempt(job['a'], 3) else 'dead'\n",
            encoding="utf-8",
        )
        (self.ws / "src" / "clients" / "webhook_pump.py").write_text(
            "from src.policy.retry_budget import should_retry_attempt\n\n"
            "def flush_webhook(a: int) -> str:\n"
            "    # token: -edge-dash-pattern\n"
            "    return 'retry' if should_retry_attempt(a, 4) else 'drop'\n",
            encoding="utf-8",
        )
        (self.ws / "tests" / "test_retry_helper.py").write_text(
            "def should_retry_attempt(attempt: int, max_retries: int) -> bool:\n"
            "    return attempt == 0\n\n"
            "def test_fake_retry_caller():\n"
            "    assert should_retry_attempt(0, 1)\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _gateways(self) -> list[tuple[str, list[str], dict[str, str]]]:
        env_base = {**os.environ, "XT_HOME": str(self.xt_home)}
        gws = [
            ("python", [sys.executable, "-m", "xtforge.cli", "mcp", "serve", "--meta"], {**env_base, "PYTHONPATH": str(ROOT), "XT_FORCE_PYTHON": "1"}),
        ]
        if GO_HUB.exists():
            gws.insert(0, ("go", [str(GO_HUB), "mcp", "serve", "--meta"], env_base))
        return gws

    def test_help_before_positional_validation_native_and_python(self) -> None:
        for mode, env in (
            ("native", {**os.environ, "XT_HOME": str(self.xt_home)}),
            ("python", {**os.environ, "XT_HOME": str(self.xt_home), "XT_FORCE_PYTHON": "1"}),
        ):
            r = subprocess.run([str(BIN), "code", "graph", "--help"], text=True, capture_output=True, env=env, timeout=15)
            self.assertEqual(r.returncode, 0, f"{mode}: {r.stderr}")
            self.assertIn("usage:", r.stdout.lower(), mode)

    def test_arguments_vs_argv_equivalence_and_spaces_across_gateways(self) -> None:
        for engine, cmd, env in self._gateways():
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "code_graph", "arguments": {"symbol": "should_retry_attempt", "path": str(self.ws), "depth": 2}}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"argv": ["code", "graph", "should_retry_attempt", str(self.ws), "--depth", "2"]}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "route_context", "arguments": {"path": str(self.ws), "query": "should_retry_attempt", "symbols": True}}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"argv": ["route", "context", str(self.ws), "--query", "should_retry_attempt", "--symbols"]}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "route_grep", "arguments": {"path": str(self.ws), "pattern": "-edge-dash-pattern"}}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"argv": ["route", "grep", str(self.ws), "--pattern", "-edge-dash-pattern"]}}},
            ]
            replies = _rpc(cmd, reqs, env=env)
            objs = []
            for rep in replies:
                self.assertFalse(rep["result"].get("isError"), f"{engine} id={rep['id']}: {rep}")
                txt = rep["result"]["content"][0]["text"]
                objs.append(json.loads(txt))
            # code_graph equivalence
            g_named, g_argv = objs[0], objs[1]
            self.assertEqual(
                {c["caller"] for c in g_named.get("production_callers", g_named["callers"])},
                {"dispatch_job", "flush_webhook"},
            )
            self.assertEqual(
                {c["caller"] for c in g_argv.get("production_callers", g_argv["callers"])},
                {"dispatch_job", "flush_webhook"},
            )
            # route_context equivalence
            self.assertEqual(objs[2].get("ok"), True)
            self.assertEqual(objs[3].get("ok"), True)
            # route_grep dash-prefixed pattern equivalence
            for g in (objs[4], objs[5]):
                matches = g.get("matches") or (g.get("data") or {}).get("matches") or []
                self.assertTrue(matches, f"{engine}: dash pattern failed: {g}")

    def test_incomplete_invocations_and_dash_symbol(self) -> None:
        for engine, cmd, env in self._gateways():
            reqs = [
                {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "code_graph", "arguments": {}}}},
                {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "route_grep", "arguments": {}}}},
                {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "code_graph", "arguments": {"symbol": "-dash_sym", "path": str(self.ws)}}}},
            ]
            replies = _rpc(cmd, reqs, env=env)
            self.assertTrue(replies[0]["result"]["isError"], f"{engine}: missing symbol must fail")
            self.assertIn("symbol", replies[0]["result"]["content"][0]["text"].lower())
            self.assertTrue(replies[1]["result"]["isError"], f"{engine}: missing pattern must fail")
            self.assertIn("pattern", replies[1]["result"]["content"][0]["text"].lower())
            self.assertFalse(replies[2]["result"]["isError"], f"{engine}: -dash_sym must not fail arg parsing: {replies[2]}")

    def test_caller_lookup_evidence_ambiguity_and_staleness(self) -> None:
        for mode, extra_env in (("rust", {}), ("python", {"XT_FORCE_PYTHON": "1"})):
            env = {**os.environ, "XT_HOME": str(self.xt_home), **extra_env}
            r1 = subprocess.run([str(BIN), "code", "graph", "should_retry_attempt", str(self.ws), "--json"], text=True, capture_output=True, env=env, timeout=15)
            self.assertEqual(r1.returncode, 0, r1.stderr)
            d1 = json.loads(r1.stdout)
            self.assertTrue(d1.get("ambiguous"), f"{mode}: should flag duplicate def in tests/")
            prod = d1.get("production_callers") or []
            self.assertEqual({c["caller"] for c in prod}, {"dispatch_job", "flush_webhook"})
            for c in prod:
                self.assertEqual(c.get("how"), "import_resolved_call")
                self.assertEqual(c.get("confidence"), "high")
                self.assertTrue(c.get("excerpt"))
            unres = d1.get("unresolved_candidates") or []
            self.assertTrue(any(u["caller"] == "test_fake_retry_caller" for u in unres), unres)

            # Mutate a file after indexing and ensure staleness is surfaced & refreshed on next lookup.
            extra_mod = self.ws / "src" / "workers" / "late_worker.py"
            extra_mod.write_text(
                "from src.policy.retry_budget import should_retry_attempt\n\n"
                "def late_runner(a: int) -> bool:\n"
                "    return should_retry_attempt(a, 2)\n",
                encoding="utf-8",
            )
            r2 = subprocess.run([str(BIN), "code", "callers", "should_retry_attempt", str(self.ws), "--json"], text=True, capture_output=True, env=env, timeout=15)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            d2 = json.loads(r2.stdout)
            self.assertTrue(d2["index_status"]["stale_detected"], d2["index_status"])
            self.assertIn(str(extra_mod), d2["index_status"]["stale_files"])
            self.assertIn("late_runner", {c["caller"] for c in d2["production_callers"]})
            extra_mod.unlink()

    def test_upstream_readiness_cold_unavailable_and_zero_match(self) -> None:
        (self.xt_home / "mcp_upstreams.json").write_text(
            json.dumps({
                "version": 1,
                "upstreams": {
                    "rea": {"name": "rea", "command": ["/nonexistent/rea-binary"], "source": "test"},
                },
            }),
            encoding="utf-8",
        )
        for engine, cmd, env in self._gateways():
            replies = _rpc(
                cmd,
                [
                    {"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "xt_discover", "arguments": {"query": "zzz_no_match"}}},
                    {"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": {"name": "xt_discover", "arguments": {"upstream": "rea", "query": "zzz_no_match"}}},
                ],
                env=env,
            )
            d_cold = json.loads(replies[0]["result"]["content"][0]["text"])
            d_unavail = json.loads(replies[1]["result"]["content"][0]["text"])
            self.assertEqual(d_cold["upstream_status"]["rea"]["status"], "cold_cache", f"{engine}: {d_cold}")
            self.assertEqual(d_unavail["upstream_status"]["rea"]["status"], "unavailable", f"{engine}: {d_unavail}")
            self.assertFalse(d_unavail["upstream_status"]["rea"]["reachable"], f"{engine}: {d_unavail}")


if __name__ == "__main__":
    unittest.main()
