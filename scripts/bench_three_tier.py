#!/usr/bin/env python3
"""Three-Tier Live Agent Benchmark for XT-Forge (Find, Fix, Recover).

Compares identical isolated workspaces across:
  - Arm A: Host harness ordinary tools (no XT-Forge MCP / guidance)
  - Arm B: Host harness with XT-Forge (--meta MCP + CLI + call recovery)

Supports DSH (Hive deepseek-ai/deepseek-v4.1-flash-1017 medium),
Codex CLI (gpt-6-luna medium), and OpenCode (openai/gpt-6-luna#medium).

Never uses Astra models. Sanitizes all credentials from persisted traces.

Usage:
    python3 scripts/bench_three_tier.py --self-test
    python3 scripts/bench_three_tier.py --harnesses dsh,codex,opencode --out-dir artifacts/three_tier
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BIN_XTFORGE = ROOT / "bin" / "xtforge"
GO_HUB = ROOT / "native" / "xtforge-go" / "xtforge-hub"

TIER_BUDGETS_S = {
    "tier1_find": 60,
    "tier2_fix": 120,
    "tier3_recover": 120,
}

SECRET_SCRUB_RE = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{8,}", re.I),
    re.compile(r"((?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*[\"']?)[^\s\"',}]{6,}", re.I),
    re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{16,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{20,})\b"),
]


def sanitize_text(text: str) -> str:
    out = text or ""
    out = SECRET_SCRUB_RE[0].sub(r"\1[REDACTED]", out)
    out = SECRET_SCRUB_RE[1].sub(r"\1[REDACTED]", out)
    out = SECRET_SCRUB_RE[2].sub("[REDACTED_TOKEN]", out)
    return out


# ---------------------------------------------------------------- Fixtures

TIER1_FILES = {
    "src/policy/retry_budget.py": '''"""Authoritative retry budget decision policy."""
from __future__ import annotations


def should_retry_attempt(attempt: int, max_retries: int, status_code: int) -> bool:
    """Decide whether a transient failure should be retried."""
    if attempt >= max_retries:
        return False
    return status_code in (408, 429, 500, 502, 503, 504)
''',
    "src/workers/job_runner.py": '''"""Background job queue worker."""
from __future__ import annotations

from src.policy.retry_budget import should_retry_attempt


def dispatch_job(job: dict, status_code: int) -> str:
    attempt = int(job.get("attempt", 0))
    max_retries = int(job.get("max_retries", 3))
    if should_retry_attempt(attempt, max_retries, status_code):
        return "requeue"
    return "dead_letter"
''',
    "src/clients/webhook_pump.py": '''"""Outbound webhook delivery client."""
from __future__ import annotations

from src.policy.retry_budget import should_retry_attempt


def flush_webhook(delivery_id: str, attempt: int, status_code: int) -> str:
    if should_retry_attempt(attempt, 4, status_code):
        return f"retry:{delivery_id}"
    return f"drop:{delivery_id}"
''',
    "docs/RETRY_ARCHITECTURE.md": '''# Legacy Retry Architecture (STALE - PRE-2025 MIGRATION)

DEPRECATED NOTES (DO NOT USE FOR CURRENT CODE):
Historically, `should_retry_legacy` in `src/old_queue.py` decided retries and
was called by `drain_legacy_queue` and `replay_dead_letters`.
That module was removed in v2.
''',
    "tests/test_retry_helper.py": '''"""Unit test helpers with an identically named local helper function."""
from __future__ import annotations


def should_retry_attempt(attempt: int, max_retries: int, status_code: int) -> bool:
    """Test-only stub shadowing the production name."""
    return attempt == 0 and status_code == 503


def test_fake_retry_caller() -> None:
    assert should_retry_attempt(0, 1, 503) is True
''',
}

TIER2_FILES = {
    "src/__init__.py": "",
    "src/queue/__init__.py": "",
    "src/queue/policy.py": '''"""Retry budget policy helpers."""
from __future__ import annotations


def has_retry_budget(retries_used: int, max_retries: int) -> bool:
    """Return True if another retry is permitted after `retries_used` retries.

    Contract:
      A task executes 1 initial attempt plus at most `max_retries` retries
      (1 + max_retries total attempts).
      BUG: `<=` grants one extra attempt after `max_retries` is exhausted.
    """
    return retries_used <= max_retries
''',
    "src/queue/dispatcher.py": '''"""Queue task executor."""
from __future__ import annotations

from typing import Callable, TypeVar

from src.queue.policy import has_retry_budget

T = TypeVar("T")


def process_task(handler: Callable[[], T], *, max_retries: int = 2) -> T:
    """Execute `handler` with at most `max_retries` retries after initial attempt."""
    retries_used = 0
    while True:
        try:
            return handler()
        except RuntimeError:
            if not has_retry_budget(retries_used, max_retries):
                raise
            retries_used += 1
''',
    "tests/__init__.py": "",
    "tests/test_smoke.py": '''"""Basic smoke test (passes on happy path only)."""
import unittest
from src.queue.dispatcher import process_task


class TestSmoke(unittest.TestCase):
    def test_first_attempt_succeeds(self) -> None:
        self.assertEqual(process_task(lambda: "ok", max_retries=2), "ok")


if __name__ == "__main__":
    unittest.main()
''',
}

TIER2_HIDDEN_TEST = '''
import sys
import unittest
from pathlib import Path

WS = Path(sys.argv[1])
sys.path.insert(0, str(WS))
from src.queue.dispatcher import process_task  # noqa: E402


class HiddenRetryTests(unittest.TestCase):
    def test_existing_success_path(self) -> None:
        calls = 0
        def fn():
            nonlocal calls
            calls += 1
            return "done"
        self.assertEqual(process_task(fn, max_retries=2), "done")
        self.assertEqual(calls, 1)

    def test_zero_retries_makes_single_attempt(self) -> None:
        calls = 0
        def fn():
            nonlocal calls
            calls += 1
            raise RuntimeError("boom")
        with self.assertRaises(RuntimeError):
            process_task(fn, max_retries=0)
        self.assertEqual(calls, 1, f"expected 1 attempt for max_retries=0, got {calls}")

    def test_succeeds_on_last_allowed_retry(self) -> None:
        calls = 0
        def fn():
            nonlocal calls
            calls += 1
            if calls < 3:
                raise RuntimeError("transient")
            return "recovered"
        self.assertEqual(process_task(fn, max_retries=2), "recovered")
        self.assertEqual(calls, 3)

    def test_exhaustion_stops_at_max_retries(self) -> None:
        calls = 0
        def fn():
            nonlocal calls
            calls += 1
            raise RuntimeError("permanent")
        with self.assertRaises(RuntimeError):
            process_task(fn, max_retries=2)
        self.assertEqual(calls, 3, f"expected 3 attempts (1 + 2 retries), got {calls}")


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(HiddenRetryTests))
    raise SystemExit(0 if res.wasSuccessful() else 1)
'''

MOCK_JOB_MCP_SERVER_PY = r'''#!/usr/bin/env python3
"""Deterministic mock MCP server for Tier 3 recovery testing.

Commits the job on the first `submit_job` call, drops its JSON-RPC reply (EOF),
then exposes read-only `get_receipt` so recovery avoids duplicate commits.
Counts duplicate `submit_job` calls separately even if keyed identically.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

STATE_PATH = Path(os.environ["XT_T3_STATE_PATH"])


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"commits": 0, "submit_attempts": 0, "receipts": {}, "calls": []}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(STATE_PATH)


TOOLS = [
    {
        "name": "submit_job",
        "description": "Submit a local job once (may interrupt after commit before sending reply). Always verify via get_receipt before retrying.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Unique job identifier (e.g. job-alpha-01)"},
                "payload": {"type": "string", "description": "Job payload string"},
            },
            "required": ["job_id", "payload"],
        },
    },
    {
        "name": "get_receipt",
        "description": "Read-only receipt lookup for an already submitted job_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job identifier to check"},
            },
            "required": ["job_id"],
        },
    },
]

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    req = json.loads(raw)
    mid = req.get("id")
    method = req.get("method", "")
    if mid is None:
        continue
    if method == "initialize":
        req_ver = (req.get("params") or {}).get("protocolVersion") or "2025-03-26"
        res = {
            "protocolVersion": req_ver,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "job_runner", "version": "1.0.0"},
        }
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        params = req.get("params") or {}
        tname = params.get("name", "")
        args = params.get("arguments") or {}
        st = load_state()
        st["calls"].append({"tool": tname, "args": args})
        if tname == "submit_job":
            st["submit_attempts"] += 1
            job_id = str(args.get("job_id") or "")
            payload = str(args.get("payload") or "")
            if job_id not in st["receipts"]:
                st["commits"] += 1
                st["receipts"][job_id] = {
                    "job_id": job_id,
                    "receipt_id": "rcpt-9482",
                    "payload": payload,
                    "status": "committed",
                }
            save_state(st)
            if st["submit_attempts"] == 1:
                # Commit persisted on disk; intentionally drop reply before responding.
                sys.exit(1)
            res = {"content": [{"type": "text", "text": json.dumps({"ok": True, "receipt": st["receipts"][job_id], "duplicate": True})}]}
        elif tname == "get_receipt":
            save_state(st)
            job_id = str(args.get("job_id") or "")
            rcpt = st["receipts"].get(job_id)
            if rcpt:
                res = {"content": [{"type": "text", "text": json.dumps({"ok": True, "found": True, "receipt": rcpt})}]}
            else:
                res = {"content": [{"type": "text", "text": json.dumps({"ok": True, "found": False})}]}
        else:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown tool: {tname}"}}) + "\n")
            sys.stdout.flush()
            continue
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
    sys.stdout.flush()
'''


def fixture_revision_digest() -> str:
    h = hashlib.sha256()
    for grp in (TIER1_FILES, TIER2_FILES):
        for k in sorted(grp):
            h.update(k.encode())
            h.update(grp[k].encode())
    h.update(TIER2_HIDDEN_TEST.encode())
    h.update(MOCK_JOB_MCP_SERVER_PY.encode())
    return h.hexdigest()[:12]


def prepare_tier_workspace(base: Path, tier: str, arm: str) -> tuple[Path, Path]:
    """Create isolated workspace + state/xt_home dir for (tier, arm)."""
    ws = base / f"{tier}_{arm}_ws"
    aux = base / f"{tier}_{arm}_aux"
    ws.mkdir(parents=True, exist_ok=True)
    aux.mkdir(parents=True, exist_ok=True)

    files = TIER1_FILES if tier == "tier1_find" else (TIER2_FILES if tier == "tier2_fix" else {})
    for rel, content in files.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    if tier == "tier3_recover":
        srv = aux / "job_mcp_server.py"
        srv.write_text(MOCK_JOB_MCP_SERVER_PY, encoding="utf-8")
        os.chmod(srv, 0o755)
        (ws / "JOB_REQUEST.json").write_text(
            json.dumps({"job_id": "job-alpha-01", "payload": "nightly-rollup"}, indent=2) + "\n",
            encoding="utf-8",
        )

    if arm == "B":
        xt_home = aux / "xt_home"
        xt_home.mkdir(parents=True, exist_ok=True)
        if tier in ("tier1_find", "tier2_fix"):
            subprocess.run(
                [str(BIN_XTFORGE), "code", "index", str(ws), "--json"],
                env={**os.environ, "XT_HOME": str(xt_home)},
                capture_output=True, text=True, timeout=15,
            )
            (ws / "AGENTS.md").write_text(
                f"# Workspace Hint\nUse the `xt-forge` MCP (`xt_call`) or `{BIN_XTFORGE}` (`route context`, `code graph`) for fast call-graph and symbol inspection.\n",
                encoding="utf-8",
            )
        else:
            state_path = aux / "server_state.json"
            srv = aux / "job_mcp_server.py"
            (xt_home / "mcp_upstreams.json").write_text(
                json.dumps({
                    "version": 1,
                    "upstreams": {
                        "job_runner": {
                            "name": "job_runner",
                            "command": [sys.executable, str(srv)],
                            "env": {"XT_T3_STATE_PATH": str(state_path)},
                            "source": "bench_three_tier",
                        }
                    },
                }, indent=2),
                encoding="utf-8",
            )
            (ws / "AGENTS.md").write_text(
                "# Workspace Hint\n"
                "The `xt-forge` MCP (`xt_discover`, `xt_schema`, `xt_call`) manages `job_runner`.\n"
                "For write calls, ALWAYS pass `idempotency_key`, `verify_tool: \"get_receipt\"`, and `verify_args: {\"job_id\": \"...\"}` on `xt_call`.\n"
                "If a call reports `unknown_outcome`, re-issue `xt_call` with the same `idempotency_key` + `verify_tool` (or call `job_runner:get_receipt`) — NEVER duplicate the write.\n",
                encoding="utf-8",
            )
    return ws, aux


def build_tier_prompt(tier: str, arm: str, ws: Path) -> str:
    if tier == "tier1_find":
        extra = (
            f" XT-Forge tools/CLI ({BIN_XTFORGE}) and `xt-forge` MCP are available."
            if arm == "B" else ""
        )
        return (
            f"Workspace root: {ws}\n"
            "Question: Which function decides whether to retry, and which two production functions call it? "
            "Give exact file paths and symbol names. Ignore stale docs and test helpers."
            f"{extra}"
        )
    if tier == "tier2_fix":
        extra = (
            f" XT-Forge (`{BIN_XTFORGE}` / `xt-forge` MCP) is available."
            if arm == "B" else ""
        )
        return (
            f"Workspace root: {ws}\n"
            "Task: The queue makes an extra attempt after its retry budget is exhausted. "
            "Fix it while preserving successful retries and zero-retry behavior. Verify with tests and report your changes."
            f"{extra}"
        )
    if arm == "B":
        return (
            f"Workspace root: {ws}\n"
            "Read JOB_REQUEST.json, then use the `xt-forge` MCP (`xt_call` on `job_runner:submit_job` with "
            "`idempotency_key: \"job-alpha-01\"`, `verify_tool: \"get_receipt\"`, `verify_args: {\"job_id\": \"job-alpha-01\"}`) "
            "to submit this local job once, verify its receipt (`receipt_id`), and summarize the result. Never trigger a duplicate commit."
        )
    return (
        f"Workspace root: {ws}\n"
        "Read JOB_REQUEST.json, then use the `job_runner` MCP server (`submit_job`, `get_receipt`) "
        "to submit this local job once, verify its receipt (`receipt_id`), and summarize the result. Do not create duplicate commits."
    )


# ---------------------------------------------------------------- Grading

def grade_tier1(final_text: str) -> tuple[bool, str | None]:
    txt = final_text or ""
    req = [
        ("should_retry_attempt", "missing decision function should_retry_attempt"),
        ("retry_budget.py", "missing file retry_budget.py"),
        ("dispatch_job", "missing production caller dispatch_job"),
        ("job_runner.py", "missing file job_runner.py"),
        ("flush_webhook", "missing production caller flush_webhook"),
        ("webhook_pump.py", "missing file webhook_pump.py"),
    ]
    for needle, msg in req:
        if needle not in txt:
            return False, msg
    excl = ("stale", "decoy", "ignore", "ignored", "removed", "not a ", "not the", "stub", "test-only", "non-production", "deprecated", "legacy")
    for bad in ("drain_legacy_queue", "test_fake_retry_caller"):
        for line in txt.splitlines():
            if bad in line and not any(w in line.lower() for w in excl):
                return False, f"misidentified {bad} as a production symbol"
    return True, None


def grade_tier2(ws: Path) -> tuple[bool, str | None]:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(TIER2_HIDDEN_TEST)
        tpath = Path(tf.name)
    try:
        proc = subprocess.run([sys.executable, str(tpath), str(ws)], text=True, capture_output=True, timeout=15)
        if proc.returncode == 0:
            return True, None
        return False, (proc.stderr or proc.stdout).strip().splitlines()[-1][:180]
    finally:
        tpath.unlink(missing_ok=True)


def grade_tier3(aux: Path, final_text: str) -> tuple[bool, str | None, dict[str, int]]:
    state_path = aux / "server_state.json"
    if not state_path.is_file():
        return False, "server_state.json missing (job never submitted)", {"commits": 0, "submit_attempts": 0, "duplicate_attempts": 0}
    st = json.loads(state_path.read_text(encoding="utf-8"))
    commits = int(st.get("commits", 0))
    submits = int(st.get("submit_attempts", 0))
    dups = max(0, submits - 1) if submits >= 1 else 0
    calls = st.get("calls") or []
    get_receipt_called = any(c.get("tool") == "get_receipt" for c in calls)
    metrics = {"commits": commits, "submit_attempts": submits, "duplicate_attempts": dups}

    if commits != 1:
        return False, f"expected commits==1, got {commits}", metrics
    if dups > 0:
        return False, f"duplicate submit_job attempts={dups}", metrics
    if not get_receipt_called:
        return False, "get_receipt was never called to verify receipt", metrics
    if "rcpt-9482" not in (final_text or ""):
        return False, "final summary omitted verified receipt_id rcpt-9482", metrics
    return True, None, metrics


# ---------------------------------------------------------------- Telemetry Parsers

def parse_jsonl_telemetry(harness: str, stdout_text: str) -> dict[str, Any]:
    input_tok: int | str = "unknown"
    output_tok: int | str = "unknown"
    in_sum, out_sum, saw_usage = 0, 0, False
    tool_calls = 0
    xtforge_calls = 0
    sig_counts: dict[str, int] = {}
    final_parts: list[str] = []

    def track_call(name: str, inp: Any) -> None:
        nonlocal tool_calls, xtforge_calls
        tool_calls += 1
        sig = f"{name}:{json.dumps(inp, sort_keys=True, default=str)[:200]}"
        sig_counts[sig] = sig_counts.get(sig, 0) + 1
        joined = f"{name} {json.dumps(inp, default=str)}".lower()
        if "xtforge" in joined or "xt-forge" in joined or "xt_call" in joined or "xt_discover" in joined or "xt_schema" in joined:
            xtforge_calls += 1

    for raw in (stdout_text or "").splitlines():
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        etype = ev.get("type")
        if harness == "dsh":
            if etype == "tool_call":
                track_call(str(ev.get("tool") or ""), ev.get("input"))
            elif etype == "status" and ev.get("phase") == "step_end" and isinstance(ev.get("usage"), dict):
                u = ev["usage"]
                in_sum += int(u.get("inputTokens", 0) or 0)
                out_sum += int(u.get("outputTokens", 0) or 0)
                saw_usage = True
            elif etype == "final":
                final_parts.append(str(ev.get("text") or ""))
            elif etype == "text" and ev.get("text"):
                final_parts.append(str(ev["text"]))
        elif harness == "codex":
            if etype == "item.completed" and isinstance(ev.get("item"), dict):
                it = ev["item"]
                itype = it.get("type")
                if itype in ("command_execution", "mcp_tool_call"):
                    track_call(str(it.get("tool") or itype), it.get("command") or it.get("arguments"))
                elif itype == "agent_message" and it.get("text"):
                    final_parts.append(str(it["text"]))
            elif etype == "turn.completed" and isinstance(ev.get("usage"), dict):
                u = ev["usage"]
                in_sum += int(u.get("input_tokens", 0) or 0)
                out_sum += int(u.get("output_tokens", 0) or 0)
                saw_usage = True
        elif harness == "opencode":
            part = ev.get("part") if isinstance(ev.get("part"), dict) else {}
            if etype == "tool_use":
                st = part.get("state") if isinstance(part.get("state"), dict) else {}
                track_call(str(part.get("tool") or ""), st.get("input"))
            elif etype == "step_finish" and isinstance(part.get("tokens"), dict):
                tk = part["tokens"]
                in_sum += int(tk.get("input", 0) or 0) + int((tk.get("cache") or {}).get("read", 0) or 0)
                out_sum += int(tk.get("output", 0) or 0) + int(tk.get("reasoning", 0) or 0)
                saw_usage = True
            elif etype == "text" and part.get("text"):
                final_parts.append(str(part["text"]))

    if saw_usage:
        input_tok = in_sum
        output_tok = out_sum
    repeated = sum(max(0, c - 1) for c in sig_counts.values())
    return {
        "input_tokens": input_tok,
        "output_tokens": output_tok,
        "tool_calls": tool_calls,
        "repeated_calls": repeated,
        "xtforge_calls": xtforge_calls,
        "final_text": "\n".join(final_parts).strip(),
    }


# ---------------------------------------------------------------- Runners

def _build_dsh_patch(aux: Path, model_tag: str, tier: str, arm: str) -> Path:
    patch = aux / f"dsh_{tier}_{arm}.yml"
    lines: list[str] = []
    if model_tag == "hive-deepseek":
        lines.append("""
- id: agent-default-model
  config:
    provider: hive-ai
    model: deepseek-ai/deepseek-v4.1-flash-1017
- id: llm-pi-ai
  config:
    providers:
      hive-ai:
        apiKeyEnv: HIVE_AI_API_KEY
        baseURL: https://api-cdn.thehive.ai/api/v3
        api: openai-completions
        compat:
          supportsReasoningEffort: true
        models:
          - id: deepseek-ai/deepseek-v4.1-flash-1017
            input: [text, image]
            reasoningEfforts:
              medium: medium
""".strip())
    for dis in ("mcp-github", "mcp-rea", "mcp-context7", "mcp-glmocr", "mcp-cad3d", "mcp-photoeditor", "mcp-searchd", "mcp-treg"):
        lines.append(f"- id: {dis}\n  disabled: true")
    if arm == "A":
        lines.append("- id: mcp-xt-forge\n  disabled: true")
    else:
        xt_home = aux / "xt_home"
        lines.append(f"""
- id: mcp-xt-forge
  disabled: false
  config:
    serverName: xt-forge
    transport: stdio
    command: {GO_HUB if GO_HUB.exists() else BIN_XTFORGE}
    args:
      - mcp
      - serve
      - --meta
    env:
      XT_HOME: {xt_home}
    failOnStartupError: false
""".strip())
    if tier == "tier3_recover" and arm == "A":
        srv = aux / "job_mcp_server.py"
        state_path = aux / "server_state.json"
        lines.append(f"""
- insert:
    - id: mcp-job-runner
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: job_runner
        transport: stdio
        command: {sys.executable}
        args:
          - {srv}
        env:
          XT_T3_STATE_PATH: {state_path}
        failOnStartupError: false
""".strip())
    patch.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return patch


def run_harness_arm(harness: str, tier: str, arm: str, ws: Path, aux: Path, timeout_s: int) -> dict[str, Any]:
    env = os.environ.copy()
    if not env.get("HIVE_AI_API_KEY") and env.get("THE_HIVE_API_KEY"):
        env["HIVE_AI_API_KEY"] = env["THE_HIVE_API_KEY"]
    prompt = build_tier_prompt(tier, arm, ws)
    model_id = ""
    cmd: list[str] = []

    if harness == "dsh":
        model_id = "hive-ai/deepseek-ai/deepseek-v4.1-flash-1017#medium"
        patch = _build_dsh_patch(aux, "hive-deepseek", tier, arm)
        cmd = ["dsh", "--profile", "headless", "--patch", str(patch), "--json", prompt]
    elif harness == "codex":
        model_id = "gpt-6-luna#medium"
        chome = aux / "codex_home"
        chome.mkdir(parents=True, exist_ok=True)
        real_auth = Path.home() / ".codex" / "auth.json"
        if real_auth.exists():
            shutil.copy2(real_auth, chome / "auth.json")
        cfg_lines = [
            'model = "gpt-6-luna"',
            'model_reasoning_effort = "medium"',
        ]
        if arm == "B":
            cfg_lines += [
                "",
                "[mcp_servers.xt-forge]",
                f'command = "{GO_HUB if GO_HUB.exists() else BIN_XTFORGE}"',
                'args = ["mcp", "serve", "--meta"]',
                f'env = {{ XT_HOME = "{aux / "xt_home"}" }}',
            ]
        elif tier == "tier3_recover":
            cfg_lines += [
                "",
                "[mcp_servers.job_runner]",
                f'command = "{sys.executable}"',
                f'args = ["{aux / "job_mcp_server.py"}"]',
                f'env = {{ XT_T3_STATE_PATH = "{aux / "server_state.json"}" }}',
            ]
        (chome / "config.toml").write_text("\n".join(cfg_lines) + "\n", encoding="utf-8")
        env["CODEX_HOME"] = str(chome)
        cmd = ["codex", "exec", "--json", "--skip-git-repo-check", "--approve-for-me", prompt]
    elif harness == "opencode":
        model_id = "openai/gpt-6-luna#medium"
        oc_cfg_path = aux / "opencode.json"
        mcp_block: dict[str, Any] = {
            "github": {"type": "local", "enabled": False},
            "treg": {"type": "remote", "enabled": False},
            "context7": {"type": "remote", "enabled": False},
        }
        if arm == "B":
            mcp_block["xt-forge"] = {
                "type": "local",
                "enabled": True,
                "command": [str(GO_HUB if GO_HUB.exists() else BIN_XTFORGE), "mcp", "serve", "--meta"],
                "environment": {"XT_HOME": str(aux / "xt_home")},
            }
        else:
            mcp_block["xt-forge"] = {"type": "local", "enabled": False}
            if tier == "tier3_recover":
                mcp_block["job_runner"] = {
                    "type": "local",
                    "enabled": True,
                    "command": [sys.executable, str(aux / "job_mcp_server.py")],
                    "environment": {"XT_T3_STATE_PATH": str(aux / "server_state.json")},
                }
        oc_cfg = {
            "$schema": "https://opencode.ai/config.json",
            "model": "openai/gpt-6-luna",
            "mcp": mcp_block,
            "plugins": [],
        }
        oc_cfg_path.write_text(json.dumps(oc_cfg, indent=2), encoding="utf-8")
        env["OPENCODE_CONFIG"] = str(oc_cfg_path)
        cmd = ["opencode", "run", "--standalone", "--auto", "--format", "json", "-m", "openai/gpt-6-luna#medium", prompt]
    else:
        raise ValueError(f"unknown harness: {harness}")

    t0 = time.perf_counter()
    timed_out = False
    stdout_raw = ""
    stderr_raw = ""
    rc = -1
    try:
        proc = subprocess.run(cmd, cwd=str(ws), env=env, text=True, capture_output=True, timeout=timeout_s)
        stdout_raw = proc.stdout
        stderr_raw = proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout_raw = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr_raw = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    wall_s = round(time.perf_counter() - t0, 2)

    parsed = parse_jsonl_telemetry(harness, stdout_raw)
    final_text = parsed["final_text"]

    extra_t3 = {}
    if timed_out:
        passed, fail_reason = False, f"timeout_{timeout_s}s"
    elif rc != 0 and not final_text and tier != "tier2_fix":
        passed, fail_reason = False, f"exit_{rc}"
    elif tier == "tier1_find":
        passed, fail_reason = grade_tier1(final_text)
    elif tier == "tier2_fix":
        passed, fail_reason = grade_tier2(ws)
    else:
        passed, fail_reason, extra_t3 = grade_tier3(aux, final_text)

    row = {
        "tier": tier,
        "arm": arm,
        "harness": harness,
        "model": model_id,
        "pass": passed,
        "failed_assertion": fail_reason,
        "wall_s": wall_s,
        "input_tokens": parsed["input_tokens"],
        "output_tokens": parsed["output_tokens"],
        "tool_calls": parsed["tool_calls"],
        "repeated_calls": parsed["repeated_calls"],
        "xtforge_calls": parsed["xtforge_calls"],
        "trace_excerpt": sanitize_text(stdout_raw[-1200:] + ("\nERR:" + stderr_raw[-400:] if stderr_raw else "")),
    }
    row.update(extra_t3)
    return row


def run_preflight_smoke(harnesses: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    tmp = Path(tempfile.mkdtemp(prefix="xt_t3_smoke_"))
    try:
        for h in harnesses:
            ws = tmp / h / "ws"
            aux = tmp / h / "aux"
            ws.mkdir(parents=True, exist_ok=True)
            aux.mkdir(parents=True, exist_ok=True)
            (ws / "smoke.txt").write_text("SMOKE_OK_9182\n", encoding="utf-8")
            env = os.environ.copy()
            if not env.get("HIVE_AI_API_KEY") and env.get("THE_HIVE_API_KEY"):
                env["HIVE_AI_API_KEY"] = env["THE_HIVE_API_KEY"]
            prompt = f"Workspace root: {ws}\nRead smoke.txt using a tool and reply ONLY with its token."
            if h == "dsh":
                patch = _build_dsh_patch(aux, "hive-deepseek", "tier1_find", "A")
                cmd = ["dsh", "--profile", "headless", "--patch", str(patch), "--json", prompt]
                model = "hive-ai/deepseek-ai/deepseek-v4.1-flash-1017#medium"
            elif h == "codex":
                chome = aux / "codex_home"
                chome.mkdir(parents=True, exist_ok=True)
                ra = Path.home() / ".codex" / "auth.json"
                if ra.exists():
                    shutil.copy2(ra, chome / "auth.json")
                (chome / "config.toml").write_text('model = "gpt-6-luna"\nmodel_reasoning_effort = "medium"\n', encoding="utf-8")
                env["CODEX_HOME"] = str(chome)
                cmd = ["codex", "exec", "--json", "--skip-git-repo-check", "--approve-for-me", prompt]
                model = "gpt-6-luna#medium"
            else:
                oc_cfg = aux / "oc.json"
                oc_cfg.write_text(json.dumps({"model": "openai/gpt-6-luna", "plugins": [], "mcp": {"xt-forge": {"type": "local", "enabled": False}}}), encoding="utf-8")
                env["OPENCODE_CONFIG"] = str(oc_cfg)
                cmd = ["opencode", "run", "--standalone", "--auto", "--format", "json", "-m", "openai/gpt-6-luna#medium", prompt]
                model = "openai/gpt-6-luna#medium"
            t0 = time.perf_counter()
            try:
                p = subprocess.run(cmd, cwd=str(ws), env=env, text=True, capture_output=True, timeout=45)
                ok = p.returncode == 0 and "SMOKE_OK_9182" in p.stdout
                results[h] = {"ok": ok, "model": model, "wall_s": round(time.perf_counter() - t0, 2), "err": None if ok else sanitize_text(p.stderr[:180])}
            except Exception as exc:
                results[h] = {"ok": False, "model": model, "wall_s": round(time.perf_counter() - t0, 2), "err": str(exc)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return results


def harness_versions(harnesses: list[str]) -> dict[str, str]:
    out = {}
    for h in harnesses:
        try:
            r = subprocess.run([h, "--version"], text=True, capture_output=True, timeout=5)
            out[h] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else "unknown"
        except Exception:
            out[h] = "unavailable"
    return out


def self_test() -> int:
    """Offline verification of fixture generation, graders, and Tier 3 mock server."""
    tmp = Path(tempfile.mkdtemp(prefix="xt_t3_selftest_"))
    try:
        # Tier 1 grading
        ok1, err1 = grade_tier1("should_retry_attempt in src/policy/retry_budget.py; dispatch_job in src/workers/job_runner.py; flush_webhook in src/clients/webhook_pump.py")
        assert ok1 and err1 is None, err1
        ok1_bad, _ = grade_tier1("should_retry_attempt in retry_budget.py; test_fake_retry_caller; dispatch_job in job_runner.py; flush_webhook in webhook_pump.py")
        assert not ok1_bad

        # Tier 2 grading: fails before fix, passes after fix.
        ws2, _ = prepare_tier_workspace(tmp, "tier2_fix", "A")
        ok2_pre, _ = grade_tier2(ws2)
        assert not ok2_pre, "Tier 2 must fail hidden tests before fix"
        p_file = ws2 / "src" / "queue" / "policy.py"
        p_file.write_text(p_file.read_text(encoding="utf-8").replace("retries_used <= max_retries", "retries_used < max_retries"), encoding="utf-8")
        ok2_post, err2_post = grade_tier2(ws2)
        assert ok2_post and err2_post is None, err2_post

        # Tier 3 grading + recovery turn-by-turn through Go hub --meta / Python fallback.
        ws3, aux3 = prepare_tier_workspace(tmp, "tier3_recover", "B")
        mcp_bin = str(GO_HUB if GO_HUB.exists() else BIN_XTFORGE)
        env = {**os.environ, "XT_HOME": str(aux3 / "xt_home")}
        proc = subprocess.Popen(
            [mcp_bin, "mcp", "serve", "--meta"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env,
        )
        replies = []
        try:
            assert proc.stdin is not None and proc.stdout is not None
            call_args = {
                "name": "job_runner:submit_job",
                "arguments": {"job_id": "job-alpha-01", "payload": "nightly-rollup"},
                "idempotency_key": "job-alpha-01",
                "verify_tool": "get_receipt",
                "verify_args": {"job_id": "job-alpha-01"},
            }
            for req in (
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "st", "version": "1"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "xt_call", "arguments": call_args}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "xt_call", "arguments": call_args}},
            ):
                proc.stdin.write(json.dumps(req) + "\n")
                proc.stdin.flush()
                replies.append(proc.stdout.readline())
        finally:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=5)
        out_joined = "\n".join(replies)
        assert "rcpt-9482" in out_joined, out_joined
        ok3, err3, m3 = grade_tier3(aux3, out_joined)
        assert ok3 and m3 == {"commits": 1, "submit_attempts": 1, "duplicate_attempts": 0}, (err3, m3)
        print("three_tier self-test: OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true", help="Verify fixtures, hidden graders, and mock MCP recovery offline")
    ap.add_argument("--harnesses", default="dsh,codex,opencode")
    ap.add_argument("--tiers", default="tier1_find,tier2_fix,tier3_recover")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    harnesses = [h.strip() for h in args.harnesses.split(",") if h.strip()]
    tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
    git_rev = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], text=True, capture_output=True).stdout.strip() or "unknown"
    h_vers = harness_versions(harnesses)
    smoke = run_preflight_smoke(harnesses)

    rows: list[dict[str, Any]] = []
    work_tmp = Path(tempfile.mkdtemp(prefix="xt_three_tier_live_"))
    try:
        for h in harnesses:
            if not smoke.get(h, {}).get("ok"):
                continue
            for idx, tier in enumerate(tiers):
                # Alternate A/B order cleanly between tiers.
                order = ("A", "B") if idx % 2 == 0 else ("B", "A")
                for arm in order:
                    ws, aux = prepare_tier_workspace(work_tmp / h, tier, arm)
                    row = run_harness_arm(h, tier, arm, ws, aux, TIER_BUDGETS_S[tier])
                    rows.append(row)
    finally:
        shutil.rmtree(work_tmp, ignore_errors=True)

    summary = {
        "xt_forge_revision": git_rev,
        "fixture_revision": fixture_revision_digest(),
        "harness_versions": h_vers,
        "preflight_smoke": smoke,
        "rows": rows,
    }

    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        csv_fields = ["tier", "arm", "harness", "model", "pass", "failed_assertion", "wall_s", "input_tokens", "output_tokens", "tool_calls", "repeated_calls", "xtforge_calls"]
        with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=csv_fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"three-tier benchmark rev={git_rev} fixture={summary['fixture_revision']}")
        print("preflight:", json.dumps(smoke))
        print(f"{'tier':<14} {'arm':<3} {'harness':<9} {'pass':<5} {'wall_s':>6} {'in_tok':>8} {'out_tok':>8} {'tools':>5} {'reps':>4} {'xtf':>4}  note")
        for r in rows:
            print(
                f"{r['tier']:<14} {r['arm']:<3} {r['harness']:<9} {str(r['pass']):<5} "
                f"{r['wall_s']:>6.1f} {str(r['input_tokens']):>8} {str(r['output_tokens']):>8} "
                f"{r['tool_calls']:>5} {r['repeated_calls']:>4} {r['xtforge_calls']:>4}  {r.get('failed_assertion') or 'ok'}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
