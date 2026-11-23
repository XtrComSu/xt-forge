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
import selectors
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BIN_XTFORGE = ROOT / "bin" / "xtforge"
GO_HUB = ROOT / "native" / "xtforge-go" / "xtforge-hub"


def runtime_metadata(*, use_meta: bool = True) -> dict[str, str]:
    exe = str(GO_HUB if (use_meta and GO_HUB.exists()) else BIN_XTFORGE)
    git_rev = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], text=True, capture_output=True).stdout.strip() or "unknown"
    ver = subprocess.run([str(BIN_XTFORGE), "--version"], text=True, capture_output=True).stdout.strip().splitlines()
    return {
        "executable_path": exe,
        "xtforge_version": ver[0] if ver else "unknown",
        "git_commit": git_rev,
    }

TIER_BUDGETS_S = {
    "tier1_find": 60,
    "tier2_fix": 90,
    "tier3_recover": 90,
    "tier4_defects": 90,
    "tier5_trace": 90,
    "tier6_regression_src": 120,
    "tier6_regression_bin": 120,
    "tier7_re_decompile_hard": 120,
    "tier8_re_patch_diff_hard": 120,
    "tier9_re_rtti_vtable_hard": 120,
}

SHORT_GENERAL_RULE = (
    "# Workspace Rule\n"
    "Start with `xt_call` (`code_callers`, `code_audit`, `code_trace`, `re_diff`, `re_decompile`, `re_rtti`, `re_borer`, or `re_anchors`) on the workspace root or binaries. "
    "When a tool returns `evidence_complete: true` (with function excerpts, disassembly, `diff_notes`, pseudocode, or `production_ambiguous: false`), "
    "answer immediately from that output without re-reading clean files, running brute-force shell/python sweeps, or re-running objdump/grep. "
    "Run an additional check only when `production_ambiguous: true`, `audit_complete: false`, the index is stale, or the evidence conflicts.\n"
)

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

TIER1_HELDOUT_FILES = {
    "src/policy/backoff_policy.py": '''"""Authoritative backoff decision policy."""
from __future__ import annotations


def allow_backoff_retry(attempt: int, cap: int, code: int) -> bool:
    if attempt >= cap:
        return False
    return code in (429, 502, 503, 504)
''',
    "src/workers/pool_worker.py": '''"""Worker pool executor."""
from __future__ import annotations

from src.policy.backoff_policy import allow_backoff_retry


def run_pool_task(item: dict, code: int) -> str:
    if allow_backoff_retry(int(item.get("n", 0)), int(item.get("cap", 3)), code):
        return "retry"
    return "abort"
''',
    "src/egress/hook_sender.py": '''"""Webhook egress sender."""
from __future__ import annotations

from src.policy.backoff_policy import allow_backoff_retry


def post_hook_event(evt_id: str, attempt: int, code: int) -> str:
    return f"retry:{evt_id}" if allow_backoff_retry(attempt, 4, code) else f"drop:{evt_id}"
''',
    "docs/BACKOFF_NOTES.md": '''# Legacy Backoff Notes (DEPRECATED)
Historically `legacy_backoff_check` in `src/old_pool.py` was called by `drain_old_pool` and `replay_old_hooks`.
''',
    "tests/test_backoff_stub.py": '''def allow_backoff_retry(attempt: int, cap: int, code: int) -> bool:
    return attempt == 0 and code == 503


def test_fake_backoff_caller() -> None:
    assert allow_backoff_retry(0, 1, 503) is True
''',
}

TIER4_FILES = {
    "src/__init__.py": "",
    "src/billing/__init__.py": "",
    "src/reporting/__init__.py": "",
    "src/billing/formatter.py": '''"""Clean currency formatting helpers (no defects)."""
from __future__ import annotations


def format_cents(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    v = abs(cents)
    return f"{sign}${v // 100}.{v % 100:02d}"
''',
    "src/billing/tax.py": '''"""Clean tax rounding helper (no defects)."""
from __future__ import annotations


def compute_tax_cents(amount_cents: int, rate_bps: int) -> int:
    if amount_cents <= 0 or rate_bps <= 0:
        return 0
    return (amount_cents * rate_bps + 5000) // 10000
''',
    "src/reporting/invoice_report.py": '''"""Customer billing report builder."""
from __future__ import annotations


def build_customer_report(invoices: list[dict], adjustments: list[dict]) -> list[dict]:
    """Emit one summary row per invoice enriched with matching adjustments."""
    rows: list[dict] = []
    # BUG 1 (duplicate billing rows): nested loop appends one row per adjustment
    # for the same invoice_id instead of aggregating adjustments per invoice.
    for inv in invoices:
        for adj in adjustments:
            if adj.get("invoice_id") == inv.get("id"):
                rows.append({
                    "invoice_id": inv["id"],
                    "customer": inv["customer"],
                    "amount_cents": inv["amount_cents"] + adj["delta_cents"],
                })
        if not any(a.get("invoice_id") == inv.get("id") for a in adjustments):
            rows.append({
                "invoice_id": inv["id"],
                "customer": inv["customer"],
                "amount_cents": inv["amount_cents"],
            })
    return rows
''',
    "src/billing/period_filter.py": '''"""Billing period window filter."""
from __future__ import annotations


def filter_charges_in_window(charges: list[dict], start_date: str, end_date: str) -> list[dict]:
    """Return charges occurring within [start_date, end_date] inclusive (YYYY-MM-DD)."""
    # BUG 2 (incorrect date boundary): uses `< end_date` instead of `<= end_date`,
    # silently dropping charges on the inclusive end_date boundary.
    return [
        c for c in charges
        if start_date <= str(c.get("date", "")) < end_date
    ]
''',
    "src/billing/ledger_cache.py": '''"""Account ledger and cached totals."""
from __future__ import annotations

_LEDGER: dict[str, list[int]] = {}
_TOTALS_CACHE: dict[str, int] = {}


def get_account_total(account_id: str) -> int:
    """Return cached total cents for account_id."""
    if account_id not in _TOTALS_CACHE:
        _TOTALS_CACHE[account_id] = sum(_LEDGER.get(account_id, []))
    return _TOTALS_CACHE[account_id]


def record_charge(account_id: str, amount_cents: int) -> None:
    """Append a charge to the ledger."""
    # BUG 3 (stale cached totals): appends to _LEDGER without invalidating _TOTALS_CACHE.
    _LEDGER.setdefault(account_id, []).append(amount_cents)
''',
}

TIER4_HELDOUT_FILES = {
    "src/__init__.py": "",
    "src/commerce/__init__.py": "",
    "src/commerce/labels.py": '''"""Clean formatting helper (no defects)."""
from __future__ import annotations


def order_tag(order_id: str) -> str:
    return f"ORD-{order_id.strip().upper()}"
''',
    "src/commerce/order_report.py": '''"""Order settlement report builder."""
from __future__ import annotations


def compile_order_rows(orders: list[dict], rebates: list[dict]) -> list[dict]:
    """Build one settlement row per order."""
    out: list[dict] = []
    for order in orders:
        for reb in rebates:
            if reb.get("order_id") == order.get("id"):
                out.append({
                    "order_id": order["id"],
                    "net_cents": order["total_cents"] - reb["credit_cents"],
                })
        if not any(r.get("order_id") == order.get("id") for r in rebates):
            out.append({"order_id": order["id"], "net_cents": order["total_cents"]})
    return out
''',
    "src/commerce/window_filter.py": '''"""Settlement date range selector."""
from __future__ import annotations


def select_entries_for_period(entries: list[dict], from_date: str, to_date: str) -> list[dict]:
    """Select entries inside inclusive [from_date, to_date] YYYY-MM-DD bounds."""
    return [e for e in entries if from_date <= str(e.get("booked_at", "")) < to_date]
''',
    "src/commerce/balance_memo.py": '''"""Merchant balance ledger with memoized totals."""
from __future__ import annotations

_POSTINGS: dict[str, list[int]] = {}
_BALANCE_CACHE: dict[str, int] = {}


def fetch_merchant_balance(merchant_id: str) -> int:
    if merchant_id not in _BALANCE_CACHE:
        _BALANCE_CACHE[merchant_id] = sum(_POSTINGS.get(merchant_id, []))
    return _BALANCE_CACHE[merchant_id]


def post_settlement(merchant_id: str, cents: int) -> None:
    _POSTINGS.setdefault(merchant_id, []).append(cents)
''',
}

TIER5_FILES = {
    "config/runtime.json": json.dumps({"active_handler": "v2", "region": "us-east"}, indent=2) + "\n",
    "src/__init__.py": "",
    "src/config/__init__.py": "",
    "src/config/loader.py": '''"""Runtime configuration loader."""
from __future__ import annotations

import json
from pathlib import Path

DEFAULT_MODE = "v2"


def load_active_handler_mode() -> str:
    cfg = Path(__file__).resolve().parents[2] / "config" / "runtime.json"
    if cfg.is_file():
        return str(json.loads(cfg.read_text(encoding="utf-8")).get("active_handler", DEFAULT_MODE))
    return DEFAULT_MODE
''',
    "src/handlers/__init__.py": '''"""Public handler re-exports."""
from __future__ import annotations

from .active_v2 import handle_event as active_v2_handle
from .legacy_v1 import handle_event as legacy_v1_handle

__all__ = ["active_v2_handle", "legacy_v1_handle"]
''',
    "src/handlers/legacy_v1.py": '''"""Legacy v1 event handler (inactive)."""
from __future__ import annotations


def handle_event(payload: dict) -> dict:
    return {"engine": "legacy_v1", "ok": True, "id": payload.get("id")}
''',
    "src/handlers/active_v2.py": '''"""Current v2 event handler (selected by runtime config)."""
from __future__ import annotations


def handle_event(payload: dict) -> dict:
    return {"engine": "active_v2", "ok": True, "id": payload.get("id")}
''',
    "src/api/__init__.py": "",
    "src/api/entrypoint.py": '''"""HTTP API entry point."""
from __future__ import annotations

from src.config.loader import load_active_handler_mode
from src.handlers import active_v2_handle, legacy_v1_handle

DISPATCH_TABLE = {
    "v1": legacy_v1_handle,
    "v2": active_v2_handle,
}


def dispatch_request(payload: dict) -> dict:
    mode = load_active_handler_mode()
    handler = DISPATCH_TABLE[mode]
    return handler(payload)
''',
}

TIER5_HELDOUT_FILES = {
    "config/pipeline.json": json.dumps({"pipeline_impl": "beta"}, indent=2) + "\n",
    "src/__init__.py": "",
    "src/settings/__init__.py": "",
    "src/settings/env.py": '''from __future__ import annotations
import json
from pathlib import Path


def get_pipeline_impl() -> str:
    p = Path(__file__).resolve().parents[2] / "config" / "pipeline.json"
    return str(json.loads(p.read_text(encoding="utf-8")).get("pipeline_impl", "beta"))
''',
    "src/pipelines/__init__.py": '''from .alpha_impl import process_item as alpha_process
from .beta_impl import process_item as beta_process
''',
    "src/pipelines/alpha_impl.py": '''def process_item(x: dict) -> dict:
    return {"pipeline": "alpha", "x": x}
''',
    "src/pipelines/beta_impl.py": '''def process_item(x: dict) -> dict:
    return {"pipeline": "beta", "x": x}
''',
    "src/router/__init__.py": "",
    "src/router/gateway.py": '''from src.pipelines import alpha_process, beta_process
from src.settings.env import get_pipeline_impl

PIPELINES = {"alpha": alpha_process, "beta": beta_process}


def route_payload(x: dict) -> dict:
    impl = get_pipeline_impl()
    return PIPELINES[impl](x)
''',
}

TIER6_C_V1 = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compute_subtotal(int qty, int unit_cents) {
    return qty * unit_cents;
}

int apply_tier_discount(int subtotal, int qty, const char *tier) {
    if (strcmp(tier, "gold") == 0 && qty >= 10) {
        return subtotal - (subtotal * 10) / 100;
    }
    if (strcmp(tier, "silver") == 0 && qty >= 10) {
        return subtotal - (subtotal * 5) / 100;
    }
    return subtotal;
}

int main(int argc, char **argv) {
    int qty = 1;
    int unit_cents = 100;
    const char *tier = "standard";
    for (int i = 1; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--qty") == 0) qty = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "--unit-cents") == 0) unit_cents = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "--tier") == 0) tier = argv[i + 1];
    }
    int sub = compute_subtotal(qty, unit_cents);
    int total = apply_tier_discount(sub, qty, tier);
    printf("total_cents=%d\n", total);
    return 0;
}
'''

TIER7_C = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t magic;
    uint16_t flags;
    uint16_t channel;
    uint64_t nonce;
    uint32_t quota;
} TokenPacket;

__attribute__((noinline))
static uint32_t validate_token(const TokenPacket *pkt) {
    if (!pkt) return 0;
    if (pkt->magic != 0x58544639U) return 0;
    if ((pkt->flags & 0x15U) != 0x15U) return 0;
    uint64_t bucket = pkt->nonce / 7ULL;
    uint32_t slot = pkt->quota % 13U;
    if ((uint32_t)(bucket + slot) == 42U) {
        return 1U;
    }
    return 0U;
}

__attribute__((noinline))
static uint32_t decoy_mix(uint32_t x) {
    return (x ^ 0xA5A55A5AU) + 17U;
}

int main(int argc, char **argv) {
    TokenPacket pkt = {0x58544639U, 0x15U, 3U, 252ULL, 19U};
    if (argc > 1) pkt.quota = (uint32_t)atoi(argv[1]);
    if (decoy_mix(pkt.channel) == 0U) return 2;
    if (validate_token(&pkt)) {
        puts("GATEKEEPER_TOKEN_OK");
        return 0;
    }
    puts("GATEKEEPER_DENIED");
    return 1;
}
'''

TIER8_C_V1 = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
static uint32_t hash_mix(uint32_t v) {
    return (v * 2654435761U) ^ (v >> 13);
}

__attribute__((noinline))
static int verify_session(uint32_t token, uint32_t level) {
    if ((token & 0xF0U) != 0xA0U) return 0;
    if ((level / 7U) < 4U) return 0;
    return 1;
}

int main(int argc, char **argv) {
    uint32_t token = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 0) : 0x85U;
    uint32_t level = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 0) : 10U;
    if (hash_mix(token) == 0U) return 2;
    puts(verify_session(token, level) ? "ALLOW" : "DENY");
    return 0;
}
'''

TIER8_C_V2 = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
static uint32_t hash_mix(uint32_t v) {
    return (v * 2654435761U) ^ (v >> 13);
}

__attribute__((noinline))
static int verify_session(uint32_t token, uint32_t level) {
    if ((token & 0xF0U) != 0x80U) return 0;
    if ((level / 7U) < 1U) return 0;
    return 1;
}

int main(int argc, char **argv) {
    uint32_t token = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 0) : 0x85U;
    uint32_t level = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 0) : 10U;
    if (hash_mix(token) == 0U) return 2;
    puts(verify_session(token, level) ? "ALLOW" : "DENY");
    return 0;
}
'''

TIER9_CPP = r'''#include <iostream>
#include <memory>
#include <vector>

class PacketHandler {
public:
    virtual ~PacketHandler() = default;
    virtual int opcode() const = 0;
    virtual int process(int x) const = 0;
};

class LegacyDropHandler : public PacketHandler {
public:
    int opcode() const override { return 0x11; }
    int process(int x) const override { return x * 2; }
};

class SecureVaultHandler : public PacketHandler {
public:
    int opcode() const override { return 0x7A; }
    int process(int x) const override { return (x ^ 0x55) + 19; }
};

class MetricsTapHandler : public PacketHandler {
public:
    int opcode() const override { return 0x33; }
    int process(int x) const override { return x + 7; }
};

int main(int argc, char **argv) {
    std::vector<std::unique_ptr<PacketHandler>> handlers;
    handlers.push_back(std::make_unique<LegacyDropHandler>());
    handlers.push_back(std::make_unique<SecureVaultHandler>());
    handlers.push_back(std::make_unique<MetricsTapHandler>());
    int x = argc > 1 ? std::atoi(argv[1]) : 10;
    int total = 0;
    for (const auto &h : handlers) {
        total += h->opcode() + h->process(x);
    }
    std::cout << "total=" << total << "\n";
    return 0;
}
'''

TIER6_C_V2 = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compute_subtotal(int qty, int unit_cents) {
    return qty * unit_cents;
}

int apply_tier_discount(int subtotal, int qty, const char *tier) {
    /* Regression: gold tier discount dropped from 10% to 5%. */
    if (strcmp(tier, "gold") == 0 && qty >= 10) {
        return subtotal - (subtotal * 5) / 100;
    }
    if (strcmp(tier, "silver") == 0 && qty >= 10) {
        return subtotal - (subtotal * 5) / 100;
    }
    return subtotal;
}

int main(int argc, char **argv) {
    int qty = 1;
    int unit_cents = 100;
    const char *tier = "standard";
    for (int i = 1; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--qty") == 0) qty = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "--unit-cents") == 0) unit_cents = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "--tier") == 0) tier = argv[i + 1];
    }
    int sub = compute_subtotal(qty, unit_cents);
    int total = apply_tier_discount(sub, qty, tier);
    printf("total_cents=%d\n", total);
    return 0;
}
'''

TIER7_C = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t magic;
    uint16_t flags;
    uint16_t channel;
    uint64_t nonce;
    uint32_t quota;
} TokenPacket;

__attribute__((noinline))
static uint32_t validate_token(const TokenPacket *pkt) {
    if (!pkt) return 0;
    if (pkt->magic != 0x58544639U) return 0;
    if ((pkt->flags & 0x15U) != 0x15U) return 0;
    uint64_t bucket = pkt->nonce / 7ULL;
    uint32_t slot = pkt->quota % 13U;
    if ((uint32_t)(bucket + slot) == 42U) {
        return 1U;
    }
    return 0U;
}

__attribute__((noinline))
static uint32_t decoy_mix(uint32_t x) {
    return (x ^ 0xA5A55A5AU) + 17U;
}

int main(int argc, char **argv) {
    TokenPacket pkt = {0x58544639U, 0x15U, 3U, 252ULL, 19U};
    if (argc > 1) pkt.quota = (uint32_t)atoi(argv[1]);
    if (decoy_mix(pkt.channel) == 0U) return 2;
    if (validate_token(&pkt)) {
        puts("GATEKEEPER_TOKEN_OK");
        return 0;
    }
    puts("GATEKEEPER_DENIED");
    return 1;
}
'''

TIER8_C_V1 = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
static uint32_t hash_mix(uint32_t v) {
    return (v * 2654435761U) ^ (v >> 13);
}

__attribute__((noinline))
static int verify_session(uint32_t token, uint32_t level) {
    if ((token & 0xF0U) != 0xA0U) return 0;
    if ((level / 7U) < 4U) return 0;
    return 1;
}

int main(int argc, char **argv) {
    uint32_t token = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 0) : 0x85U;
    uint32_t level = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 0) : 10U;
    if (hash_mix(token) == 0U) return 2;
    puts(verify_session(token, level) ? "ALLOW" : "DENY");
    return 0;
}
'''

TIER8_C_V2 = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
static uint32_t hash_mix(uint32_t v) {
    return (v * 2654435761U) ^ (v >> 13);
}

__attribute__((noinline))
static int verify_session(uint32_t token, uint32_t level) {
    if ((token & 0xF0U) != 0x80U) return 0;
    if ((level / 7U) < 1U) return 0;
    return 1;
}

int main(int argc, char **argv) {
    uint32_t token = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 0) : 0x85U;
    uint32_t level = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 0) : 10U;
    if (hash_mix(token) == 0U) return 2;
    puts(verify_session(token, level) ? "ALLOW" : "DENY");
    return 0;
}
'''

TIER9_CPP = r'''#include <iostream>
#include <memory>
#include <vector>

class PacketHandler {
public:
    virtual ~PacketHandler() = default;
    virtual int opcode() const = 0;
    virtual int process(int x) const = 0;
};

class LegacyDropHandler : public PacketHandler {
public:
    int opcode() const override { return 0x11; }
    int process(int x) const override { return x * 2; }
};

class SecureVaultHandler : public PacketHandler {
public:
    int opcode() const override { return 0x7A; }
    int process(int x) const override { return (x ^ 0x55) + 19; }
};

class MetricsTapHandler : public PacketHandler {
public:
    int opcode() const override { return 0x33; }
    int process(int x) const override { return x + 7; }
};

int main(int argc, char **argv) {
    std::vector<std::unique_ptr<PacketHandler>> handlers;
    handlers.push_back(std::make_unique<LegacyDropHandler>());
    handlers.push_back(std::make_unique<SecureVaultHandler>());
    handlers.push_back(std::make_unique<MetricsTapHandler>());
    int x = argc > 1 ? std::atoi(argv[1]) : 10;
    int total = 0;
    for (const auto &h : handlers) {
        total += h->opcode() + h->process(x);
    }
    std::cout << "total=" << total << "\n";
    return 0;
}
'''


def fixture_revision_digest() -> str:
    h = hashlib.sha256()
    for grp in (TIER1_FILES, TIER1_HELDOUT_FILES, TIER2_FILES, TIER4_FILES, TIER4_HELDOUT_FILES, TIER5_FILES, TIER5_HELDOUT_FILES):
        for k in sorted(grp):
            h.update(k.encode())
            h.update(grp[k].encode())
    h.update(TIER6_C_V1.encode())
    h.update(TIER6_C_V2.encode())
    h.update(TIER7_C.encode())
    h.update(TIER8_C_V1.encode())
    h.update(TIER8_C_V2.encode())
    h.update(TIER9_CPP.encode())
    h.update(TIER2_HIDDEN_TEST.encode())
    h.update(MOCK_JOB_MCP_SERVER_PY.encode())
    return h.hexdigest()[:12]


def prepare_tier_workspace(
    base: Path,
    tier: str,
    arm: str,
    *,
    use_meta: bool = True,
    variant: str = "primary",
    instructions_mode: str = "short",
    cold_index: bool = False,
) -> tuple[Path, Path]:
    """Create isolated workspace + state/xt_home dir for (tier, arm)."""
    ws = base / f"{tier}_{variant}_{arm}_ws"
    aux = base / f"{tier}_{variant}_{arm}_aux"
    ws.mkdir(parents=True, exist_ok=True)
    aux.mkdir(parents=True, exist_ok=True)

    file_map = {
        ("tier1_find", "primary"): TIER1_FILES,
        ("tier1_find", "heldout"): TIER1_HELDOUT_FILES,
        ("tier2_fix", "primary"): TIER2_FILES,
        ("tier2_fix", "heldout"): TIER2_FILES,
        ("tier4_defects", "primary"): TIER4_FILES,
        ("tier4_defects", "heldout"): TIER4_HELDOUT_FILES,
        ("tier5_trace", "primary"): TIER5_FILES,
        ("tier5_trace", "heldout"): TIER5_HELDOUT_FILES,
    }.get((tier, variant), {})
    for rel, content in file_map.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    if tier in ("tier6_regression_src", "tier6_regression_bin"):
        bin_dir = ws / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            raise RuntimeError("gcc or clang required to compile Tier 6 fixtures")
        src_dir = (ws / "src") if tier == "tier6_regression_src" else (aux / "src")
        src_dir.mkdir(parents=True, exist_ok=True)
        c1 = src_dir / "pricing_v1.c"
        c2 = src_dir / "pricing_v2.c"
        c1.write_text(TIER6_C_V1, encoding="utf-8")
        c2.write_text(TIER6_C_V2, encoding="utf-8")
        for c_path, out_bin in ((c1, bin_dir / "calc_v1"), (c2, bin_dir / "calc_v2")):
            flags = [cc, "-O0", "-g", str(c_path), "-o", str(out_bin)] if tier == "tier6_regression_src" else [cc, "-O0", c_path.name, "-o", str(out_bin)]
            r = subprocess.run(flags, cwd=str(src_dir), text=True, capture_output=True, timeout=20)
            if r.returncode != 0:
                raise RuntimeError(f"failed to compile {c_path}: {r.stderr}")
        if tier == "tier6_regression_bin":
            shutil.rmtree(src_dir, ignore_errors=True)
        (ws / "REPRO_INPUT.txt").write_text(
            "Supplied input: --qty 12 --unit-cents 500 --tier gold\n"
            "Observed v1 (./bin/calc_v1): total_cents=5400\n"
            "Observed v2 (./bin/calc_v2): total_cents=5700\n",
            encoding="utf-8",
        )

    if tier == "tier7_re_decompile_hard":
        bin_dir = ws / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            raise RuntimeError("gcc or clang required to compile Tier 7 fixture")
        src_dir = aux / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        c_path = src_dir / "gatekeeper.c"
        c_path.write_text(TIER7_C, encoding="utf-8")
        r = subprocess.run([cc, "-O2", "-s", c_path.name, "-o", str(bin_dir / "gatekeeper")], cwd=str(src_dir), text=True, capture_output=True, timeout=20)
        if r.returncode != 0:
            raise RuntimeError(f"failed to compile {c_path}: {r.stderr}")
        shutil.rmtree(src_dir, ignore_errors=True)

    if tier == "tier8_re_patch_diff_hard":
        bin_dir = ws / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            raise RuntimeError("gcc or clang required to compile Tier 8 fixtures")
        src_dir = aux / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        c1 = src_dir / "auth_v1.c"
        c2 = src_dir / "auth_v2.c"
        c1.write_text(TIER8_C_V1, encoding="utf-8")
        c2.write_text(TIER8_C_V2, encoding="utf-8")
        for c_path, out_bin in ((c1, bin_dir / "auth_v1"), (c2, bin_dir / "auth_v2")):
            r = subprocess.run([cc, "-O2", "-s", c_path.name, "-o", str(out_bin)], cwd=str(src_dir), text=True, capture_output=True, timeout=20)
            if r.returncode != 0:
                raise RuntimeError(f"failed to compile {c_path}: {r.stderr}")
        shutil.rmtree(src_dir, ignore_errors=True)
        (ws / "REPRO_INPUT.txt").write_text(
            "Supplied input: 0x85 10\n"
            "Observed v1 (./bin/auth_v1 0x85 10): DENY\n"
            "Observed v2 (./bin/auth_v2 0x85 10): ALLOW\n",
            encoding="utf-8",
        )

    if tier == "tier9_re_rtti_vtable_hard":
        bin_dir = ws / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        cxx = shutil.which("g++") or shutil.which("clang++")
        if not cxx:
            raise RuntimeError("g++ or clang++ required to compile Tier 9 fixture")
        src_dir = aux / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        cpp_path = src_dir / "router_cpp.cpp"
        cpp_path.write_text(TIER9_CPP, encoding="utf-8")
        r = subprocess.run([cxx, "-O2", "-s", cpp_path.name, "-o", str(bin_dir / "router_cpp")], cwd=str(src_dir), text=True, capture_output=True, timeout=20)
        if r.returncode != 0:
            raise RuntimeError(f"failed to compile {cpp_path}: {r.stderr}")
        shutil.rmtree(src_dir, ignore_errors=True)

    if tier == "tier3_recover":
        srv = aux / "job_mcp_server.py"
        srv.write_text(MOCK_JOB_MCP_SERVER_PY, encoding="utf-8")
        os.chmod(srv, 0o755)
        (ws / "JOB_REQUEST.json").write_text(
            json.dumps({"job_id": "job-alpha-01", "payload": "nightly-rollup"}, indent=2) + "\n",
            encoding="utf-8",
        )

    if arm in ("B", "C"):
        xt_home = aux / "xt_home"
        xt_home.mkdir(parents=True, exist_ok=True)
        xt_env = {**os.environ, "XT_HOME": str(xt_home)}
        if not cold_index and tier in ("tier1_find", "tier2_fix", "tier4_defects", "tier5_trace"):
            subprocess.run(
                [str(BIN_XTFORGE), "code", "index", str(ws), "--json"],
                env=xt_env,
                capture_output=True, text=True, timeout=15,
            )
        if tier == "tier3_recover":
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
            if instructions_mode != "none":
                if use_meta:
                    (ws / "AGENTS.md").write_text(
                        "# Workspace Rule\n"
                        "Use `xt_call` on `job_runner:submit_job` with `idempotency_key`, `verify_tool`, and `verify_args` for non-idempotent writes.\n",
                        encoding="utf-8",
                    )
                else:
                    (ws / "AGENTS.md").write_text(
                        "# Workspace Rule\n"
                        "Use `job_runner_call` with `idempotency_key`, `verify_tool`, and `verify_args`.\n",
                        encoding="utf-8",
                    )
        elif instructions_mode == "short":
            (ws / "AGENTS.md").write_text(SHORT_GENERAL_RULE, encoding="utf-8")
        elif instructions_mode == "verbose":
            (ws / "AGENTS.md").write_text(
                SHORT_GENERAL_RULE
                + "Available XT-Forge MCP calls via `xt_call`: `code_graph`, `code_callers`, `code_audit`, `code_trace`, `route_context`, `re_diff`.\n",
                encoding="utf-8",
            )
    return ws, aux


def build_tier_prompt(tier: str, arm: str, ws: Path, *, use_meta: bool = True, variant: str = "primary") -> str:
    extra = f" XT-Forge (`{BIN_XTFORGE}` / `xt-forge` MCP) is available." if arm in ("B", "C") else ""
    if tier == "tier1_find":
        return (
            f"Workspace root: {ws}\n"
            "Question: Which function decides whether to retry, and which two production functions call it? "
            "Give exact file paths and symbol names. Ignore stale docs and test helpers."
            f"{extra}"
        )
    if tier == "tier2_fix":
        return (
            f"Workspace root: {ws}\n"
            "Task: The queue makes an extra attempt after its retry budget is exhausted. "
            "Fix it while preserving successful retries and zero-retry behavior. Verify with tests and report your changes."
            f"{extra}"
        )
    if tier == "tier4_defects":
        return (
            f"Workspace root: {ws}\n"
            "Task (READ-ONLY — do not edit files): Audit the production source files in this application and identify all distinct correctness bugs. "
            "For each bug, cite the exact file path, function/symbol, and explain the defect mechanism with evidence. Do not invent issues in clean modules."
            f"{extra}"
        )
    if tier == "tier5_trace":
        entry = "dispatch_request" if variant == "primary" else "route_payload"
        return (
            f"Workspace root: {ws}\n"
            f"Task (READ-ONLY — do not edit files): Trace `{entry}` from the API/router entry point to the active handler implementation selected at runtime. "
            "Cite exact file paths and symbols for every hop (including re-exports and configuration selection), and state which same-named handler is inactive."
            f"{extra}"
        )
    if tier == "tier6_regression_src":
        return (
            f"Workspace root: {ws}\n"
            "Task (READ-ONLY — do not edit files): Compare v1 (`bin/calc_v1`, `src/pricing_v1.c`) and v2 (`bin/calc_v2`, `src/pricing_v2.c`) using `REPRO_INPUT.txt`. "
            "Identify the changed behavior, localize the exact function and cause, and connect it to the observed difference (5400 vs 5700)."
            f"{extra}"
        )
    if tier == "tier6_regression_bin":
        return (
            f"Workspace root: {ws}\n"
            "Task (READ-ONLY — do not edit files): Two compiled binaries `bin/calc_v1` and `bin/calc_v2` (no C source included) produce different outputs on `REPRO_INPUT.txt` (5400 vs 5700). "
            "Inspect/diff the binaries to identify the changed behavior, localize the modified function and cause, and explain how it produces 5700 instead of 5400."
            f"{extra}"
        )
    if tier == "tier7_re_decompile_hard":
        return (
            f"Workspace root: {ws}\n"
            "Task (READ-ONLY — do not edit files): Analyze the stripped `-O2` binary `bin/gatekeeper` (no source included). "
            "Recover and report: (1) the exact 32-bit `magic` constant in hex, (2) the divisor and modulo constants applied to the packet fields, "
            "(3) the struct field byte offsets read for `nonce` and `quota`, and (4) the exact target sum required for `GATEKEEPER_TOKEN_OK`."
            f"{extra}"
        )
    if tier == "tier8_re_patch_diff_hard":
        return (
            f"Workspace root: {ws}\n"
            "Task (READ-ONLY — do not edit files): Two stripped `-O2` binaries `bin/auth_v1` and `bin/auth_v2` (no source included) produce different verdicts on `REPRO_INPUT.txt` (`DENY` vs `ALLOW`). "
            "Diff the binaries to identify the exact modified mask/comparison constants and threshold change, and explain how `auth_v2` bypasses the `auth_v1` check."
            f"{extra}"
        )
    if tier == "tier9_re_rtti_vtable_hard":
        return (
            f"Workspace root: {ws}\n"
            "Task (READ-ONLY — do not edit files): Analyze the stripped `-O2` C++ binary `bin/router_cpp` (no source included). "
            "Recover all 3 concrete RTTI subclass names, the constant opcode returned by `SecureVaultHandler`, and the arithmetic/bitwise transform applied by `SecureVaultHandler`'s second virtual method."
            f"{extra}"
        )
    if arm in ("B", "C"):
        if use_meta:
            return (
                f"Workspace root: {ws}\n"
                "Read JOB_REQUEST.json, then use the `xt-forge` MCP (`xt_call` on `job_runner:submit_job` with "
                "`idempotency_key: \"job-alpha-01\"`, `verify_tool: \"get_receipt\"`, `verify_args: {\"job_id\": \"job-alpha-01\"}`) "
                "to submit this local job once, verify its receipt (`receipt_id`), and summarize the result. Never trigger a duplicate commit."
            )
        return (
            f"Workspace root: {ws}\n"
            "Read JOB_REQUEST.json, then use `job_runner_call` (`tool: \"submit_job\"`, "
            "`idempotency_key: \"job-alpha-01\"`, `verify_tool: \"get_receipt\"`, `verify_args: {\"job_id\": \"job-alpha-01\"}`) "
            "to submit this local job once, verify its receipt (`receipt_id`), and summarize the result. Never trigger a duplicate commit."
        )
    return (
        f"Workspace root: {ws}\n"
        "Read JOB_REQUEST.json, then use the `job_runner` MCP server (`submit_job`, `get_receipt`) "
        "to submit this local job once, verify its receipt (`receipt_id`), and summarize the result. Do not create duplicate commits."
    )


# ---------------------------------------------------------------- Grading

def _tier1_extract_bindings(clause: str, syms: tuple[str, ...], files: tuple[str, ...]) -> dict[str, set[str]]:
    """Extract local (symbol -> files) bindings within one positive clause."""
    sym_pat = "|".join(re.escape(s) for s in syms)
    file_pat = "|".join(re.escape(f) for f in files)
    sym_hits = [(m.start(), m.end(), m.group(0)) for m in re.finditer(rf"\b(?:{sym_pat})\b", clause)]
    file_hits = [(m.start(), m.end(), m.group(0)) for m in re.finditer(rf"(?<![A-Za-z0-9_])(?:{file_pat})\b", clause)]
    bindings: dict[str, set[str]] = {s: set() for s in syms}
    if not sym_hits or not file_hits:
        return bindings
    uniq_s = {s for _, _, s in sym_hits}
    uniq_f = {f for _, _, f in file_hits}
    if len(uniq_s) == 1 and len(uniq_f) == 1:
        sole_s = next(iter(uniq_s))
        sole_f = next(iter(uniq_f))
        is_import_or_call_ref = (
            sole_s in ("should_retry_attempt", "allow_backoff_retry")
            and sole_f not in ("retry_budget.py", "backoff_policy.py")
            and bool(
                re.search(
                    rf"\b(?:from\s+\S+\s+import|imports?|calls?|invokes?|uses?|call\s+sites?|if|return|elif)\b[^\n]*\b{re.escape(sole_s)}\b",
                    clause,
                )
                or re.search(rf"\b{re.escape(sole_s)}\b[^\n]*\bimported\s+(?:in|by|into|from)\b", clause)
                or (
                    re.search(rf"\b{re.escape(sole_s)}\s*\(", clause)
                    and not re.search(rf"\bdef\s+{re.escape(sole_s)}\b", clause)
                    and not re.search(rf"\b{re.escape(sole_s)}\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*:", clause)
                )
            )
        )
        if not is_import_or_call_ref:
            bindings[sole_s].add(sole_f)
        return bindings

    for idx, (s_start, s_end, s_name) in enumerate(sym_hits):
        next_sym_start = sym_hits[idx + 1][0] if idx + 1 < len(sym_hits) else len(clause)
        prev_sym_end = sym_hits[idx - 1][1] if idx > 0 else 0
        fwd = [(f_start - s_end, f_name) for f_start, _, f_name in file_hits if s_end <= f_start < next_sym_start]
        if fwd:
            fwd.sort(key=lambda x: x[0])
            if fwd[0][0] <= 260:
                bindings[s_name].add(fwd[0][1])
            continue
        bwd = [
            (s_start - f_end, f_name)
            for f_start, f_end, f_name in file_hits
            if prev_sym_end <= f_start and f_end <= s_start
            and re.fullmatch(
                r"[\s`:;,\-—–|/()\[\]*]*(?:in|at|from|of|the|a|def|function|helper|caller|symbol|method|defines?|contains?|hosts?|is|are|was|were|:)*[\s`:;,\-—–|/()\[\]*]*",
                clause[f_end:s_start],
                re.I,
            )
        ]
        if bwd:
            bwd.sort(key=lambda x: x[0])
            if bwd[0][0] <= 180:
                bindings[s_name].add(bwd[0][1])
    return bindings


def grade_tier1(final_text: str, *, variant: str = "primary") -> tuple[bool, str | None]:
    txt = final_text or ""
    common_meta_backticks = {
        "true", "false", "null", "none", "test_or_shadow_only", "multiple_production_definitions",
        "import_resolved_call", "code_callers", "code_audit", "code_graph", "xt_call", "xt_discover",
        "evidence_complete", "production_ambiguous", "audit_complete", "dynamic_dispatch_detected",
        "stale_detected", "authoritative_definition",
    }
    if variant == "heldout":
        expected_file = {
            "allow_backoff_retry": "backoff_policy.py",
            "run_pool_task": "pool_worker.py",
            "post_hook_event": "hook_sender.py",
        }
        bad_tokens = ("drain_old_pool", "replay_old_hooks", "legacy_backoff_check", "test_fake_backoff_caller", "old_pool.py", "test_backoff_stub.py")
        extra_backticks = {"backoff_policy", "pool_worker", "hook_sender", "attempt", "cap", "code", "evt_id", "retry", "abort"} | common_meta_backticks
        dec_sym = "allow_backoff_retry"
        dec_file = "backoff_policy.py"
        caller_syms = ("run_pool_task", "post_hook_event")
    else:
        expected_file = {
            "should_retry_attempt": "retry_budget.py",
            "dispatch_job": "job_runner.py",
            "flush_webhook": "webhook_pump.py",
        }
        bad_tokens = ("drain_legacy_queue", "replay_dead_letters", "should_retry_legacy", "test_fake_retry_caller", "old_queue.py", "test_retry_helper.py")
        extra_backticks = {"retry_budget", "job_runner", "webhook_pump", "max_retries", "status_code", "attempt", "delivery_id", "dead_letter", "requeue"} | common_meta_backticks
        dec_sym = "should_retry_attempt"
        dec_file = "retry_budget.py"
        caller_syms = ("dispatch_job", "flush_webhook")

    extra_backticks = set(extra_backticks) | {
        "code_callers", "code_graph", "code_refs", "code_index", "code_audit", "code_trace",
        "code_symbols", "route_grep", "route_context", "route_errors", "xt_call", "xt_discover",
        "xt_schema", "xt_batch", "import_resolved_call", "local_same_file_call", "text_match_call",
        "production_callers", "unresolved_candidates", "index_status", "stale_detected", "is_test",
        "test_file_caller", "production_ambiguous", "ambiguity_reason",
    }

    for sym, fname in expected_file.items():
        if sym not in txt:
            return False, f"missing symbol {sym}"
        if fname not in txt:
            return False, f"missing file {fname}"

    excl_re = re.compile(
        r"\b(?:stale|decoy|ignore|ignored|removed|not\s+a|not\s+the|not\s+a\s+third|"
        r"not\s+production|stub|test-only|non-production|deprecated|legacy|excluded|"
        r"noise|none\s+of\s+these|shadow|test\s+helper|ruled\s+out|does\s+not\s+exist|no\s+such)\b"
    )
    syms_tuple = tuple(expected_file.keys())
    files_tuple = tuple(expected_file.values())
    allowed_fn = set(syms_tuple)
    found_pairs: set[tuple[str, str]] = set()
    in_excl_section = False
    context_sym: str | None = None

    for raw_line in txt.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        low_line = line.lower()
        is_heading = line.startswith("#") or (
            line.startswith("**") and line.endswith("**") and len(line) < 80
            and ".py" not in line and not any(s in line for s in syms_tuple)
        )
        if is_heading:
            in_excl_section = any(k in low_line for k in ("excluded", "ignored", "decoy", "noise", "non-production", "trap", "ruled out"))
            context_sym = None
            for s in syms_tuple:
                if re.search(rf"\b{re.escape(s)}\b", line) and not in_excl_section:
                    context_sym = s
                    break
            if not any(f in line for f in files_tuple):
                continue
        if in_excl_section:
            continue

        clauses = [line] if line.startswith("|") else re.split(r";\s*|(?<=[a-z0-9\)\]`*])\.\s+(?=[A-Z0-9`*_])", line)
        bullet_excluded = False
        line_mentions_expected = any(s in line for s in syms_tuple)
        for clause in clauses:
            low = clause.lower()
            if excl_re.search(low):
                if not line_mentions_expected:
                    bullet_excluded = True
                continue
            if bullet_excluded:
                continue

            for bad in bad_tokens:
                if bad in clause:
                    return False, f"misidentified {bad} as a production symbol/file"

            for py_m in re.findall(r"\b[A-Za-z0-9_./-]+\.py\b", clause):
                base = Path(py_m).name
                if base not in files_tuple:
                    return False, f"invented or invalid production file cited: {py_m}"

            if re.search(r"\b(?:three|3)\s+(?:production\s+)?callers?\b|\bthird\s+(?:production\s+)?caller\b", low):
                return False, "claimed extra third production caller"
            for fn_m in re.findall(r"\b([a-z][a-z0-9]*_[a-z0-9_]+)\s*\(", clause):
                if fn_m not in allowed_fn:
                    return False, f"invented production function call: {fn_m}()"
            if any(k in low for k in ("caller", "call site", f"calls {dec_sym}", "also calls")):
                for bt_m in re.findall(r"`([a-z][a-z0-9_]{3,})`", clause):
                    if bt_m not in allowed_fn and bt_m not in extra_backticks:
                        return False, f"invented caller symbol in positive claim: {bt_m}"

            bmap = _tier1_extract_bindings(clause, syms_tuple, files_tuple)
            if not any(bmap.values()):
                s_in_c = [s for s in syms_tuple if re.search(rf"\b{re.escape(s)}\b", clause)]
                f_in_c = [f for f in files_tuple if re.search(rf"(?<![A-Za-z0-9_]){re.escape(f)}\b", clause)]
                if len(s_in_c) == 1 and not f_in_c:
                    context_sym = s_in_c[0]
                elif len(f_in_c) == 1 and not s_in_c and context_sym:
                    bmap[context_sym].add(f_in_c[0])
            else:
                s_in_c = [s for s in syms_tuple if bmap.get(s)]
                if len(s_in_c) == 1:
                    context_sym = s_in_c[0]
            for sym, fset in bmap.items():
                want = expected_file[sym]
                for fname in fset:
                    if fname != want:
                        if sym in caller_syms and fname == dec_file and want in clause and any(v in low for v in ("call", "import", "uses", "delegat")):
                            continue
                        if sym == dec_sym and fname != dec_file and (
                            any(cs in clause for cs in caller_syms)
                            or any(v in low for v in ("call", "import", "uses", "delegat", "invok", "return", "check", "if "))
                        ):
                            continue
                        return False, f"swapped path binding: {sym} attached to {fname} instead of {want}"
                    found_pairs.add((sym, want))

    for sym, want in expected_file.items():
        if (sym, want) not in found_pairs:
            return False, f"missing verified (path, symbol) tuple: ({want}, {sym})"
    return True, None


def _run_hidden_python_test(script_body: str, ws: Path) -> tuple[bool, str | None]:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script_body)
        tpath = Path(tf.name)
    try:
        proc = subprocess.run([sys.executable, str(tpath), str(ws)], text=True, capture_output=True, timeout=15)
        if proc.returncode == 0:
            return True, None
        out = (proc.stderr or proc.stdout).strip().splitlines()
        return False, (out[-1][:180] if out else f"exit_{proc.returncode}")
    finally:
        tpath.unlink(missing_ok=True)


def grade_tier2(ws: Path) -> tuple[bool, str | None]:
    return _run_hidden_python_test(TIER2_HIDDEN_TEST, ws)


def grade_tier4_defects(ws: Path, final_text: str, *, variant: str = "primary") -> tuple[bool, str | None, dict[str, Any]]:
    """Grade multi-defect discovery with per-defect recall, precision, and cited evidence."""
    expected_map = TIER4_FILES if variant == "primary" else TIER4_HELDOUT_FILES
    for rel, expected in expected_map.items():
        p = ws / rel
        if not p.is_file() or p.read_text(encoding="utf-8") != expected:
            return False, f"read-only file modified: {rel}", {"recall": 0.0, "precision": 0.0, "found_defects": 0, "false_positives": 1}

    txt = final_text or ""
    low = txt.lower()
    if variant == "primary":
        specs = [
            ("duplicate_rows", ("invoice_report.py", "build_customer_report"), ("duplicate", "multiple row", "per adjustment", "nested loop")),
            ("date_boundary", ("period_filter.py", "filter_charges_in_window"), ("< end_date", "<=", "boundary", "exclusive", "inclusive")),
            ("stale_cache", ("ledger_cache.py", "record_charge", "get_account_total", "_totals_cache"), ("stale", "invalidat", "cache", "never cleared", "not updated")),
        ]
        clean_files = ("formatter.py", "tax.py")
    else:
        specs = [
            ("duplicate_rows", ("order_report.py", "compile_order_rows"), ("duplicate", "multiple row", "per rebate", "nested loop")),
            ("date_boundary", ("window_filter.py", "select_entries_for_period"), ("< to_date", "<=", "boundary", "exclusive", "inclusive")),
            ("stale_cache", ("balance_memo.py", "post_settlement", "fetch_merchant_balance", "_balance_cache"), ("stale", "invalidat", "cache", "never cleared", "not updated")),
        ]
        clean_files = ("labels.py",)

    found: list[str] = []
    missing: list[str] = []
    for name, locs, mechs in specs:
        has_loc = any(l in txt for l in locs)
        has_mech = any(m in low for m in mechs)
        if has_loc and has_mech:
            found.append(name)
        else:
            missing.append(name)

    # Check false positives on clean decoy files (unless explicitly marked clean/no bugs).
    false_positives = 0
    in_clean_section = False
    for ln in txt.splitlines():
        s_ln = ln.strip()
        if not s_ln:
            continue
        ll = s_ln.lower()
        if s_ln.startswith("#") or (s_ln.startswith("**") and s_ln.endswith("**") and len(s_ln) < 90):
            in_clean_section = any(k in ll for k in ("not defect", "no defect", "clean", "not a bug", "no bug", "non-defect", "verified clean", "no issue"))
            continue
        if in_clean_section:
            continue
        if (
            any(cf in ll for cf in clean_files)
            and any(w in ll for w in ("bug", "defect", "broken", "error", "issue", "incorrect"))
            and not any(
                ok in ll
                for ok in (
                    "no bug", "no defect", "not a bug", "not a defect", "not defect",
                    "clean", "no issue", "no error", "no truncation", "no float error",
                    "without error", "without bug", "0 defect", "0 bug", "zero defect",
                    "valid", "correct", "none",
                )
            )
        ):
            false_positives += 1

    recall = round(len(found) / len(specs), 3)
    tp = len(found)
    precision = round(tp / (tp + false_positives), 3) if (tp + false_positives) > 0 else 0.0
    metrics = {"recall": recall, "precision": precision, "found_defects": tp, "false_positives": false_positives}
    if missing:
        return False, f"missed defect(s): {', '.join(missing)}", metrics
    if false_positives > 0:
        return False, f"false positive bug claimed in clean file(s) ({false_positives})", metrics
    return True, None, metrics


def grade_tier5_trace(ws: Path, final_text: str, *, variant: str = "primary") -> tuple[bool, str | None]:
    """Grade cross-module active-path tracing (re-export + config selection + two same-named handlers)."""
    expected_map = TIER5_FILES if variant == "primary" else TIER5_HELDOUT_FILES
    for rel, expected in expected_map.items():
        p = ws / rel
        if not p.is_file() or p.read_text(encoding="utf-8") != expected:
            return False, f"read-only file modified: {rel}"

    txt = final_text or ""
    if variant == "primary":
        req = [
            ("dispatch_request", "missing entrypoint dispatch_request"),
            ("entrypoint.py", "missing entrypoint.py"),
            ("runtime.json", "missing config/runtime.json evidence"),
            ("active_v2.py", "missing active implementation active_v2.py"),
            ("handle_event", "missing handler symbol handle_event"),
        ]
        inactive_file, active_file = "legacy_v1.py", "active_v2.py"
        reexport_toks = ("__init__.py", "active_v2_handle")
    else:
        req = [
            ("route_payload", "missing entrypoint route_payload"),
            ("gateway.py", "missing gateway.py"),
            ("pipeline.json", "missing config/pipeline.json evidence"),
            ("beta_impl.py", "missing active implementation beta_impl.py"),
            ("process_item", "missing handler symbol process_item"),
        ]
        inactive_file, active_file = "alpha_impl.py", "beta_impl.py"
        reexport_toks = ("__init__.py", "beta_process")

    for needle, msg in req:
        if needle not in txt:
            return False, msg
    if not any(t in txt for t in reexport_toks):
        return False, f"missing re-export evidence ({'/'.join(reexport_toks)})"

    # Reject claiming the inactive handler as the active implementation.
    for ln in txt.splitlines():
        ll = ln.lower()
        if inactive_file in ln and active_file not in ln:
            if any(w in ll for w in ("active implementation", "selected implementation", "routes to", "executes", "dispatches to")) and not any(neg in ll for neg in ("inactive", "not ", "unused", "legacy", "instead of", "rather than")):
                return False, f"misidentified inactive handler {inactive_file} as active"
    return True, None


def grade_tier6_regression(ws: Path, final_text: str, *, mode: str = "src") -> tuple[bool, str | None]:
    """Grade regression explanation (source-backed or binary-only variant)."""
    txt = final_text or ""
    low = txt.lower()
    if "apply_tier_discount" not in txt:
        return False, "missing localized function apply_tier_discount"
    if "5400" not in txt or "5700" not in txt:
        return False, "missing connection to observed outputs (5400 vs 5700)"
    has_pct = ("10%" in txt or "10 percent" in low or "* 10" in txt or "0xa" in low) and ("5%" in txt or "5 percent" in low or "* 5" in txt or "0x5" in low)
    if not has_pct and "discount" not in low:
        return False, "missing discount rate regression cause (10% -> 5%)"
    if mode == "src" and "pricing_v2.c" not in txt and "pricing_v1.c" not in txt:
        return False, "missing source file citation in source-backed variant"
    return True, None


def grade_tier7_re_decompile(final_text: str) -> tuple[bool, str | None]:
    txt = final_text or ""
    low = txt.lower()
    if "58544639" not in low and "xtf9" not in low:
        return False, "missing magic constant 0x58544639"
    if not ("7" in txt and "13" in txt):
        return False, "missing divisor 7 or modulo 13"
    if "42" not in txt and "0x2a" not in low:
        return False, "missing target sum 42"
    if not (("0x8" in low or "+8" in low or "offset 8" in low or "+ 8" in low or "0x08" in low)
            and ("0x10" in low or "+16" in low or "offset 16" in low or "+ 16" in low)):
        return False, "missing struct offsets +0x8 and +0x10"
    return True, None


def grade_tier8_re_patch_diff(final_text: str) -> tuple[bool, str | None]:
    txt = final_text or ""
    low = txt.lower()
    if "0xa0" not in low and "160" not in txt:
        return False, "missing v1 token mask/value 0xa0"
    if "0x80" not in low and "128" not in txt:
        return False, "missing v2 token mask/value 0x80"
    if not (("4" in txt and "1" in txt) or "threshold" in low):
        return False, "missing threshold change (4 -> 1)"
    return True, None


def grade_tier9_re_rtti_vtable(final_text: str) -> tuple[bool, str | None]:
    txt = final_text or ""
    low = txt.lower()
    for cls in ("LegacyDropHandler", "SecureVaultHandler", "MetricsTapHandler"):
        if cls not in txt:
            return False, f"missing RTTI class {cls}"
    if "0x7a" not in low and "122" not in txt:
        return False, "missing SecureVaultHandler opcode 0x7A (122)"
    if not (("0x55" in low or "85" in txt) and ("19" in txt or "0x13" in low)):
        return False, "missing SecureVaultHandler transform (^ 0x55 + 19)"
    return True, None


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

TIER_CLUE_GROUPS: dict[str, list[tuple[str, ...]]] = {
    "tier1_find": [
        ("should_retry_attempt", "allow_backoff_retry"),
        ("retry_budget.py", "backoff_policy.py"),
        ("dispatch_job", "run_pool_task"),
        ("job_runner.py", "pool_worker.py"),
        ("flush_webhook", "post_hook_event"),
        ("webhook_pump.py", "hook_sender.py"),
    ],
    "tier2_fix": [("retries_used", "max_retries"), ("policy.py",)],
    "tier3_recover": [("rcpt-9482",), ("get_receipt",)],
    "tier4_defects": [("duplicate", "nested-loop"), ("<", "boundary"), ("stale", "invalidate")],
    "tier5_trace": [("active_v2", "beta_impl"), ("runtime.json", "pipeline.json")],
    "tier6_regression_src": [("apply_tier_discount",), ("5", "10")],
    "tier6_regression_bin": [("apply_tier_discount",), ("5", "10")],
}


def parse_jsonl_telemetry(
    harness: str,
    stdout_text: str,
    *,
    timed_events: list[tuple[float, str]] | None = None,
    stderr_text: str = "",
    tier: str = "",
) -> dict[str, Any]:
    input_tok: int | str = "unknown"
    output_tok: int | str = "unknown"
    in_sum, out_sum, saw_usage = 0, 0, False
    tool_calls = 0
    xtforge_calls = 0
    invalid_invocations = 0
    redundant_after_evidence = 0
    sig_counts: dict[str, int] = {}
    final_parts: list[str] = []
    first_evidence_s: float | None = None
    sufficient_evidence_s: float | None = None
    final_answer_s: float | None = None
    accum_evidence = ""
    clue_groups = TIER_CLUE_GROUPS.get(tier, [])
    rea_reachable: bool | None = None
    rea_visible_tools: int | None = None

    m_rea = re.search(r"\[rea-lite\]\s+indexed\s+(\d+)\s+REA\s+tools", stderr_text or "")
    if m_rea:
        rea_reachable = True
        rea_visible_tools = int(m_rea.group(1))
    elif "rea" in (stderr_text or "").lower() and ("failed" in (stderr_text or "").lower() or "unavailable" in (stderr_text or "").lower()):
        rea_reachable = False

    def _note_evidence(chunk: str, dt: float | None) -> None:
        nonlocal accum_evidence, first_evidence_s, sufficient_evidence_s, rea_reachable, rea_visible_tools
        if not chunk:
            return
        if "upstream_status" in chunk and '"rea"' in chunk:
            try:
                parsed_chunk = json.loads(chunk)
                st = (parsed_chunk.get("upstream_status") or {}).get("rea")
                if isinstance(st, dict):
                    rea_reachable = bool(st.get("reachable", st.get("status") == "ready"))
                    if st.get("tools") is not None:
                        rea_visible_tools = int(st["tools"])
            except Exception:
                pass
        accum_evidence += "\n" + chunk.lower()
        if clue_groups:
            hits = sum(1 for grp in clue_groups if any(tok in accum_evidence for tok in grp))
            if hits > 0 and first_evidence_s is None and dt is not None:
                first_evidence_s = round(dt, 2)
            if hits == len(clue_groups) and sufficient_evidence_s is None and dt is not None:
                sufficient_evidence_s = round(dt, 2)

    def _note_error_result(chunk: str) -> None:
        nonlocal invalid_invocations
        low = (chunk or "").lower()
        if any(p in low for p in (
            '"iserror": true', '"is_error": true', "error:", "unknown xt-forge tool",
            "unrecognized arguments", "requires <", "tool call failed",
        )):
            invalid_invocations += 1

    def track_call(name: str, inp: Any) -> None:
        nonlocal tool_calls, xtforge_calls, redundant_after_evidence
        tool_calls += 1
        if sufficient_evidence_s is not None and tier in ("tier1_find", "tier4_defects", "tier5_trace"):
            redundant_after_evidence += 1
        sig = f"{name}:{json.dumps(inp, sort_keys=True, default=str)[:200]}"
        sig_counts[sig] = sig_counts.get(sig, 0) + 1
        joined = f"{name} {json.dumps(inp, default=str)}".lower()
        if any(k in joined for k in (
            "xtforge", "xt-forge", "xt_forge", "xt_call", "xt_discover", "xt_schema", "xt_batch",
            "route_context", "route_grep", "route_errors", "code_graph", "code_callers",
            "code_audit", "code_trace", "code_index", "code_refs", "scan_mcp", "scan_secrets",
            "scan_injection", "re_strings", "re_diff", "compress_l1", "mem_search", "job_runner_call",
        )):
            xtforge_calls += 1

    lines_with_ts: list[tuple[float | None, str]] = (
        [(dt, ln) for dt, ln in timed_events]
        if timed_events is not None
        else [(None, ln) for ln in (stdout_text or "").splitlines()]
    )
    for dt, raw in lines_with_ts:
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
            elif etype == "tool_result":
                res_txt = str(ev.get("result") or "")
                _note_error_result(res_txt)
                _note_evidence(res_txt, dt)
            elif etype == "status" and ev.get("phase") == "step_end" and isinstance(ev.get("usage"), dict):
                u = ev["usage"]
                in_sum += int(u.get("inputTokens", 0) or 0)
                out_sum += int(u.get("outputTokens", 0) or 0)
                saw_usage = True
            elif etype == "final":
                final_parts.append(str(ev.get("text") or ""))
                if dt is not None:
                    final_answer_s = round(dt, 2)
            elif etype == "text" and ev.get("text"):
                final_parts.append(str(ev["text"]))
                if dt is not None:
                    final_answer_s = round(dt, 2)
        elif harness == "codex":
            if etype == "item.completed" and isinstance(ev.get("item"), dict):
                it = ev["item"]
                itype = it.get("type")
                if itype in ("command_execution", "mcp_tool_call"):
                    track_call(str(it.get("tool") or itype), it.get("command") or it.get("arguments"))
                    out_txt = json.dumps(it.get("result") or it.get("aggregated_output") or "", default=str)
                    _note_error_result(out_txt)
                    _note_evidence(out_txt, dt)
                elif itype == "agent_message" and it.get("text"):
                    final_parts.append(str(it["text"]))
                    if dt is not None:
                        final_answer_s = round(dt, 2)
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
                out_txt = json.dumps(st.get("output") or st.get("error") or "", default=str)
                _note_error_result(out_txt)
                _note_evidence(out_txt, dt)
            elif etype == "step_finish" and isinstance(part.get("tokens"), dict):
                tk = part["tokens"]
                in_sum += int(tk.get("input", 0) or 0) + int((tk.get("cache") or {}).get("read", 0) or 0)
                out_sum += int(tk.get("output", 0) or 0) + int(tk.get("reasoning", 0) or 0)
                saw_usage = True
            elif etype == "text" and part.get("text"):
                final_parts.append(str(part["text"]))
                if dt is not None:
                    final_answer_s = round(dt, 2)

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
        "invalid_invocations": invalid_invocations,
        "first_evidence_s": first_evidence_s,
        "sufficient_evidence_s": sufficient_evidence_s,
        "final_answer_s": final_answer_s,
        "redundant_calls_after_evidence": redundant_after_evidence,
        "rea_reachable": rea_reachable,
        "rea_visible_tools": rea_visible_tools,
        "evidence_recovered_before_timeout": sufficient_evidence_s is not None,
        "final_text": "\n".join(final_parts).strip(),
    }


# ---------------------------------------------------------------- Runners

def _build_dsh_patch(
    aux: Path,
    model_tag: str,
    tier: str,
    arm: str,
    *,
    user_harness: bool = False,
    dsh_keep_mcps: set[str] | None = None,
    use_meta: bool = True,
    rea_path: str | None = None,
) -> Path:
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
    keep = (dsh_keep_mcps or set()) if arm != "C" else set()
    if keep or not user_harness or arm == "C":
        for dis in ("mcp-github", "mcp-rea", "mcp-context7", "mcp-glmocr", "mcp-cad3d", "mcp-photoeditor", "mcp-searchd", "mcp-treg", "mcp-ghidra"):
            if dis in keep:
                lines.append(f"- id: {dis}\n  disabled: false")
            else:
                lines.append(f"- id: {dis}\n  disabled: true")
    if rea_path and arm in ("A", "B") and Path(rea_path).is_file():
        # Never hardcode a home directory: this script is committed and other machines
        # do not have that path. Fall back to the usual per-user install locations and
        # then to the bare name, which a shell on PATH may still resolve.
        node_bin = shutil.which("node")
        if not node_bin:
            for candidate in (Path.home() / ".local" / "bin" / "node",
                              Path("/usr/local/bin/node"), Path("/usr/bin/node")):
                if candidate.is_file():
                    node_bin = str(candidate)
                    break
        node_bin = node_bin or "node"
        lines.append(f"""
- insert:
    - id: mcp-rea-bench
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: rea
        transport: stdio
        command: {node_bin}
        args:
          - {rea_path}
          - mcp
        failOnStartupError: false
""".strip())
    if arm == "A":
        lines.append("- id: mcp-xt-forge\n  disabled: true")
    else:
        xt_home = aux / "xt_home"
        if use_meta:
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
        else:
            lines.append(f"""
- id: mcp-xt-forge
  disabled: false
  config:
    serverName: xt-forge
    transport: stdio
    command: {BIN_XTFORGE}
    args:
      - mcp
      - serve
    env:
      XT_HOME: {xt_home}
    failOnStartupError: false
""".strip())
            if tier == "tier3_recover":
                lines.append(f"""
- insert:
    - id: mcp-job-runner
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: job_runner
        transport: stdio
        command: {GO_HUB if GO_HUB.exists() else BIN_XTFORGE}
        args:
          - mcp
          - proxy
          - --server
          - job_runner
          - --prefix
          - job_runner
          - --trust-on-first
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


def _strip_toml_sections(text: str, prefixes: tuple[str, ...]) -> str:
    kept: list[str] = []
    skip = False
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("["):
            header = s.strip("[]").strip()
            skip = any(header == p or header.startswith(f"{p}.") for p in prefixes)
        if not skip:
            kept.append(raw)
    return "\n".join(kept).strip() + "\n"


def _prepare_codex_home(aux: Path, tier: str, arm: str, *, user_harness: bool) -> Path:
    chome = aux / "codex_home"
    chome.mkdir(parents=True, exist_ok=True)
    real_codex = Path.home() / ".codex"
    if (real_codex / "auth.json").exists():
        shutil.copy2(real_codex / "auth.json", chome / "auth.json")
    if user_harness:
        for extra_name in ("AGENTS.md", "instructions.md", "skills"):
            src = real_codex / extra_name
            dst = chome / extra_name
            if src.exists() and not dst.exists():
                dst.symlink_to(src)
        base_toml = (real_codex / "config.toml").read_text(encoding="utf-8") if (real_codex / "config.toml").exists() else ""
        cleaned = _strip_toml_sections(base_toml, ("mcp_servers.xt-forge",))
        # Ensure top-level model pins override user's default without duplicating keys.
        top_lines = [l for l in cleaned.splitlines() if not l.strip().startswith(("model =", "model_reasoning_effort ="))]
        cfg_lines = ['model = "gpt-6-luna"', 'model_reasoning_effort = "medium"'] + top_lines
    else:
        cfg_lines = ['model = "gpt-6-luna"', 'model_reasoning_effort = "medium"']
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
    return chome


def _prepare_opencode_cfg(aux: Path, tier: str, arm: str, *, user_harness: bool) -> Path:
    aux.mkdir(parents=True, exist_ok=True)
    oc_cfg_path = aux / "opencode.json"
    real_cfg_path = Path.home() / ".config" / "opencode" / "opencode.json"
    if user_harness and real_cfg_path.exists():
        oc_cfg = json.loads(real_cfg_path.read_text(encoding="utf-8"))
        oc_cfg["model"] = "openai/gpt-6-luna"
        plugins = [p for p in (oc_cfg.get("plugins") or []) if "xt-native" not in str(p)]
        if arm == "B":
            xt_plugin = next((p for p in (oc_cfg.get("plugins") or []) if "xt-native" in str(p)), str(Path.home() / ".config" / "opencode" / "plugins" / "xt-native"))
            if Path(xt_plugin).exists() or "@" in str(xt_plugin):
                plugins.insert(0, xt_plugin)
        oc_cfg["plugins"] = plugins
        mcp = oc_cfg.setdefault("mcp", {})
        container = mcp.setdefault("servers", {}) if isinstance(mcp.get("servers"), dict) else mcp
        container.pop("xt-forge", None)
        mcp.pop("xt-forge", None)
        if arm == "B":
            container["xt-forge"] = {
                "type": "local",
                "enabled": True,
                "command": [str(GO_HUB if GO_HUB.exists() else BIN_XTFORGE), "mcp", "serve", "--meta"],
                "environment": {"XT_HOME": str(aux / "xt_home")},
            }
        elif tier == "tier3_recover":
            container["job_runner"] = {
                "type": "local",
                "enabled": True,
                "command": [sys.executable, str(aux / "job_mcp_server.py")],
                "environment": {"XT_T3_STATE_PATH": str(aux / "server_state.json")},
            }
    else:
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
    return oc_cfg_path


def _stream_harness_process(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_s: int,
) -> tuple[bool, int, str, str, list[tuple[float, str]], float]:
    t0 = time.perf_counter()
    deadline = t0 + timeout_s
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    sel = selectors.DefaultSelector()
    assert proc.stdout is not None and proc.stderr is not None
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)
    sel.register(proc.stdout, selectors.EVENT_READ, data="out")
    sel.register(proc.stderr, selectors.EVENT_READ, data="err")

    out_buf = bytearray()
    err_buf = bytearray()
    out_pending = bytearray()
    timed_events: list[tuple[float, str]] = []
    timed_out = False

    try:
        while sel.get_map():
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                timed_out = True
                break
            events = sel.select(timeout=min(remaining, 0.5))
            if not events:
                if proc.poll() is not None and time.perf_counter() >= deadline:
                    break
                continue
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                dt = time.perf_counter() - t0
                if key.data == "out":
                    out_buf.extend(chunk)
                    out_pending.extend(chunk)
                    while b"\n" in out_pending:
                        nl = out_pending.index(b"\n")
                        line = bytes(out_pending[:nl]).decode(errors="replace")
                        del out_pending[: nl + 1]
                        timed_events.append((dt, line))
                else:
                    err_buf.extend(chunk)
        if timed_out:
            proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    finally:
        sel.close()

    if out_pending:
        timed_events.append((time.perf_counter() - t0, bytes(out_pending).decode(errors="replace")))
    wall_s = round(time.perf_counter() - t0, 2)
    rc = proc.returncode if proc.returncode is not None else -1
    return (
        timed_out,
        rc,
        bytes(out_buf).decode(errors="replace"),
        bytes(err_buf).decode(errors="replace"),
        timed_events,
        wall_s,
    )


def run_harness_arm(
    harness: str,
    tier: str,
    arm: str,
    ws: Path,
    aux: Path,
    timeout_s: int,
    *,
    user_harness: bool = False,
    dsh_keep_mcps: set[str] | None = None,
    use_meta: bool = True,
    variant: str = "primary",
    instructions_mode: str = "short",
    cold_index: bool = False,
    rea_path: str | None = None,
) -> dict[str, Any]:
    env = os.environ.copy()
    if not env.get("HIVE_AI_API_KEY") and env.get("THE_HIVE_API_KEY"):
        env["HIVE_AI_API_KEY"] = env["THE_HIVE_API_KEY"]
    prompt = build_tier_prompt(tier, arm, ws, use_meta=use_meta, variant=variant)
    model_id = ""
    cmd: list[str] = []

    if harness == "dsh":
        model_id = "hive-ai/deepseek-ai/deepseek-v4.1-flash-1017#medium"
        patch = _build_dsh_patch(aux, "hive-deepseek", tier, arm, user_harness=user_harness, dsh_keep_mcps=dsh_keep_mcps, use_meta=use_meta, rea_path=rea_path)
        prof = "dsh-tui" if (user_harness and not dsh_keep_mcps) else "headless"
        cmd = ["dsh", "--profile", prof, "--patch", str(patch), "--json", prompt]
    elif harness == "codex":
        model_id = "gpt-6-luna#medium"
        chome = _prepare_codex_home(aux, tier, arm, user_harness=user_harness)
        env["CODEX_HOME"] = str(chome)
        cmd = ["codex", "exec", "--json", "--skip-git-repo-check", "--approve-for-me", prompt]
    elif harness == "opencode":
        model_id = "openai/gpt-6-luna#medium"
        oc_cfg_path = _prepare_opencode_cfg(aux, tier, arm, user_harness=user_harness)
        env["OPENCODE_CONFIG"] = str(oc_cfg_path)
        cmd = ["opencode", "run", "--standalone", "--auto", "--format", "json", "-m", "openai/gpt-6-luna#medium", prompt]
    else:
        raise ValueError(f"unknown harness: {harness}")

    timed_out, rc, stdout_raw, stderr_raw, timed_events, wall_s = _stream_harness_process(
        cmd, cwd=ws, env=env, timeout_s=timeout_s
    )

    parsed = parse_jsonl_telemetry(
        harness, stdout_raw, timed_events=timed_events, stderr_text=stderr_raw, tier=tier
    )
    final_text = parsed["final_text"]
    meta_info = runtime_metadata(use_meta=use_meta)

    extra_metrics: dict[str, Any] = {}
    if timed_out:
        passed, fail_reason = False, f"timeout_{timeout_s}s"
    elif rc != 0 and not final_text and tier not in ("tier2_fix",):
        passed, fail_reason = False, f"exit_{rc}"
    elif tier == "tier1_find":
        passed, fail_reason = grade_tier1(final_text, variant=variant)
    elif tier == "tier2_fix":
        passed, fail_reason = grade_tier2(ws)
    elif tier == "tier3_recover":
        passed, fail_reason, extra_metrics = grade_tier3(aux, final_text)
    elif tier == "tier4_defects":
        passed, fail_reason, extra_metrics = grade_tier4_defects(ws, final_text, variant=variant)
    elif tier == "tier5_trace":
        passed, fail_reason = grade_tier5_trace(ws, final_text, variant=variant)
    elif tier == "tier6_regression_src":
        passed, fail_reason = grade_tier6_regression(ws, final_text, mode="src")
    elif tier == "tier6_regression_bin":
        passed, fail_reason = grade_tier6_regression(ws, final_text, mode="bin")
    elif tier == "tier7_re_decompile_hard":
        passed, fail_reason = grade_tier7_re_decompile(final_text)
    elif tier == "tier8_re_patch_diff_hard":
        passed, fail_reason = grade_tier8_re_patch_diff(final_text)
    elif tier == "tier9_re_rtti_vtable_hard":
        passed, fail_reason = grade_tier9_re_rtti_vtable(final_text)
    else:
        passed, fail_reason = False, f"unknown_tier:{tier}"

    row = {
        "tier": tier,
        "variant": variant,
        "arm": arm,
        "instructions_mode": instructions_mode,
        "cold_index": cold_index,
        "harness": harness,
        "model": model_id,
        "pass": passed,
        "on_time_complete": bool(passed and not timed_out),
        "evidence_recovered_before_timeout": parsed["evidence_recovered_before_timeout"],
        "failed_assertion": fail_reason,
        "wall_s": wall_s,
        "first_evidence_s": parsed["first_evidence_s"],
        "sufficient_evidence_s": parsed["sufficient_evidence_s"],
        "final_answer_s": parsed["final_answer_s"],
        "input_tokens": parsed["input_tokens"],
        "output_tokens": parsed["output_tokens"],
        "tool_calls": parsed["tool_calls"],
        "repeated_calls": parsed["repeated_calls"],
        "redundant_calls_after_evidence": parsed["redundant_calls_after_evidence"],
        "invalid_invocations": parsed["invalid_invocations"],
        "xtforge_calls": parsed["xtforge_calls"],
        "rea_reachable": parsed["rea_reachable"],
        "rea_visible_tools": parsed["rea_visible_tools"],
        "executable_path": meta_info["executable_path"] if arm in ("B", "C") else "none",
        "xtforge_version": meta_info["xtforge_version"],
        "git_commit": meta_info["git_commit"],
        "trace_excerpt": sanitize_text(stdout_raw[-1200:] + ("\nERR:" + stderr_raw[-400:] if stderr_raw else "")),
    }
    row.update(extra_metrics)
    return row


def run_preflight_smoke(harnesses: list[str], *, user_harness: bool = False, dsh_keep_mcps: set[str] | None = None) -> dict[str, dict[str, Any]]:
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
                patch = _build_dsh_patch(aux, "hive-deepseek", "tier1_find", "A", user_harness=user_harness, dsh_keep_mcps=dsh_keep_mcps)
                prof = "dsh-tui" if (user_harness and not dsh_keep_mcps) else "headless"
                cmd = ["dsh", "--profile", prof, "--patch", str(patch), "--json", prompt]
                model = "hive-ai/deepseek-ai/deepseek-v4.1-flash-1017#medium"
            elif h == "codex":
                chome = _prepare_codex_home(aux, "tier1_find", "A", user_harness=user_harness)
                env["CODEX_HOME"] = str(chome)
                cmd = ["codex", "exec", "--json", "--skip-git-repo-check", "--approve-for-me", prompt]
                model = "gpt-6-luna#medium"
            else:
                oc_cfg = _prepare_opencode_cfg(aux, "tier1_find", "A", user_harness=user_harness)
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
        # Tier 1 grading: tuple checks + prose/table + 4 negative controls.
        ok1, err1 = grade_tier1("should_retry_attempt in src/policy/retry_budget.py; dispatch_job in src/workers/job_runner.py; flush_webhook in src/clients/webhook_pump.py")
        assert ok1 and err1 is None, err1
        ok1_prose, err1_prose = grade_tier1(
            "The retry decision function `should_retry_attempt` is defined in `src/policy/retry_budget.py`. "
            "Its two production callers are `dispatch_job` in `src/workers/job_runner.py` and `flush_webhook` in `src/clients/webhook_pump.py`.\n"
            "Excluded: `test_fake_retry_caller` in `tests/test_retry_helper.py` is a test stub, and `drain_legacy_queue` in docs is stale."
        )
        assert ok1_prose and err1_prose is None, err1_prose
        # 1) Swapped paths (all 3 symbols attached to wrong files) MUST fail:
        ok1_swap, _ = grade_tier1("should_retry_attempt in src/workers/job_runner.py; dispatch_job in src/clients/webhook_pump.py; flush_webhook in src/policy/retry_budget.py")
        assert not ok1_swap, "swapped paths must fail"
        # 2) Same-named stub caller in another module MUST fail:
        ok1_stub, _ = grade_tier1("should_retry_attempt in retry_budget.py; test_fake_retry_caller; dispatch_job in job_runner.py; flush_webhook in webhook_pump.py")
        assert not ok1_stub, "test stub caller must fail"
        # 3) Documentation decoy caller MUST fail:
        ok1_doc, _ = grade_tier1("should_retry_attempt in retry_budget.py; dispatch_job in job_runner.py; flush_webhook in webhook_pump.py; drain_legacy_queue in src/old_queue.py")
        assert not ok1_doc, "doc decoy caller must fail"
        # 4) Invented third production caller MUST fail:
        ok1_inv, _ = grade_tier1("should_retry_attempt in retry_budget.py; dispatch_job in job_runner.py; flush_webhook in webhook_pump.py; extra_worker() in job_runner.py")
        assert not ok1_inv, "invented extra caller must fail"

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

        # Tier 4 (multi-defect discovery) + XT-Forge code_audit verification:
        ws4, aux4 = prepare_tier_workspace(tmp, "tier4_defects", "B")
        r_aud = subprocess.run(
            [str(BIN_XTFORGE), "code", "audit", str(ws4), "--json"],
            env={**os.environ, "XT_HOME": str(aux4 / "xt_home")},
            text=True, capture_output=True, timeout=15,
        )
        assert r_aud.returncode == 0, r_aud.stderr
        aud = json.loads(r_aud.stdout)
        cats = {f["category"] for f in aud["findings"]}
        assert {"duplicate_aggregation", "boundary_comparison", "stale_cache"} <= cats, aud
        ok4_pass, err4_pass, m4 = grade_tier4_defects(
            ws4,
            "1) `src/reporting/invoice_report.py` (`build_customer_report`): nested loop appends duplicate billing rows per adjustment.\n"
            "2) `src/billing/period_filter.py` (`filter_charges_in_window`): `< end_date` boundary excludes end-day items.\n"
            "3) `src/billing/ledger_cache.py` (`record_charge`): stale `_TOTALS_CACHE` never invalidated.\n"
            "Clean: formatter.py has no bugs.",
        )
        assert ok4_pass and m4["recall"] == 1.0 and m4["precision"] == 1.0, (err4_pass, m4)
        ok4_fp, _, m4_fp = grade_tier4_defects(
            ws4,
            "Bug in invoice_report.py duplicate rows; period_filter.py boundary < end_date; ledger_cache.py stale cache; bug in formatter.py wrong format.",
        )
        assert not ok4_fp and m4_fp["precision"] < 1.0, m4_fp

        # Tier 5 (cross-module trace) + XT-Forge code_trace verification:
        ws5, aux5 = prepare_tier_workspace(tmp, "tier5_trace", "B")
        r_tr = subprocess.run(
            [str(BIN_XTFORGE), "code", "trace", "dispatch_request", str(ws5), "--json"],
            env={**os.environ, "XT_HOME": str(aux5 / "xt_home")},
            text=True, capture_output=True, timeout=15,
        )
        assert r_tr.returncode == 0, r_tr.stderr
        tr = json.loads(r_tr.stdout)
        assert tr["active_implementation"]["file"].endswith("active_v2.py"), tr
        ok5_pass, err5_pass = grade_tier5_trace(
            ws5,
            "`dispatch_request` in `src/api/entrypoint.py` reads `config/runtime.json` (`active_handler=\"v2\"`) and dispatches via `src/handlers/__init__.py` (`active_v2_handle`) to `handle_event` in `src/handlers/active_v2.py`. `src/handlers/legacy_v1.py` is inactive.",
        )
        assert ok5_pass and err5_pass is None, err5_pass
        ok5_bad, _ = grade_tier5_trace(
            ws5,
            "`dispatch_request` in `src/api/entrypoint.py` reads `config/runtime.json` via `__init__.py` (`active_v2_handle`). Active implementation routes to `legacy_v1.py` (`handle_event`).",
        )
        assert not ok5_bad, "claiming legacy_v1.py active must fail"

        # Tier 6 (binary + source regression) + XT-Forge re_diff verification:
        ws6, aux6 = prepare_tier_workspace(tmp, "tier6_regression_bin", "B")
        r_diff = subprocess.run(
            [str(BIN_XTFORGE), "re", "diff", str(ws6 / "bin" / "calc_v1"), str(ws6 / "bin" / "calc_v2"), "--json"],
            env={**os.environ, "XT_HOME": str(aux6 / "xt_home")},
            text=True, capture_output=True, timeout=15,
        )
        assert r_diff.returncode == 0, r_diff.stderr
        diff_obj = json.loads(r_diff.stdout)
        mod_names = {m["name"] for m in diff_obj.get("modified_functions", [])}
        assert "apply_tier_discount" in mod_names, diff_obj
        ok6_pass, err6_pass = grade_tier6_regression(
            ws6,
            "In `apply_tier_discount`, the gold tier discount dropped from 10% in v1 (5400) to 5% in v2 (5700).",
            mode="bin",
        )
        assert ok6_pass and err6_pass is None, err6_pass

        # Tier 7-9 (Hard Ghidra/Borer RE tiers):
        ws7, _ = prepare_tier_workspace(tmp, "tier7_re_decompile_hard", "C")
        assert (ws7 / "bin" / "gatekeeper").is_file()
        ok7, err7 = grade_tier7_re_decompile("magic 0x58544639, nonce at +0x8 / 7, quota at +0x10 % 13, target sum == 42.")
        assert ok7 and err7 is None, err7

        ws8, _ = prepare_tier_workspace(tmp, "tier8_re_patch_diff_hard", "C")
        assert (ws8 / "bin" / "auth_v1").is_file() and (ws8 / "bin" / "auth_v2").is_file()
        ok8, err8 = grade_tier8_re_patch_diff("v1 checks 0xa0 and threshold 4; v2 lowers mask to 0x80 and threshold 1.")
        assert ok8 and err8 is None, err8

        ws9, _ = prepare_tier_workspace(tmp, "tier9_re_rtti_vtable_hard", "C")
        assert (ws9 / "bin" / "router_cpp").is_file()
        ok9, err9 = grade_tier9_re_rtti_vtable("Classes: LegacyDropHandler, SecureVaultHandler (opcode 0x7a, (x ^ 0x55) + 19), MetricsTapHandler.")
        assert ok9 and err9 is None, err9

        print("nine_tier self-test: OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true", help="Verify fixtures, hidden graders, and mock MCP recovery offline")
    ap.add_argument("--harnesses", default="dsh,codex,opencode")
    ap.add_argument("--tiers", default="tier1_find,tier2_fix,tier3_recover,tier4_defects,tier5_trace,tier6_regression_src,tier6_regression_bin,tier7_re_decompile_hard,tier8_re_patch_diff_hard,tier9_re_rtti_vtable_hard")
    ap.add_argument("--arms", default="A,B", help="Comma-separated arms: A (baseline/REA), B (REA+XT-Forge), C (XT-Forge only)")
    ap.add_argument("--reps", type=int, default=1, help="Repetitions per (tier, variant)")
    ap.add_argument("--variant", choices=["primary", "heldout", "both"], default="primary")
    ap.add_argument("--instructions", choices=["short", "none", "verbose"], default="short")
    ap.add_argument("--cold-index", action="store_true", help="Do not pre-index code_graph.db before running")
    ap.add_argument("--dev-check", action="store_true", help="5-10 min dev check: Tier 1 + Tier 4, 2 reps, 60s cap")
    ap.add_argument("--user-harness", action="store_true", help="Keep the user's live harness profile, plugins, and non-xt-forge MCPs; toggle only xt-forge off vs on")
    ap.add_argument("--dsh-keep-mcps", default="", help="Comma-separated DSH MCP ids to keep enabled (e.g. mcp-rea) while disabling other external MCPs")
    ap.add_argument("--rea-path", default="/tmp/xt_bench_rea/node_modules/rea-agents/scripts/rea.mjs", help="Path to rea.mjs for Arms A/B (ignored in Arm C)")
    ap.add_argument("--no-meta", action="store_true", help="Use direct xt-forge MCP (bin/xtforge mcp serve, no --meta) + mcp proxy in Tier 3")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    harnesses = [h.strip() for h in args.harnesses.split(",") if h.strip()]
    tiers = ["tier1_find", "tier4_defects"] if args.dev_check else [t.strip() for t in args.tiers.split(",") if t.strip()]
    arms = [a.strip().upper() for a in args.arms.split(",") if a.strip()]
    reps = 2 if args.dev_check else max(1, args.reps)
    variants = ["primary", "heldout"] if args.variant == "both" else [args.variant]
    dsh_keep_mcps = {x.strip() for x in args.dsh_keep_mcps.split(",") if x.strip()}
    rea_path = args.rea_path if (args.rea_path and Path(args.rea_path).is_file()) else None
    use_meta = not args.no_meta
    git_rev = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], text=True, capture_output=True).stdout.strip() or "unknown"
    h_vers = harness_versions(harnesses)
    smoke = run_preflight_smoke(harnesses, user_harness=args.user_harness, dsh_keep_mcps=dsh_keep_mcps)

    rows: list[dict[str, Any]] = []
    work_tmp = Path(tempfile.mkdtemp(prefix="xt_six_tier_live_"))
    try:
        for h in harnesses:
            if not smoke.get(h, {}).get("ok"):
                continue
            run_idx = 0
            for rep in range(reps):
                for variant in variants:
                    for tier in tiers:
                        order = list(arms) if run_idx % 2 == 0 else list(reversed(arms))
                        run_idx += 1
                        budget = 60 if args.dev_check else TIER_BUDGETS_S[tier]
                        for arm in order:
                            ws, aux = prepare_tier_workspace(
                                work_tmp / h / f"r{rep}",
                                tier, arm,
                                use_meta=use_meta,
                                variant=variant,
                                instructions_mode=args.instructions,
                                cold_index=args.cold_index,
                            )
                            try:
                                row = run_harness_arm(
                                    h, tier, arm, ws, aux, budget,
                                    user_harness=args.user_harness,
                                    dsh_keep_mcps=dsh_keep_mcps,
                                    use_meta=use_meta,
                                    variant=variant,
                                    instructions_mode=args.instructions,
                                    cold_index=args.cold_index,
                                    rea_path=rea_path,
                                )
                                row["rep"] = rep
                                row["user_harness"] = args.user_harness
                                row["meta_mode"] = use_meta
                                rows.append(row)
                            finally:
                                shutil.rmtree(ws, ignore_errors=True)
                                shutil.rmtree(aux, ignore_errors=True)
    finally:
        shutil.rmtree(work_tmp, ignore_errors=True)

    # Paired A vs B summary
    by_pair: dict[tuple[str, str, str, int], dict[str, dict[str, Any]]] = {}
    for r in rows:
        by_pair.setdefault((r["harness"], r["tier"], r["variant"], r["rep"]), {})[r["arm"]] = r
    wins, ties, losses = 0, 0, 0
    for pair in by_pair.values():
        if "A" in pair and "B" in pair:
            a, b = pair["A"], pair["B"]
            if b["pass"] and not a["pass"]:
                wins += 1
            elif a["pass"] and not b["pass"]:
                losses += 1
            elif a["pass"] and b["pass"]:
                if b["wall_s"] + 0.5 < a["wall_s"]:
                    wins += 1
                elif a["wall_s"] + 0.5 < b["wall_s"]:
                    losses += 1
                else:
                    ties += 1
            else:
                ties += 1

    # Per-(harness, tier, variant, arm) median aggregation across reps
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for r in rows:
        grouped.setdefault((r["harness"], r["tier"], r["variant"], r["arm"]), []).append(r)

    def _med(vals: list[float | int | None]) -> float | None:
        clean = [float(v) for v in vals if isinstance(v, (int, float))]
        return round(statistics.median(clean), 2) if clean else None

    median_summary: list[dict[str, Any]] = []
    for (h, t, v, arm_id), grp in sorted(grouped.items()):
        passes = sum(1 for g in grp if g["pass"])
        median_summary.append({
            "harness": h,
            "tier": t,
            "variant": v,
            "arm": arm_id,
            "reps": len(grp),
            "passes": passes,
            "pass_rate": round(passes / len(grp), 3),
            "median_wall_s": _med([g.get("wall_s") for g in grp]),
            "median_ev_s": _med([g.get("sufficient_evidence_s") for g in grp]),
            "median_input_tokens": _med([g.get("input_tokens") for g in grp]),
            "median_tool_calls": _med([g.get("tool_calls") for g in grp]),
            "median_xtforge_calls": _med([g.get("xtforge_calls") for g in grp]),
        })

    summary = {
        "xt_forge_revision": git_rev,
        "fixture_revision": fixture_revision_digest(),
        "user_harness": args.user_harness,
        "harness_versions": h_vers,
        "preflight_smoke": smoke,
        "paired_b_vs_a": {"wins": wins, "ties": ties, "losses": losses},
        "median_summary": median_summary,
        "rows": rows,
    }

    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        csv_fields = ["tier", "variant", "rep", "arm", "harness", "model", "pass", "on_time_complete", "failed_assertion", "wall_s", "first_evidence_s", "sufficient_evidence_s", "final_answer_s", "input_tokens", "output_tokens", "tool_calls", "repeated_calls", "redundant_calls_after_evidence", "invalid_invocations", "xtforge_calls", "recall", "precision"]
        with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=csv_fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"six-tier benchmark rev={git_rev} fixture={summary['fixture_revision']} paired_B_vs_A={wins}W-{ties}T-{losses}L")
        print("preflight:", json.dumps(smoke))
        print(f"{'tier':<20} {'var':<7} {'r':>1} {'arm':<3} {'pass':<5} {'wall_s':>6} {'ev_s':>6} {'in_tok':>8} {'tools':>5} {'inv':>3} {'xtf':>4}  note")
        for r in rows:
            ev_s = f"{r['sufficient_evidence_s']:.1f}" if isinstance(r.get("sufficient_evidence_s"), (int, float)) else "-"
            note = r.get("failed_assertion") or (f"ok (R={r['recall']} P={r['precision']})" if "recall" in r else "ok")
            print(
                f"{r['tier']:<20} {r['variant']:<7} {r['rep']:>1} {r['arm']:<3} {str(r['pass']):<5} "
                f"{r['wall_s']:>6.1f} {ev_s:>6} {str(r['input_tokens']):>8} "
                f"{r['tool_calls']:>5} {r['invalid_invocations']:>3} {r['xtforge_calls']:>4}  {note}"
            )
        if median_summary:
            print("\n=== MEDIAN SUMMARY ===")
            print(f"{'tier':<26} {'arm':<3} {'pass':>6} {'med_wall_s':>10} {'med_ev_s':>8} {'med_in_tok':>10} {'med_tools':>9}")
            for m in median_summary:
                print(
                    f"{m['tier']:<26} {m['arm']:<3} {m['passes']}/{m['reps']:<4} "
                    f"{str(m['median_wall_s'] or '-'):>10} {str(m['median_ev_s'] or '-'):>8} "
                    f"{str(m['median_input_tokens'] or '-'):>10} {str(m['median_tool_calls'] or '-'):>9}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
