---
name: XTF-SessionRecovery
description: Prevent duplicate side-effects across dropped MCP tool calls using crash-safe call journaling, idempotency keys, and verify tools.
---

# XTF-SessionRecovery (Advanced Tier)

**Quick start:** `xt_call` with `idempotency_key`, `verify_tool`, and `verify_args`

Guarantee exactly-once execution for state-mutating MCP calls even when an upstream stdio server crashes, times out, or drops its reply after committing.

## When to use
- Calling non-idempotent tools (`submit_job`, `create_order`, `apply_patch`, database writes, or stateful RE session mutations) where retrying blindly on timeout would cause duplicate commits.
- Managing persistent stateful RE/debugger sessions via `xt-forge session`.

## Workflow
1. Discover the write tool and its companion read/receipt verification tool via `xt_search` and `xt_schema`.
2. Invoke `xt_call` with `idempotency_key`, `verify_tool`, and `verify_args`:
   ```json
   {
     "name": "job_runner:submit_job",
     "arguments": {"job_id": "job-alpha-01", "payload": "nightly-rollup"},
     "idempotency_key": "job-alpha-01",
     "verify_tool": "get_receipt",
     "verify_args": {"job_id": "job-alpha-01"}
   }
   ```
3. If the upstream drops the connection mid-flight, `xt-forge` records `"status": "unknown"` in `$XT_HOME/call_journal.json` and returns a `recovery_hint`. **Immediately** re-invoke `xt_call` with the **exact same `idempotency_key` + `verify_tool` + `verify_args`** (never wander `$XT_HOME` with `ls` or `cat`); `xt-forge` runs `verify_tool` before any retry and returns the committed receipt with `"recovered": true`.
4. Inspect or clean active stateful sessions with:
   ```sh
   xt-forge session list --json
   ```

## Guardrails
- Never retry a failed/timed-out mutating tool call without an `idempotency_key` and `verify_tool`.
