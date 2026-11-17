---
name: XTF-Spark
description: Track short-lived working notes and pinned facts across turns with flash scratchpad memory.
---

# XTF-Spark (Simple Tier)

Keep active campaign targets, hypotheses, and file anchors outside your prompt window in sub-millisecond Rust-backed flash memory.

## When to use
- Switching between multi-step investigations or waiting on long test runs.
- Pinning critical facts so conversation compaction cannot erase them.

## Workflow
1. Store a hot note with TTL:
   ```sh
   printf '%s\n' "Target entrypoint at main.go:55 handles --meta shortcut" | xt-forge flash set --key entry --text-file - --ttl 604800
   ```
2. Pin critical keys so they inject reliably when recalled:
   ```sh
   xt-forge flash pin entry
   ```
3. Inspect pinned or wired notes, or use universal slash commands (`/mp`, `/mw`, `/mc`):
   ```sh
   xt-forge flash list --pin-only
   xt-forge slash "/mw"
   ```
4. Promote lasting findings to durable SQLite memory (`mem`) before expiring:
   ```sh
   xt-forge slash "/mu entry"
   ```

## Guardrails
- Never store raw tokens, API keys, or credentials in flash notes.
- Run `xt-forge flash compact` periodically when notes accumulate.
