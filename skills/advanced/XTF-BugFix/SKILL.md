---
name: XTF-BugFix
description: Localize bugs across complex codebases with call graphs, scope checks, and test verification.
---

# XTF-BugFix (Advanced Tier)

**Quick start:** `xt-forge code index . && xt-forge goal check --objective "..." --criteria "..."`

Navigate large multi-module repositories methodically so bug fixes stay surgical and never regress silent callers.

## When to use
- Fixing cross-module regressions or modifying core shared infrastructure.
- Preventing scope creep (`scope_bloat` / `criteria_drift`) across multi-file changes.

## Workflow
1. Index the codebase and locate entrypoints and impacted call chains:
   ```sh
   xt-forge code index .
   xt-forge code graph failing_symbol . --depth 3
   ```
2. Inspect memory for prior failures (`failed_attempt`, `anti_pattern`) touching this subsystem:
   ```sh
   xt-forge goal check --objective "Fix bug in failing_symbol" --criteria "unit tests pass; no caller regressions"
   ```
3. Implement minimal targeted changes, checking AST syntax cleanly:
   ```sh
   xt-forge code syntax path/to/changed.py
   ```
4. Run the project's test suite with automatic runner detection (`pytest` → `unittest` → `cargo test` → `go test` → `npm test`) via `xt-forge test . --json` (or `xt_call` → `test_run`), and record completion evidence:
   ```sh
   xt-forge test . --json
   xt-forge goal verify --criteria "unit tests pass; caller X intact" --verify "python3 -m unittest discover -s tests" --body-file proof.txt
   ```

## Guardrails
- Keep diffs tightly scoped to root cause; run the full relevant suite sequentially after the final edit.
