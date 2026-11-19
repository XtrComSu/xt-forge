---
name: XTF-CodeAudit
description: Audit source trees via AST for duplicate aggregation, boundary off-by-one bugs, stale caches, numeric truncation, and mutable defaults.
---

# XTF-CodeAudit (Simple Tier)

**Quick start:** `xt-forge audit . --json` (or `xt_call` → `code_audit`)

Perform a multi-file static correctness audit across Python workspaces in one call, returning complete function sources, defect classifications, and clean-module verification.

## When to use
- Auditing an application or module for subtle correctness defects without reading every file one by one.
- Checking for nested-loop join duplication, inclusive/exclusive boundary bugs (`<` vs `<=`), stale module caches missing invalidation, integer floor-division truncation, or mutable defaults.

## Workflow
1. Run the workspace AST correctness auditor:
   ```sh
   xt-forge audit . --json
   ```
   Or via the `--meta` MCP gateway:
   ```json
   {"name": "code_audit", "arguments": {"path": "."}}
   ```
2. Inspect `findings` — each finding includes:
   - `category` (`duplicate_aggregation`, `boundary_comparison`, `stale_cache`, `numeric_truncation`, `mutable_default`)
   - `file`, `line`, `function`, `signal`
   - `function_source` (full line-numbered source of the enclosing function) and `reader_source` (for `stale_cache` pairs)
3. Check `clean_files` and `evidence_complete: true` to confirm which production modules have zero defects without issuing redundant file reads.

## Guardrails
- When `evidence_complete: true` is returned, report directly from `findings` and `clean_files` instead of re-reading every clean module.
- Do not invent speculative bugs in modules listed under `clean_files`.
