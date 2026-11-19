---
name: XTF-DispatchTrace
description: Trace active runtime execution paths across package re-exports, shadowed symbols, and config-driven dispatch tables.
---

# XTF-DispatchTrace (Simple Tier)

**Quick start:** `xt-forge trace <entry_symbol> . --json` (or `xt_call` → `code_trace`)

Resolve which concrete handler or implementation actually runs at runtime when a codebase has `from ... import ... as ...` re-exports, duplicate symbol names, or JSON/TOML/YAML/ENV configuration dispatch tables.

## When to use
- Tracing an entrypoint (`dispatch_request`, `route_payload`, etc.) through `__init__.py` re-exports and `DISPATCH_TABLE[cfg]` lookups.
- Disambiguating active production handlers from legacy/shadowed functions with the same name.

## Workflow
1. Trace the entrypoint symbol across the workspace:
   ```sh
   xt-forge trace dispatch_request . --json
   ```
   Or via the `--meta` MCP gateway:
   ```json
   {"name": "code_trace", "arguments": {"symbol": "dispatch_request", "path": "."}}
   ```
2. Read `active_implementation` and `active_path` (which lists every hop from `entry_definition` → `config_helper` → `reexport_or_import` → `resolved_implementation` with line-numbered function excerpts).
3. Inspect `disputed_edges` and `inactive_candidates` to cite the exact config key/value (`config_values`) and explain why shadowed or legacy handlers are inactive.

## Guardrails
- Always trust resolved import bindings and active config values over filename guesses.
- When `evidence_complete: true` is present, all hop excerpts and inactive candidate excerpts are already included.
