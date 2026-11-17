---
name: XTF-Compass
description: Navigate callers, callees, and LSP definitions accurately before editing shared symbols.
---

# XTF-Compass (Simple Tier)

Trace callers and definitions through XT-Forge's local SQLite call graph instead of guessing from substring matches.

## When to use
- Renaming, refactoring, or changing signatures of functions, classes, or methods.
- Checking where a bug or hot path is invoked across modules.

## Workflow
1. Index or refresh the workspace symbol graph incrementally:
   ```sh
   xt-forge code index .
   ```
2. Inspect multi-hop callers and callees for a symbol:
   ```sh
   xt-forge code graph <symbol> . --depth 2
   ```
3. Outline definitions in a specific file or verify references:
   ```sh
   xt-forge code outline path/to/file.py
   xt-forge code refs <symbol> .
   ```
4. If an LSP server is available, query compiler-exact locations via the Go multiplexer:
   ```sh
   xt-forge code lsp refs path/to/file.go --line 42 --col 12
   ```

## Guardrails
- Always inspect callers before changing return shapes or default arguments.
- Re-run `xt-forge code syntax <file>` after edits to catch AST errors early.
