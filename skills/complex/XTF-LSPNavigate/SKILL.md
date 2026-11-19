---
name: XTF-LSPNavigate
description: Query language servers via the Go LSP stdio multiplexer alongside AST symbol outlines and cross-references.
---

# XTF-LSPNavigate (Complex Tier)

**Quick start:** `xt-forge code lsp --lang py --method textDocument/documentSymbol --file app.py`

Combine fast incremental AST indexing (`code outline`, `code refs`, `code callers`) with persistent Go-multiplexed Language Server Protocol (`code lsp`) queries across Python, Rust, Go, and TypeScript.

## When to use
- Navigating type definitions, hover signatures, or workspace symbols across polyglot repositories.
- Checking all callers (`production_callers` vs `unresolved_candidates`) before changing a function signature.

## Workflow
1. Check symbol definitions and import-resolved production callers first:
   ```sh
   xt-forge callers MySymbol . --json
   ```
2. Inspect file structure without reading the entire file:
   ```sh
   xt-forge code outline path/to/module.py --json
   ```
3. Run an LSP query through the Go concurrency hub when compiler-grade type resolution is needed:
   ```sh
   xt-forge code lsp --lang rust --root . --method workspace/symbol --params '{"query":" index_workspace"}'
   ```

## Guardrails
- Prefer `xt-forge callers` (`code_callers`) for fast workspace-wide caller verification; it automatically separates test/shadow callers into `unresolved_candidates`.
