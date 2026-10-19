# Changelog

Version scheme: `MAJOR.MINOR.PATCH-<codename>`; the root `VERSION` file is the
single source of truth. This repo is a consolidation snapshot of the xt-forge
line (origin: `sample-app/xtforge` + `native/xtforge-rs`, plus the live
`~/.xt-forge` store), created 2026-10-19 for portable backup and install.

## 0.3.0-Damascus — 2026-10-06

- build: type 2 (specbuild) pipeline
- theme: XT-Code AMOLED

## 0.2.0-Damascus — 2026-10-06

- release: harness sync, plugin wiring, 38-tool MCP server, doctor
- build: mid-phase crash resume re-executes exactly once (A8)
- cli: package split; MCP flash/compress/goal tools; audit S18 fixes
- docs+tests: protocol/README/decisions, hardening suite, PROGRESS

## 0.1.0-Damascus — 2026-10-05

- cli+mcp: unified CLI dispatcher, MCP stdio server
- adapters: OpenCode adapter + generic harness + slash core
- build: staged pipeline — schema, DAG, handoff, gates, runner, drivers

## Snapshot notes — 2026-10-19

- included: `xtforge/` Python package (stdlib-only), `native/xtforge-rs`
  source + bench harness, `bin/` launchers (portable + origin reference),
  live store snapshot under `data/`
- excluded: native build artifacts (`target/`), `__pycache__/`, `mem.db-shm`
