## 0.4.5 - 2026-11-19

### Added
- **Ghidra MCP & Full REA Replacement (`xt-forge mcp connect ghidra`, `xt-forge --meta`, `xt-forge tool run ghidra`)**:
  - Added `xtforge.adapters.ghidra_mcp` (`python3 -m xtforge.adapters.ghidra_mcp`), a **38-tool stdio MCP server** compatible with `LaurieWired/GhidraMCP`, `pyghidra-mcp`, and `rea-agents` binary, Electron `.asar`, Android `.apk`, `.har`/`.saz` netcap, and JS/TS bundle workflows.
  - **Tiered Multi-Engine Execution**: Automatically routes across (1) live Ghidra GUI HTTP bridge (`GHIDRA_MCP_URL`, default `http://127.0.0.1:8080/`), (2) headless Ghidra (`analyzeHeadless` + auto-detected `JAVA_HOME`), and (3) instant `<20 ms` `borer` lifter + `xt-forge` `.rodata` string & reciprocal-division math annotator.
  - **Persistent Inline Decompiler Overlay (`$XT_HOME/re_overlay.db` + `ghidra-var-overlay.json`)**: `rename_function`, `rename_function_by_address`, `rename_variable`, `rename_data`, `set_function_prototype`, `set_decompiler_comment`, and `set_disassembly_comment` rewrite decompiled C signatures, variable names, call targets, and comments inline and allow subsequent `decompile_function` calls by the newly renamed symbol name.
  - **Zero-Node.js REA Fallback**: When `rea-agents` is not installed locally (or `XT_REPLACE_REA=1`), `xt-forge` automatically serves `rea` MCP requests through `xtforge.adapters.ghidra_mcp` without falling back to `npx rea-agents@latest`.

## 0.4.4 - 2026-11-19

### Added
- **Borer MCP Integration & 1-Call Optimization (`xt-forge mcp connect borer`, `xt-forge --meta`, `xt-forge tool run borer`)**:
  - Added first-class preset, auto-discovery, SHA-256 trust pinning, and persistent stdio pooling for [`imjustprism/borer`](https://github.com/imjustprism/borer) (`borer`, 34 MCP tools + 111 `borer://` resources for certified x86/x64/arm64/RISC-V decompilation, function emulation, symbolic solve, taint tracking, devirtualization, and unpacking) in both Go (`native/xtforge-go/internal/mcp/upstreams.go`, `proxy.go`) and Python (`xtforge/core/mcp_registry.py`, `mcp_proxy.py`, `mcp_server.py`).
  - **1-Call `load_binary` Injection & Session Rehydration**: Passing `"path"` or `"binary"` to any downstream `borer:*` tool (`decompile`, `function_summary`, `query`, `binary_info`, `strings`, `symbols`, `xrefs`, `cfg`, `callgraph`) automatically executes `load_binary` in the active session and caches the target binary path in `$XT_HOME/cache/borer-session.json` so subsequent calls and one-shot CLI invocations (`xt-forge tool run borer ...`) preserve binary state without extra round-trips.
  - **`borer://` Resource Discovery & Shorthand Expansion**: Indexed all 39 static resources and 72 resource templates (`triage`, `emulate`, `solve`, `taint`, `devirt`, `unpack`, `stackstrings`, `capabilities`, `antianalysis`, `dynimports`, `checks`, `yara`, `sig`, `layout`, `patch`) for `xt_discover` and automatically normalized shorthand `query(uri="capabilities")` calls to `"borer://capabilities"`.
- **Clean, Minimal 2x-Supersampled Visual Cards (`docs/assets/*.png`)**:
  - Redesigned `xt-oss-banner.png`, `xtforge-vs-rea-benchmark.png`, `architecture-rust-go.png`, and `mcp-token-savings.png` with a clean, restrained dark palette, generous negative space, crisp 2x-supersampled Noto Sans + JetBrains Mono typography, and zero neon box clutter.

## 0.4.3 - 2026-11-19

### Added
- **Normalized Binary Diffing, `.rodata` String Annotation & Reciprocal Division Decoding (`xt-forge diff` / `re diff`)**:
  - Added `xtforge.core.re.diff` (`diff_binaries`), normalizing absolute/RIP-relative hex offsets across `v1` and `v2` binaries, annotating `function_disasm_v1` and `function_disasm_v2` inline with resolved `.rodata` string literals, and automatically decoding GCC/Clang strength-reduced reciprocal multiplication/shift constants (`imul` + `sar`/`shr`) into human-readable divisors and percentage shifts (`diff_notes`).
- **Multi-File AST Static Correctness Auditor (`xt-forge audit` / `code audit`)**:
  - Added `xtforge.core.code.audit` (`audit_workspace`), detecting nested-loop duplicate aggregation without deduplication, asymmetric/off-by-one boundary comparisons (`<` vs `<=`), stale module caches where mutators omit invalidation, integer floor-division truncation in allocation helpers, and mutable defaults, with full line-numbered `function_source` and `reader_source` evidence.
- **Cross-Module Active Dispatch Tracer (`xt-forge trace` / `code trace`)**:
  - Added `xtforge.core.code.trace` (`trace_symbol`), resolving runtime execution hops across package `__init__.py` re-exports (`from ... import ... as ...`), duplicate symbol names, and JSON/YAML/TOML/INI/ENV/Python configuration dispatch tables (`active_implementation`, `active_path`, `disputed_edges`, and `inactive_candidates` with line-numbered function excerpts).
- **High-Concurrency Binary MapReduce & MCTS Hypothesis Solver (`xt-forge swarm`)**:
  - Added `swarm map` and `swarm mcts` in the Go concurrency hub (`native/xtforge-go/internal/swarm/engine.go`) and Python fallback (`xtforge/core/re/swarm.py`).
- **Top-Level Ergonomic CLI & `--meta` Gateway Shortcuts**:
  - Added top-level aliases `xt-forge callers`, `xt-forge audit`, `xt-forge trace`, `xt-forge diff`, and `xt-forge context`, plus first-class `--meta` MCP tools `code_callers`, `code_audit`, `code_trace`, and `re_diff` with zero-dash argument safety and `evidence_complete` flags in both Go (`xtforge-hub`) and Python (`xtforge/adapters/mcp_server.py`).
- **24 `XTF-*` Workflow Skills**:
  - Added 6 new workflow skills (`XTF-CodeAudit`, `XTF-DispatchTrace`, `XTF-BinaryDiff`, `XTF-LSPNavigate`, `XTF-SwarmRE`, `XTF-SessionRecovery`), expanding the catalog to **24 skills** across Simple (8), Complex (8), and Advanced (8) tiers.

### Fixed
- **6-Tier Live Benchmark (`scripts/bench_three_tier.py`)**:
  - Extended the benchmark suite to 6 tiers (`tier1_find`, `tier2_fix`, `tier3_recover`, `tier4_defects`, `tier5_trace`, `tier6_regression_src`, `tier6_regression_bin`) with live A/B pairing against raw REA (`rea-agents`, 229 tools) and fixed `grade_tier1` so call-site grep lines inside fenced code blocks are not misclassified as definition bindings.

## 0.4.2 - 2026-11-18

### Added
- **Context-Miss Diagnostics & Unseen Generalization (`route context --diagnose`)**:
  - Added `--diagnose`, `--expected-file`, and `--expected-line` in both Rust (`xtforge-native`) and Python (`xtforge.core.route.pack`), reporting `indexed`, `rank`, `score`, `drop_reason`, and token cutoffs on missed targets (`t03`, `t06`, `t09`, `t17` resolved: **20/20** hit rate vs `3/20` repo map on `context_tasks.json`).
  - Added held-out unseen benchmark fixture (`tests/fixtures/unseen_project/` + `tests/fixtures/context_tasks_unseen.json`, **8/8** hit rate with 54.3% token reduction).
- **Live Evidence Freshness (`digest` + incremental cache invalidation)**:
  - Attached SHA-256 `digest` and `start_line..end_line` provenance to packed context slices and automatically invalidated affected `code_graph.db` edges and cached results on live file rename/move/delete without manual rebuilds (`tests/test_context_freshness.py`).
- **Crash-Safe Tool Call Recovery & MCP Cancellation**:
  - Extended `xtforge.core.call_journal` and Go `internal/mcp/journal.go` (`pending` / `completed` / `unknown` states) with request-scoped `notifications/cancelled` propagation and automatic dead-upstream session respawn (`internal/mcp/upstreams.go`, `xtforge/adapters/mcp_server.py`), preventing duplicate commits across dropped replies (`tests/test_call_recovery.py`).
- **Measured Discovery Cost & 3-Tier Live Harness Benchmarks**:
  - Added `scripts/bench_discovery_cost.py` comparing direct MCP catalogs (4, 50, 229 tools) against Go (`1,384 B` / `346` tok) and Python (`1,007 B` / `252` tok) `--meta` gateways.
  - Added `scripts/bench_three_tier.py` (`Find`, `Fix`, `Recover`) with live tool-call preflight and credential-scrubbed traces across Codex CLI, OpenCode, and DSH (`tests/test_shipped_packages.py` covering Python wheel, npm `xt-forge`/`xtf`, and `install.sh`).

### Fixed
- **Full RELRO Detection (`re checksec`)**: Fixed both Go (`internal/rehub/sec_capa.go`) and Python (`xtforge/core/re/elf.py`) to inspect `DT_FLAGS` (`BIND_NOW`) and `DT_FLAGS_1` (`NOW`) alongside legacy `DT_BIND_NOW`, matching `readelf` (`Full` on `/bin/ls`).
- **Bundled SQLite in Rust (`native/xtforge-rs/Cargo.toml`)**: Enabled `rusqlite` `bundled` feature so Rust builds cleanly without system `libsqlite3-dev` headers.
- **`codec` CLI & Entropy Scanner**: Fixed argparse intermixed options bug in `codec` CLI (`xtforge/cli/__init__.py`) and eliminated false-positive `high_entropy` alerts on snake/kebab identifiers and `expected.json` fixtures (`scan_fast.rs`, `xtforge/core/scan/__init__.py`).
- **Accurate Diagnostics & Metadata**: Aligned Go hub `serverInfo` version to `0.4.2`, fixed `doctor` `native_dir` reporting and active `xtscan`/`xtdigest`/`xtsqueeze` engine tags (`xtforge/core/route/caps.py`), moved the MCP stdio implementation into wheel-included `xtforge/adapters/mcp_server.py`, and forwarded custom `env` blocks from `mcp_upstreams.json`.

## 0.4.1 - 2026-11-18

### Added
- **REA & Craft Anything MCP Integration (`mcp connect`, `mcp proxy --server`, `--meta`)**:
  - Built-in presets for [`morluto/rea`](https://github.com/morluto/rea) (`rea-agents mcp`, 229 RE tools) and [`storytold/craft-anything`](https://github.com/storytold/craft-anything) (`craft-anything-cli mcp`, dynamic `enable_toolset` / `--all-tools`).
  - Persistent stateful stdio sessions across multi-turn RE calls in both the Go hub (`internal/mcp/upstreams.go`) and Python fallback (`xtforge/core/mcp_proxy.py`), with automatic tool-catalog refresh on `notifications/tools/list_changed` / `enable_toolset`.
  - One-command `xt-forge mcp connect <server>` to probe, audit, trust-pin, save `$XT_HOME/mcp_upstreams.json`, and cache `$XT_HOME/cache/mcp-catalog-<server>.json` for lazy `<server>:<tool>` discovery/execution inside `xt-forge --meta`.
- **Cross-Platform Installers & Agent Self-Install Prompts**:
  - Added Linux/macOS (`install.sh`), Windows (`install.ps1`, `bin/xtforge.cmd`), `npx xt-forge init`, and agent copy-paste prompts under `prompts/`.
- **XT Brand Visuals & Plain Skill Naming**:
  - Replaced legacy icon assets with `XT`-styled artwork (`docs/assets/xt-forge-icon.svg`, `README.md`), standardized `XtrComSu` authorship across package metadata and git history, and renamed all 18 workflow skills cleanly (`XTF-RepoMap`, `XTF-MCPGateway`, `XTF-Decompile`, etc.).

### Fixed
- Unified Python `xtforge.core.mcp_audit` SHA-256 schema/tool hashing with Go `internal/mcp/audit.go` so `mcp_trust.json` pins interoperate cleanly across native and `XT_FORCE_PYTHON=1` modes.

## 0.4.0 - Local Release Preview

### Added
- **Hybrid Rust + Go + Python execution stack**:
  - Rust native engine (`native/xtforge-rs`, `xtforge-native`) handles `mem` SQLite WAL/FTS5 v3 operations (`record-failure`, `consolidate`), incremental AST/regex `code index` and BFS `code graph` (`code_graph.db`), stateful `re annotate` overlays (`re_overlay.db`), native Mach-O header parsing (`re info`), block Shannon entropy (`re entropy`), 255-key XOR string recovery (`re strings --xor`), and `scan mcp` prompt-injection inspection.
  - Go concurrency hub (`native/xtforge-go`, `xtforge-hub`) handles `mcp serve --meta` (4-tool 0.90 KB discovery/schema/call/batch gateway), `mcp proxy` (squeeze + cache spill wrapper), `mcp audit` / `mcp trust` (SHA-256 rug-pull locks), `code lsp` stdio multiplexing, `re asar` (Electron Pickle + source maps), `re netcap` (HAR/SAZ extraction with credential masking), `re apk`, `re decompile`, confirm-gated `re trace`, `research` multi-source fan-out, and background `loop schedule|list|stop|status`.
  - Pure-stdlib Python core (`xtforge/`) preserves 100% fallback parity under `XT_FORCE_PYTHON=1`.
- **Negative memory and consolidation (`mem.db` v3)**: `mem record-failure` logs `failed_attempt` records keyed by `error_sig`; `mem search` returns matching `warnings`; `mem consolidate` promotes repeated high-support episodes into `anti_pattern` items and prunes expired flash notes.
- **Anti-drift goal checks & permission modes**: `goal check` flags `scope_bloat`, `criteria_drift`, `repeat_error`, and negative-memory warnings; `guard mode` persists `explore|ask|auto` (`XT_PERM_MODE`) with structured JSONL audit logs in `$XT_HOME/audit/`.
- **Symbol-aware context packing & output spill cache**: `route context --symbols` expands query matches along `code_graph.db` call/import neighbors; `compress.clip_or_spill()` spills oversized payloads to `$XT_HOME/cache/artifacts/` while returning bounded L1 previews.
- **Documentation & visuals**: added `docs/GUIDE.md`, `docs/ARCHITECTURE-RUST-GO.md`, `docs/RE-WORKBENCH.md`, `docs/MCP-GATEWAY-AND-STEERING.md`, `docs/RELEASE-0.4.0.md`, plus PNG diagrams and animated terminal GIFs under `docs/assets/`.

### Fixed
- `bin/xtforge` now opens with `#!/usr/bin/env bash` so it executes out of the box across Linux desktops, CI runners, and Termux without manual interpreter edits.

## 0.3.4 - unreleased

### Added
- `xtforge mcp` — what the harness actually mounts, and what each server costs.
  `status` lists every declared server across every cordis profile;
  `advice` says whether fronting a server with the lite proxy would save
  anything; `configs` shows the files that were read. Costs are measured by an
  opt-in `--probe` that speaks real JSON-RPC `tools/list` to each server with
  the env the harness would give it, and reports unknown rather than zero for
  anything unmeasured.
- Native Rust engine (`xtforge-native`) compiled and active: 2-5ms queries for
  `route context`, ranked `route grep`, `mem search`, and `flash`. Dynamic
  Python resolver automatically locates system `/usr/bin/python3` or Termux.

### Fixed
- Allowlisted root safety guard in both Rust and Python now detects the true user
  home when running under a harness sub-account (`.dsh/agy-accounts/*`), resolving
  false `root_denied` errors on projects.
- DSH home auto-discovery now resolves `.dsh` in ancestor paths and detects
  `DSH_TUI_PROFILE`, allowing MCP inventory and prompt injection to work out of the
  box without `DSH_HOME` overrides.
- Non-interactive test hanging fixed in `tests/test_eval.py` by providing `input=""`
  for stdin tests.
- Fixed taste plugin session test assertion in `test_plugin_runtime.py` to match
  the cue-preserving statement extractor.
- The injected agent prompt described a `memos` MCP server that the active
  profile does not mount, and two `mcp__memos__*` tools that therefore could
  not be called. The harness block is now read from the live profile; when the
  memory server is proxied it names the proxy's call tool instead of tools the
  model cannot reach, and when nothing can be read it says so.
- Version identity was reported three ways at once: `VERSION` said 0.3.2,
  `pyproject.toml` said 0.3.3 and `xtforge.version()` said 0.1.0.
  `VERSION` is now the single source and the package re-exports it.
- The cordis patch reader treated every key at the `serverName` indent as the
  end of the record, so every server parsed with no command, args or env. The
  effect was silent: all servers were reported as direct and costless, and the
  229-tool `rea` catalog looked like a direct mount. Sibling keys are now read,
  and a server is recognised as proxied both by `LITE_PREFIX` and by the lite
  proxy script with no prefix.

## 0.3.3 — 2026-11-03

### Added
- `xtforge knowledge` — agent-contributed knowledge with lifecycle status
  (`observed|proposed|verified|contradicted|superseded|obsolete`), verification
  records, revision history, deprecation reasons, relations and scope filters.
- `xtforge design` — search the bundled design library, with a state-coverage
  check that fails when a pattern omits a required state.
- Design library (`design/`) — 3 patterns and 1 anti-pattern, each with
  documented dependencies, licence, provenance and declared states.
- `xt-design-brief` skill — establish users, primary task, states and a
  verification plan before building UI.

### Changed
- Memory schema v2: additive columns for status, evidence, verification,
  author, target, project, versions, environment. Existing rows are untouched
  and read as `status: observed` with `statusInferred: true`.
- Record deduplication now treats `target`/`project` as identity, so findings
  from different scopes no longer merge.
- Design library and error-memory paths resolve relatively; shipped prompt text
  discovers the launcher instead of naming one machine's path.
- Installed copies read their version from package metadata rather than
  reporting `0.0.0`.

### Fixed
- A `pass` recorded without an executed check no longer promotes a record to
  `verified`; it is recorded as an assertion with a caveat.
- A contradicted record now loses confidence (to ≤0.05) instead of keeping it.

# Changelog

Version scheme: `MAJOR.MINOR.PATCH-<codename>`; the root `VERSION` file is the
single source of truth. This repository holds the unified `xt-forge` toolkit
(`xtforge/`, `native/xtforge-rs`, and `native/xtforge-go`).

## 0.3.2-Damascus — 2026-10-21

Three defects in the shipped taste plugin, found by auditing a live profile
rather than by reading the code. All three made the profile lie about what
the user had asked for.

- **fix(taste): a rule the user avoided was injected as an instruction to
  do it.** The statement is the subject of a preference ("fabricate output")
  and the polarity says which way it points, but the injected block rendered
  the statement alone. A user who wrote "Never fabricate output" had
  `<rule>fabricate output</rule>` injected into every session — the exact
  opposite of the instruction. The block now renders a negative learning as
  a prohibition, and a statement that is already a prohibition is not
  prefixed twice
- **fix(taste): one prompt was ingested once per location.** The plugin is
  loaded once per location, so the prompt hook fired two or three times for
  the same prompt and each copy counted as another piece of evidence. A rule
  the user stated *once* reached `enforced` and was injected into every
  session, while the evidence log showed the same quote repeated. The
  prompt carries an id that is unique per admitted prompt, so it is now the
  deduplication key: one prompt, one signal
- **fix(taste): `xtforge taste repair`** collapses evidence the plugin
  recorded twice and recomputes the counters it inflated. Two rows are the
  same observation when they carry the same kind, quote and source and were
  recorded in the same second; a user who states the same thing again
  later is evidence and is kept, and a deliberate `manual` learning is never
  collapsed. Read-only unless `--apply`
- cli: `xtforge taste repair` (report by default, `--apply` to fix)
- 408 python tests + 17 plugin tests green

## 0.3.1-Damascus — 2026-10-20

- plugin: the OpenCode taste plugin is source in this repo
  (`plugins/xt-native/`) and ships with `xtforge plugin install|status|
  uninstall`; `xtforge sync` installs it too. Installed byte-for-byte and
  stamped with the paths the plugin needs, so the copy on a machine is not
  pinned to one home directory. Without a stamp the plugin degrades to a
  no-op instead of guessing
- plugin: D2 acceptance — **10 scripted sessions -> 6 expected learnings, 0
  invented keys, 1 enforced rule injected** (`plugins/xt-native/test/
  taste.sessions.test.mjs`); near-miss prompts stay silent and a hint never
  reaches the session
- plugin: 11 contract tests drive the real plugin with a mock OpenCode
  context (`plugins/xt-native/test/plugin.test.mjs`) — commands, hooks, the
  injected block, a fabricated completion claim, loop scheduling, and
  degradation when xt-forge is missing
- doctor: reports the plugin as installed / registered / current, with the
  drift list, instead of a single boolean that could not see it
- sync: writes the OpenCode config in the shape OpenCode v2 reads
  (`mcp.servers`, `plugins`), leaves a working MCP command alone, and backs
  up the config it rewrites
- sync: the AGENTS.md template ships again (`adapters/generic/AGENTS.md.tpl`)
  and the generated launcher points at an interpreter and a shell that exist
- cli: `xtforge plugin install|status|uninstall|manifest`
- taste: the extractor only creates a key from a preference word (always,
  never, prefer, avoid, please use, "use X not Y"). A bare "use" is a work
  order far more often than it is a durable preference — 19 of the 23 live
  learnings were invented by the old, looser rules
- taste: `taste prune` retires the learnings the current rules would no
  longer invent, so a scheduled tidy can clean the profile without guesswork
- taste: concurrent writes no longer lose evidence. Absorbing a signal is a
  read-modify-write, and SQLite's deferred transaction did the read *outside*
  the write lock — so two processes learning the same key both read the same
  row and both wrote it back, and one piece of evidence was gone. Four
  concurrent writers recorded **1** piece of evidence instead of 4, so the
  rule never reached `enforced` and was never injected into a session. The
  store now takes the write lock before the read (`BEGIN IMMEDIATE`): 4
  writers record 4 pieces of evidence and the rule is `enforced`
  (`scripts/repro_taste_lost_update.py`; regression test in
  `tests/test_taste.py`)
- taste plugin: prompt ingests are serialised, so a learning's statement is
  decided by the order the preference was said, not by process timing
- goal/loop: session-scoped goals, restart-safe loops, self-paced backoff
- suite: 393 tests green, including the plugin's own runtime tests on Node

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
