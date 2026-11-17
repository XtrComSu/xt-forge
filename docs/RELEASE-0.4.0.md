# XT-Forge 0.4.0 Release Notes (Preview)

Codename: **Damascus**

XT-Forge 0.4.0 expands the toolkit from a fast memory and file-routing CLI into a hybrid **Rust + Go + Python** workbench for agent steering, low-overhead MCP serving, and deterministic reverse engineering. Every new capability obeys the original contract: zero external Python runtime dependencies, strict path and command guards, structured `--json` output on every verb, and full fallback parity under `XT_FORCE_PYTHON=1`.

## Highlights

* **Four-tool MCP Meta-Gateway (`xt-forge --meta`):** Exposes `xt_discover`, `xt_schema`, `xt_call`, and `xt_batch` so agents can search and execute the full toolkit with a 0.90 KB compact schema footprint (94% smaller than the default 50-tool catalog) while leaving the default 50-tool surface untouched.
* **Dead-Simple CLI & Slash Integration (`npx xt-forge init`, `./install.sh`, `/xtf --meta`):** Puts `xt-forge` and `xtf` directly onto `PATH`, installs `/xtf` slash commands across DSH, OpenCode, and Claude Code, and syncs 18 3-tier `XTF-*` workflow skills automatically.
* **MCP Supply-Chain Security (`scan mcp`, `mcp audit`, `mcp trust`, `mcp proxy`):** Scans tool docstrings for hidden prompt injections, pins per-tool and catalog SHA-256 hashes in `mcp_trust.json`, detects silent post-install schema changes ("rug pulls"), and spills large responses cleanly to `cache/artifacts/`.
* **Persistent Code Call Graphs and LSP Bridge (`code index`, `code graph`, `code lsp`, `route context --symbols`):** Builds an incremental `code_graph.db` across Python, Rust, Go, JavaScript, TypeScript, and C/C++, connects callers and callees during context packing, and spawns local language servers on demand when available.
* **Stateful RE Workbench (`re annotate`, `asar`, `netcap`, `apk`, `decompile`, `trace`):** Hashes binaries by SHA-256 into `re_overlay.db`, merges analyst renames and comments directly into CFG/xrefs output, exports Radare2/Rizin and Ghidra scripts, inspects Electron ASAR and Android APK containers, summarizes HAR/SAZ captures with masked credentials, and adds Rust Mach-O headers and length-ranked XOR recovery.
* **Agent Steering & Negative Memory (`mem record-failure`, `mem consolidate`, `goal check`, `guard mode`):** Stores indexed `failed_attempt` and `anti_pattern` records, surfaces failure warnings during normal search, consolidates repetitive notes with `derived_from` provenance links, checks goals for criteria drift and scope bloat, and adds `explore | ask | auto` permission modes with JSONL audit logs.
* **Parallel Research & Loop Daemon (`research`, `loop schedule | list | stop`):** Runs concurrent multi-store dossier queries and persists bounded recurring schedules (`MaxTasks=50`, 7-day lifetime, `XT_NATIVE_LOOP=0` kill switch).

## Documentation & Visuals

* [Field Guide](GUIDE.md)
* [Hybrid Rust, Go, and Python Architecture](ARCHITECTURE-RUST-GO.md)
* [Reverse Engineering Workbench](RE-WORKBENCH.md)
* [MCP Meta-Gateway and Steering](MCP-GATEWAY-AND-STEERING.md)

## Preview Artifacts (Not Published)

Local build artifacts live in `dist/` for hands-on inspection before any public release:

* `xt_forge-0.4.0-py3-none-any.whl`: stdlib-only Python wheel (`uv pip install xt_forge-0.4.0-py3-none-any.whl`).
* `xt_forge-0.4.0.tar.gz`: Python source distribution.
* `xt-forge-0.4.0-linux-x86_64.tar.gz`: standalone Linux x86_64 preview bundle with `bin/xtforge`, compiled `xtforge-native` (Rust) and `xtforge-hub` (Go), `xtforge/`, `adapters/`, and `docs/`.
* `SHA256SUMS`: artifact checksums (`(cd dist && sha256sum -c SHA256SUMS)`).
