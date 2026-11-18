<div align="center">
  <a href="https://xtrcom.xyz">
    <img src="docs/assets/xtforge-icon.png" alt="XT-Forge Icon" width="112" />
  </a>
  <h1>xt-forge</h1>
  <p><strong>Local agent workbench for call-graph context, offline reverse engineering, keyless CVE intel, and sub-1KB MCP routing.</strong></p>
  <p>Built in <strong>Rust</strong>, <strong>Go</strong>, and zero-dependency <strong>Python 3.11+</strong> by <a href="https://xtrcom.xyz">XtrComSu</a>.</p>
  <p>
    <a href="https://github.com/XtrComSu/xt-forge/releases/tag/v0.4.2-Damascus"><img src="https://img.shields.io/badge/release-v0.4.2--Damascus-FF2E2E?style=flat-square&logo=github" alt="Release v0.4.2-Damascus" /></a>
    <img src="https://img.shields.io/badge/engines-Rust%20%2B%20Go%20%2B%20Python%203.11%2B-111116?style=flat-square" alt="Rust + Go + Python" />
    <img src="https://img.shields.io/badge/MCP%20schema-1.35%20KB%20(--meta)-22C55E?style=flat-square" alt="1.35 KB MCP Schema" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3B82F6?style=flat-square" alt="MIT License" /></a>
  </p>
</div>

<p align="center">
  <img src="docs/assets/overview-showcase.gif" alt="XT-Forge v0.4.2-Damascus Overview Showcase" width="100%" />
</p>

---

## Why Use xt-forge

Most coding and security agent setups burn thousands of context tokens on massive tool schemas, blind grep searches, and dead-end retries. `xt-forge` puts a fast, local workbench on your `PATH` with native Rust/Go performance and zero third-party runtime dependencies:

| Everyday Problem | What `xt-forge` Gives You | Command / Guide |
| --- | --- | --- |
| Bloated MCP catalogs eat 10K–40K+ tokens upfront | `--meta` gateway exposes 4 meta-tools (`1,384 B` Go / `1,007 B` Python) across local tools + external MCPs | `xt-forge --meta` |
| Massive RE/IDE MCPs (`rea`, `craft-anything`) break context limits | Connect once (`mcp connect`), SHA-256 trust-pin, and route stateful stdio calls lazily | `xt-forge mcp connect rea` |
| Regex grep misses callers, callees, and definitions | Incremental `code_graph.db` call graph + LSP multiplexer pack structural slices | `xt-forge code index .` |
| Binary triage usually drags in heavy GUI tools | Offline ELF/PE/Mach-O headers, `checksec`, `capa`, RTTI, CFG, XOR, ASAR, APK, HAR | [CVE & RE Guide](docs/CVE-AND-REVERSE-ENGINEERING.md) |
| Threat lookups stall behind API keys or rate limits | Keyless NVD, FIRST EPSS, CISA KEV, InternetDB, GreyNoise, and CIRCL fan-out | `xt-forge intel cve CVE-2024-3094` |
| Agents repeat failed fixes or claim done unverified | Negative failure memory, drift checks, and command-backed `goal verify` | [MCP & Steering Guide](docs/MCP-GATEWAY-AND-STEERING.md) |
| External MCP servers mutate schemas or inject prompts | Per-tool SHA-256 rug-pull locks (`mcp audit`), guard proxy, and injection scanner | `xt-forge mcp audit` |

---

## Install on Windows, Linux, and macOS

### Option 1: Universal `npx` Setup (Windows, Linux, macOS)

Node.js (`18+`) installs global `xt-forge`, `xtf`, `/xtf` slash commands, and all 18 `XTF-*` skills in one step:

```sh
npx xt-forge@latest init
```

### Option 2: Native One-Line Install (Builds Rust + Go + Links PATH)

**Linux & macOS (Bash / Zsh):**

```sh
# Piped one-liner:
curl -fsSL https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.sh | bash

# Or from a local clone:
git clone https://github.com/XtrComSu/xt-forge.git && cd xt-forge && ./install.sh
```

**Windows (PowerShell 5.1+ / PowerShell 7+):**

```powershell
# Piped one-liner:
irm https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.ps1 | iex

# Or from a local clone:
git clone https://github.com/XtrComSu/xt-forge.git; cd xt-forge; .\install.ps1
```

Both `install.sh` and `install.ps1` compile Rust (`xtforge-native`, requires **Cargo 1.78+** with bundled SQLite — no `libsqlite3-dev` headers required) and Go (`xtforge-hub`, requires **Go 1.24+**) when toolchains are present, and fall back to zero-dependency Python 3.11+ (`XT_FORCE_PYTHON=1` forces Python anytime) with CLI workflow parity while native binaries accelerate hot paths 10x–25x. Prebuilt release tarballs, npm packages (`xt-forge`, `xtf`), and stdlib wheels (`xtforge`) live on [Releases](https://github.com/XtrComSu/xt-forge/releases).

```sh
xt-forge --meta        # stdio MCP gateway (xt_discover, xt_schema, xt_call, xt_batch)
xt-forge doctor        # inspect workspace health, guard mode, and native engines
npx xt-forge skills    # list the 18 bundled XTF-* workflow skills
```

---

## Agent Self-Install Prompts

Want an AI coding agent (Claude Code, Codex CLI, OpenCode, DSH, Cursor) to install and verify `xt-forge` itself? Paste this prompt directly to the agent, or print the full prompt suite via `npx xt-forge prompt-install` (see [prompts/install.md](prompts/install.md)):

> Install `xt-forge` (`https://github.com/XtrComSu/xt-forge`) for this OS (`./install.sh` on Linux/macOS, `.\install.ps1` on Windows PowerShell, or `npx xt-forge@latest init`), verify `xt-forge`, `xtf`, `/xtf`, and all 18 `XTF-*` skills are installed, register `xt-forge --meta` in the active MCP config if one exists, and run `xt-forge version --json` + `xt-forge doctor --json` + `tools/list` on `xt-forge --meta` to prove the setup works.

---

## Lean MCP Setup + REA & Craft Anything

Wire `xt-forge` once using `--meta`. Models discover tools on demand (`xt_discover` -> `xt_schema` -> `xt_call` or `xt_batch`), keeping initial prompt schema size at **1,384 bytes (346 tokens)** in Go (`1,007 B / 252 tok` in Python) — **93.1% smaller** on 50-tool catalogs and **98.5% smaller** on 229-tool catalogs (`Direct` remains leaner on tiny 1–4 tool catalogs) — and spilling oversized responses cleanly to `$XT_HOME/cache/artifacts/`.

<p align="center">
  <img src="docs/assets/mcp-rea-craft.gif" alt="Connecting REA and Craft Anything through XT-Forge --meta Gateway" width="100%" />
</p>

It natively connects, trust-pins, and proxies **[REA](https://github.com/morluto/rea)** (`rea-agents mcp`, **229 RE tools** / ~3.5 MB raw schema) and **[Craft Anything](https://github.com/storytold/craft-anything)** (`craft-anything-cli mcp`, dynamic `enable_toolset` / `--all-tools`) behind **persistent stateful stdio sessions**, automatic `notifications/tools/list_changed` catalog refresh, and unified cross-runtime SHA-256 rug-pull checks:

```sh
# 1. Connect, injection-scan, and SHA-256 pin REA or Craft Anything once
xt-forge mcp connect rea --json
xt-forge mcp connect craft-anything --json

# 2. Or proxy either server directly with auto-refreshing dynamic toolsets
xt-forge mcp proxy --server rea
xt-forge mcp proxy --server craft-anything

# 3. Optional Craft Anything / custom binary overrides
export REA_CMD=/path/to/rea-agents
export CRAFT_ANYTHING_CMD=/path/to/craft-anything-cli
export XT_CRAFT_ALL_TOOLS=1   # or XT_CRAFT_DEEP=1 / XT_CRAFT_ALLOW_RUN=1 / XT_CRAFT_PROJECT=/repo
```

```json
{
  "mcpServers": {
    "xt-forge": {
      "command": "xt-forge",
      "args": ["--meta"]
    }
  }
}
```

<details>
<summary>MCP Schema Overhead Chart & Rug-Pull Audit Walkthrough</summary>

![MCP Prompt Schema Overhead](docs/assets/mcp-token-savings.png)

![MCP Proxy and Rug-Pull Audit](docs/assets/mcp-proxy-audit.gif)

</details>

---

## Reverse Engineering, Intel & Visual Walkthroughs

<p align="center">
  <img src="docs/assets/re-intel-triage.gif" alt="Offline RE Checksec, Capa, and Keyless CVE/KEV Triage" width="100%" />
</p>

<details>
<summary>More Live Workflow Demos (Call Graphs, Goal Drift Checks, RE Overlay Workbench)</summary>

**Incremental Call Graph & Context Packing (`code index` / `route context --symbols`):**

![Call Graph and Context Packing Demo](docs/assets/code-graph-context.gif)

**Stateful RE Workbench (`re annotate`, `re asar`, `re apk`, `re decompile`):**

![Stateful Reverse Engineering Workbench](docs/assets/re-workbench.gif)

**Negative Memory & Anti-Drift Verification (`goal check` / `goal verify`):**

![Goal Check and Verification Gate](docs/assets/goal-vibe-check.gif)

</details>

---

## 3-Tier Workflow Skills (`XTF-*`)

`xt-forge init` syncs **18 self-explanatory workflow skills** across three tiers into `~/.agents/skills`, `~/.dsh/skills`, `~/.config/opencode/skills`, and `~/.claude/skills` so models pick exact commands instead of guessing:

| Tier | Count | Skills | Scope |
| --- | ---: | --- | --- |
| **Simple** | 6 | `XTF-RepoMap`, `XTF-CallGraph`, `XTF-Notes`, `XTF-SecretScan`, `XTF-LogCompress`, `XTF-CVELookup` | Workspace maps, call graphs, flash notes, secret/injection scans, log compression, keyless CVE lookup |
| **Complex** | 6 | `XTF-BinaryTriage`, `XTF-Disasm`, `XTF-IOCIntel`, `XTF-BinaryPatch`, `XTF-Unpack`, `XTF-DeepResearch` | Offline ELF/PE triage, disassembly/CFG/RTTI, IOC enrichment, guarded patching, ASAR/APK/HAR unpack, parallel research |
| **Advanced** | 6 | `XTF-Decompile`, `XTF-MCPGateway`, `XTF-BugFix`, `XTF-CrashTriage`, `XTF-GoalLoop`, `XTF-MemoryEval` | String decoding, decompilation, MCP rug-pull defense + REA/Craft routing, bug fixes, minidump postmortem, bounded verification loops |

Full reference and trigger patterns live in [docs/SKILLS.md](docs/SKILLS.md).

---

## Harness Integrations

Drop-in configurations, slash commands (`/xtf --meta`), and tailored setup walkthroughs are included for each major agent harness:

| Harness | Folder | Integration Highlights |
| --- | --- | --- |
| **DSH** | [integrations/dsh/](integrations/dsh/) | Native `/xtf --meta` command prompt, `mcp-patch.json`, profile-aware `cordis` setup |
| **OpenCode** | [integrations/opencode/](integrations/opencode/) | `opencode.json` + native `/xtf`, `/taste`, `/goal`, `/loop` TypeScript plugin |
| **Codex CLI** | [integrations/codex/](integrations/codex/) | Clean `config.toml` entry + compact `AGENTS.md` workflow rules |
| **Claude Code** | [integrations/claude-code/](integrations/claude-code/) | Project `.mcp.json`, `CLAUDE.md`, and `/xtf` slash command integration |

---

## Common Commands

```sh
# Keyless CVE + Exploit + IOC Triage
xt-forge intel cve CVE-2024-3094 --json
xt-forge re checksec payload.elf --json
xt-forge re capa payload.elf --json
xt-forge re ioc payload.elf --json

# Incremental Symbol Call Graph & Context Packing
xt-forge code index .
xt-forge code graph verify_sig . --depth 2 --json
xt-forge route context . --query "verify_sig" --symbols --token-budget 1200

# Connect External MCPs, Guardrails & Security Scanning
xt-forge mcp connect rea --json
xt-forge mcp audit --server upstream --cmd "npx -y @org/server" --trust-on-first
xt-forge guard mode explore|ask|auto
xt-forge mem search "TLS" --k 3 --json
xt-forge scan secrets .
```

---

## Native Performance

Hot CLI paths run directly in Rust (`xtforge-native`) and Go (`xtforge-hub`), delivering 10x to 25x speedups over `XT_FORCE_PYTHON=1` on cold subprocess invocations (median of 5 runs):

| Workload | Native Engine | Native (ms) | Python (ms) | Speedup |
| --- | --- | ---: | ---: | ---: |
| `scan secrets xtforge` | Rust | 28.2 | 327.2 | 11.6x |
| `route context xtforge --symbols` | Rust | 15.3 | 162.8 | 10.7x |
| `code index xtforge` | Rust | 6.9 | 122.9 | 17.9x |
| `codec entropy <elf>` | Rust | 7.7 | 197.5 | 25.8x |
| `re checksec <elf>` | Go | 8.8 | 120.6 | 13.7x |
| `re capa <elf>` | Go | 18.3 | 313.9 | 17.2x |
| `intel sources` | Go | 6.0 | 109.3 | 18.2x |

![XT-Forge Hybrid Architecture](docs/assets/architecture-rust-go.png)

---

## Benchmarks & Reproducibility

`v0.4.2-Damascus` validates context precision, MCP discovery overhead, and crash recovery end-to-end:

| Suite | Scope | Result | Command |
| --- | --- | --- | --- |
| **Context Packing** | `context_tasks.json` (20 tasks) + held-out `context_tasks_unseen.json` (8 tasks) | **20/20** (`608.4` mean tok, `88.8%` cut vs `3/20` map) · **8/8** unseen (`566.4` mean tok) | `python3 scripts/bench_context_pack.py --json` |
| **Discovery Cost** | Direct vs `--meta` on 4, 50, and 229 tools | Direct wins 1-turn on 4 tools (`450` vs `1,591` tok); `--meta` saves `93.1%` (50) & `98.5%` (229, `4.2 ms` first call) | `python3 scripts/bench_discovery_cost.py --json` |
| **3-Tier Live Suite** | `Find` / `Fix` / `Recover` (Codex, OpenCode, DSH) | Crash-safe `Recover`: **3/3 pass** with `xt-forge` (`1` commit, `0` duplicates) vs `0/3` baseline | `python3 scripts/bench_three_tier.py --self-test` |

---

## Documentation

- [Field Guide & Architecture Walkthrough](docs/GUIDE.md)
- [CVE Research and Reverse Engineering Deep Dive](docs/CVE-AND-REVERSE-ENGINEERING.md)
- [3-Tier Skills Reference (`XTF-*`)](docs/SKILLS.md)
- [MCP Meta-Gateway and Steering](docs/MCP-GATEWAY-AND-STEERING.md)
- [Rust + Go Hybrid Runtime Details](docs/ARCHITECTURE-RUST-GO.md)
- [RE Workbench Details](docs/RE-WORKBENCH.md)
- [Changelog (`v0.4.2-Damascus`)](CHANGELOG.md) · [Architecture Release Notes](docs/RELEASE-0.4.0.md)

## Tests

```sh
cd native/xtforge-rs && cargo test && cargo build --release && cd ../..
cd native/xtforge-go && go test -race ./... && go build -o xtforge-hub ./cmd/xtforge-hub && cd ../..
python3 -m unittest discover -s tests
node --test plugins/xt-native/test/*.test.mjs
```

[MIT Licensed](LICENSE) · [xtrcom.xyz](https://xtrcom.xyz)
