<div align="center">
  <a href="https://xtrcom.xyz">
    <img src="docs/assets/xtforge-icon.png" alt="XT-Forge Logo" width="96" />
  </a>
  <h1>xt-forge</h1>
  <p><strong>Supreme local agent workbench for call-graph context, AST correctness auditing, normalized binary diffing, keyless CVE intel, and sub-1KB MCP routing.</strong></p>
  <p>Engineered in <strong>Rust</strong>, <strong>Go</strong>, and zero-dependency <strong>Python 3.11+</strong> under <strong>XT-OSS</strong> by <a href="https://xtrcom.xyz">XtrComSu</a>.</p>
  <p>
    <a href="https://github.com/XtrComSu/xt-forge-dev/releases">
      <img src="docs/assets/header-badges.svg" alt="XT-Forge v0.4.8-Damascus" />
    </a>
  </p>
  <p>
    <a href="#install-on-linux-macos-and-windows">Quickstart &amp; Install</a> ·
    <a href="#xt-forge-vs-raw-rea">9-Tier Benchmarks</a> ·
    <a href="#why-use-xt-forge">Why Use xt-forge</a> ·
    <a href="#workflow-navigator">Workflow Navigator</a> ·
    <a href="#lean-mcp-setup--ghidra-borer--craft-anything-full-rea-replacement">MCP Gateway</a> ·
    <a href="docs/GUIDE.md">CLI Guide</a> ·
    <a href="CHANGELOG.md">Changelog</a>
  </p>
</div>

<p align="center">
  <img src="docs/assets/overview-cards.svg" alt="XT-Forge Capabilities" width="100%" />
</p>

<p align="center">
  <img src="docs/assets/overview-showcase.gif" alt="XT-Forge v0.4.8-Damascus XT-OSS Overview Showcase" width="100%" />
</p>

---

## Workflow Navigator

Direct your workflow using the roadmap below to find the commands, guides, and tools for your target:

<p align="center">
  <a href="#workflow-navigator">
    <img src="docs/assets/release-review/navigator.svg" alt="XT-Forge Workflow Navigator: Native binaries, source navigation, supply chain, and agent gateway" width="100%" />
  </a>
</p>

| Workflow | Primary Task | Key Commands | Output & Evidence |
| --- | --- | --- | --- |
| **[Native Binaries](#binary-inspection--reverse-engineering)** | Header inspection, disassembly, CFG flow, and cross-references | `re overview`, `re disasm-native`, `re xrefs-native`, `re diff` | JSON image metadata, instruction lists, call references |
| **[Source Code](#source-navigation--ast-call-graph)** | Token-budgeted context search, AST callers, and dispatch traces | `route context`, `callers`, `code trace`, `code audit` | Relevant code windows, call hierarchy, active dispatch path |
| **[Supply Chain](#dependency-inventory--osv-advisory-checks)** | Dependency resolution, OSV CVE queries, and guarded fixes | `re deps`, `re vulns`, `re remediate`, `re cve-info` | Resolved package versions, vulnerability findings, `.xtbak` patches |
| **[AI Agent Gateway](#lean-mcp-setup--ghidra-borer--craft-anything-full-rea-replacement)** | Sub-1.4KB stdio MCP hub with on-demand tool discovery | `xt-forge --meta`, `xt_discover`, `xt_call`, `xt_batch` | Compact catalog (~350 tokens), schema on demand, tool execution |

---

## XT-Forge vs. Raw REA

Mounting a 229-tool reverse-engineering MCP server like raw **[REA](https://github.com/morluto/rea)** (`rea-agents mcp`, ~3.5 MB tool catalog) directly into an agent harness floods the prompt window, triggers tool-discovery loops, causes context exhaustion, and times out on multi-file audits, binary regressions, and dropped-connection recovery.

**`xt-forge`** solves this at both layers:
1. **Sub-1KB `--meta` Gateway (`1,384 B` / `346` tokens in Go, `98.5%` schema reduction):** Routes local `xt-forge` engines plus stateful upstream MCPs (**[Borer](https://github.com/imjustprism/borer)**, **REA**, **Craft Anything**) through 4 deterministic primitives (`xt_discover`, `xt_schema`, `xt_call`, `xt_batch`) with crash-safe idempotency journaling (`$XT_HOME/call_journal.json`).
2. **Direct Structural & Binary Analysis (`code_callers`, `code_audit`, `code_trace`, `re_diff`):** Replaces multi-turn `grep`, `read_file`, and `objdump` loops with single-call AST, CFG, and disassembly analysis.

<p align="center">
  <img src="docs/bench_9tier_charts.png" alt="XT-Forge 9-Tier 5-Rep Median Benchmark (Arm A vs B vs C)" width="100%" />
</p>

Across **9 tiers × 5 repetitions each (45 live runs per arm on DSH DeepSeek V4.1 Flash)**, **Standalone XT-Forge (Arm C)** achieved **42/45 (93.3%)** vs **XT-Forge + REA (Arm B, 34/45, 75.6%)** and **Raw REA (Arm A, 10/45, 22.2%)**:

| Benchmark Tier | Workload | Arm A: Raw REA<br/>Pass · Med Time · Tokens | Arm B: XT-Forge + REA<br/>Pass · Med Time · Tokens | Arm C: Standalone XT-Forge<br/>Pass · Med Time · Tokens |
| --- | --- | --- | --- | --- |
| **T1 · Find** | Symbol definition + production callers vs test/doc decoys | `0/5` · `60.03s` · `7,734` | `2/5` · `27.59s` · `6,587` | **`3/5` · `15.69s` · `6,378`** |
| **T2 · Fix** | Off-by-one retry budget bug fix + hidden tests | `3/5` · `87.85s` · `16,419` | `3/5` · `66.23s` · `13,422` | **`5/5` · `54.56s` · `13,928`** |
| **T3 · Recover** | Stateful MCP job submission across mid-flight drop | `1/5` · `90.03s` · `12,505` | **`5/5`** · `39.42s` · `5,792` | `4/5` · **`28.98s`** · `7,042` |
| **T4 · Defects** | Multi-file AST correctness audit (3 bugs + clean decoys) | `0/5` · `90.03s` · `8,984` | `5/5` · `54.93s` · `11,490` | **`5/5` · `36.06s` · `10,381`** |
| **T5 · Trace** | Active runtime path across `__init__.py` re-exports & config | `4/5` · `71.50s` · `10,033` | **`5/5` · `21.19s` · `5,915`** | `5/5` · `31.31s` · `10,596` |
| **T6 · Bin Diff** | Compiled ELF regression (`calc_v1` vs `calc_v2`, 10% → 5%) | `1/5` · `120.03s` · `23,922` | `4/5` · `75.90s` · `20,831` | **`5/5` · `69.73s` · `16,621`** |
| **T7 · Stripped Decompile** | `-O2 -s` ELF (`gatekeeper`): magic, `/ 7`, `% 13`, offsets `+0x8`/`+0x10`, `42` | `1/5` · `120.03s` · `24,992` | `5/5` · `69.20s` · `14,417` | **`5/5` · `51.05s` · `15,699`** |
| **T8 · Stripped Auth Diff** | `-O2 -s` ELF (`auth_v1` vs `auth_v2`): `0xa0 → 0x80` & `4 → 1` | `0/5` · `120.03s` · `21,911` | `3/5` · `116.91s` · `20,962` | **`5/5` · `80.02s` · `21,390`** |
| **T9 · Stripped C++ RTTI** | `-O2 -s` C++ ELF (`router_cpp`): 3 RTTI classes, `0x7A`, `(x^0x55)+19` | `0/5` · `120.03s` · `27,840` | `2/5` · `120.03s` · `19,838` | **`5/5` · `62.96s` · `27,778`** |

See **[Full 9-Tier Benchmark & Root-Cause Analysis](docs/BENCHMARKS.md)** and [raw JSON summary](benchmarks/nine_tier_5rep_summary.json) for why Standalone XT-Forge beats both Raw REA and XT-Forge + REA.

<p align="center">
  <img src="docs/assets/re-diff-decompile.gif" alt="Normalized Binary Diff, Reciprocal Math Decoding, Decompile & AST Audit" width="100%" />
</p>

---

## Why Use xt-forge

<p align="center">
  <img src="docs/assets/xtforge-overview-player.gif" alt="XT-Forge Workbench Overview" width="100%" />
</p>

| Everyday Problem | What `xt-forge` Gives You | Command / Guide |
| --- | --- | --- |
| **Bloated MCP catalogs eat 10K–40K+ tokens upfront** | `--meta` gateway exposes 4 meta-tools (`1,384 B` Go / `1,007 B` Python) across local tools + external MCPs | `xt-forge --meta` |
| **Massive RE/IDE MCPs (`ghidra`, `borer`, `craft-anything`) break context limits** | Connect once (`mcp connect`), SHA-256 trust-pin, and route stateful stdio calls lazily with 1-call `load_binary` optimization | `xt-forge mcp connect ghidra` |
| **100+ MB stripped ELFs, sectionless binaries (`e_shnum=0`), or Android Bionic `APS2` relocations OOM Ghidra** | Streaming RIP-relative `lea` string-anchor resolver (**2.7s** on 120.6 MB), O(1) windowed disassembly, `PT_DYNAMIC` sectionless ELF parser (**5.6ms**), and RSS-budgeted `process_vm_readv` probe | `xt-forge re deep-elf target.so --json` |
| **Multi-file bug hunts burn 10+ file reads and miss subtle defects** | One-call AST correctness auditor flags duplicate joins, boundary `<` vs `<=`, stale caches, and floor-div truncation with full function source | `xt-forge audit . --json` |
| **Re-exports and config dispatch tables hide the real handler** | Cross-module active-path tracer resolves `__init__.py` aliases and JSON/TOML/YAML/ENV dispatch keys | `xt-forge trace dispatch_request .` |
| **Comparing two binaries requires manual `objdump` diffing & magic-number math** | Normalized per-function instruction diffing, inline `.rodata` string annotation, and GCC/Clang reciprocal division decoding | `xt-forge diff v1.bin v2.bin --json` |
| **Regex grep misses callers, callees, and definitions** | Incremental `code_graph.db` call graph + Go LSP multiplexer pack structural slices and separate test shadows | `xt-forge callers MyFunc . --json` |
| **Supply-chain dependencies hide unpatched CVEs in manifests & binaries** | Offline manifest parsing + Go binary dependency extraction, live OSV vulnerability checks, and guarded version patching with `.xtbak` backups | `xt-forge re deps . && xt-forge re vulns .` |
| **Threat lookups stall behind API keys or rate limits** | Keyless NVD, FIRST EPSS, CISA KEV, InternetDB, GreyNoise, and CIRCL fan-out | `xt-forge intel cve CVE-2024-3094` |
| **Agents repeat failed fixes or duplicate mutating MCP calls on timeout** | Crash-safe `$XT_HOME/call_journal.json` (`idempotency_key` + `verify_tool`), negative memory, and `goal verify` | [MCP & Steering Guide](docs/MCP-GATEWAY-AND-STEERING.md) |

---

## Binary Inspection & Reverse Engineering

```sh
xt-forge re overview ./app --json
xt-forge re functions ./app --limit 20 --json
xt-forge re disasm-native ./app --target main --flow --json
xt-forge re xrefs-native ./app --target main --json
```

Replace `./app` and `main` with the file and function you want to inspect. For a universal Mach-O, use `--arch` to select a slice. For an IPA, use `--member` to select the app executable.

<p align="center">
  <img src="docs/assets/release-review/binary-walkthrough.gif" alt="Animated terminal walkthrough showing ELF identification, disassembly, and call tracking" width="100%" />
</p>

[Static Instructions](docs/assets/release-review/disassembly.svg) · [Overview Transcript](docs/assets/release-review/overview.txt) · [Disassembly Transcript](docs/assets/release-review/disassembly.txt) · [Cross-references Transcript](docs/assets/release-review/references.txt)

| Input | What You Can Inspect |
| --- | --- |
| **ELF** | Segments, sections, dependencies, symbol versions, function starts, and references to imports and data |
| **Windows PE** | EXE and DLL headers, imports, exports, resources, and CodeView debug records. Load a matching PDB to recover names and types. |
| **Mach-O** | Thin and universal images, per-slice metadata, function starts, Objective-C metadata, and selected hardening flags |
| **Containers & Managed Files** | IPA, DMG, static archives, APK/DEX, .NET metadata, and Unity IL2CPP metadata |
| **Firmware & Filesystems** | UEFI volumes and file entries, Android boot and OTA metadata, and NTFS transaction records |
| **Other Files** | File size, SHA-256, Shannon entropy, and bounded hex and string previews |

Native decoding includes x86, x86-64, arm64, and selected ARM32 and Thumb instructions. Structured pseudocode covers supported x86-64 and arm64 functions and reports why recovery stops when it cannot proceed. See the [workbench guide](docs/RE-WORKBENCH.md) for commands and format details.

---

## Dependency Inventory & OSV Advisory Checks

```sh
xt-forge re deps .
xt-forge re vulns .
xt-forge re remediate .
```

`re deps` reads dependency manifests (`go.mod`, `package.json`, `requirements.txt`, `Cargo.toml`, `pom.xml`) and extracts embedded build metadata from compiled Go binaries. `re vulns` sends resolved package names and versions to OSV and checks affected vulnerability ranges. `re remediate` previews candidate safe version updates; add `--write` to apply supported edits atomically with `.xtbak` backup preservation.

<p align="center">
  <img src="docs/assets/release-review/dependency-walkthrough.gif" alt="Animated terminal walkthrough showing dependency resolution and OSV vulnerability advisory remediation" width="100%" />
</p>

[Static Inventory](docs/assets/release-review/dependencies.svg) · [Sample Manifest](docs/assets/release-review/manifest.txt) · [Inventory Output](docs/assets/release-review/dependencies.txt) · [Remediation Preview](docs/assets/release-review/remediation.txt)

---

## Source Navigation & AST Call Graph

Search token-budgeted context windows across large codebases, resolve caller hierarchies via AST parsing, and trace active runtime dispatch chains without reading files repeatedly:

```sh
xt-forge route context . --query "authenticate dispatch token" --json
xt-forge callers authenticate . --json
xt-forge trace dispatch_request . --json
xt-forge code audit . --json
```

<p align="center">
  <img src="docs/assets/release-review/source-walkthrough.gif" alt="Animated terminal walkthrough showing context routing, callers hierarchy, and execution dispatch" width="100%" />
</p>

<p align="center">
  <img src="docs/assets/code-graph-context.gif" alt="Call Graph and Context Packing Demo" width="100%" />
</p>

[Static Source Navigation](docs/assets/release-review/source-navigation.svg) · [Context Search](docs/assets/release-review/source_context.txt) · [Callers Graph](docs/assets/release-review/source_callers.txt) · [Dispatch Trace](docs/assets/release-review/source_trace.txt)

---

## Lean MCP Setup + Ghidra, Borer & Craft Anything (Full REA Replacement)

Wire `xt-forge` once using `--meta`. Models discover tools on demand (`xt_discover` -> `xt_schema` -> `xt_call` or `xt_batch`), keeping initial prompt schema size at **1,384 bytes (346 tokens)** in Go (`1,007 B / 252 tok` in Python) — **94.4% smaller** vs Borer alone and **99.96% smaller** across all connected upstreams — and spilling oversized responses cleanly to `$XT_HOME/cache/artifacts/`.

<p align="center">
  <img src="docs/assets/release-review/mcp-walkthrough.gif" alt="Animated terminal walkthrough showing stdio MCP gateway initialization, tool discovery, and execution" width="100%" />
</p>

<p align="center">
  <img src="docs/assets/mcp-rea-craft.gif" alt="Connecting REA and Craft Anything through XT-Forge --meta Gateway" width="100%" />
</p>

| Tool | Use |
| --- | --- |
| `xt_discover` | Find tools on-demand by name, task, or keyword across native commands and connected upstreams |
| `xt_schema` | Retrieve detailed argument schemas for a discovered tool before invocation |
| `xt_call` | Execute an analysis tool with crash-safe journaling and automated error recovery |
| `xt_batch` | Submit multiple read-only tool calls concurrently to minimise round trips |

It natively connects, trust-pins, and optimizes **Ghidra MCP** (43 MCP tools compatible with `LaurieWired/GhidraMCP`, `pyghidra-mcp`, and `rea-agents`), **[Borer](https://github.com/imjustprism/borer)** (34 MCP tools + 111 `borer://` resources for certified decompilation and symbolic solving), and **[Craft Anything](https://github.com/storytold/craft-anything)** (300+ tools) behind **persistent stateful stdio sessions**, **1-call `path` auto-`load_binary` optimization**, and unified SHA-256 rug-pull checks:

```sh
# 1. Connect, injection-scan, and SHA-256 pin Ghidra, Borer, or Craft Anything once
xt-forge mcp connect ghidra --json
xt-forge mcp connect borer --json
xt-forge mcp connect craft-anything --json

# 2. One-call Ghidra & Borer execution (auto-loads binary + applies persistent C overlays)
xt-forge tool run ghidra rename_function '{"path":"/usr/bin/ls","old_name":"0x5620","new_name":"ls_entrypoint"}'
xt-forge tool run ghidra set_function_prototype '{"path":"/usr/bin/ls","function_address":"0x5620","prototype":"int ls_entrypoint(int argc, char **argv)"}'
xt-forge tool run ghidra decompile_function '{"path":"/usr/bin/ls","name":"ls_entrypoint"}'
xt-forge tool run borer query '{"path":"/usr/bin/ls","uri":"capabilities"}'

# 3. Or proxy any server directly with auto-refreshing dynamic toolsets
xt-forge mcp proxy --server ghidra
xt-forge mcp proxy --server borer
xt-forge mcp proxy --server craft-anything
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

<p align="center">
  <img src="docs/assets/mcp-token-savings.png" alt="MCP Prompt Schema Overhead Savings" width="100%" />
</p>

<details>
<summary><b>Live Terminal Walkthroughs: MCP Rug-Pull Audit, Intel Triage, RE Workbench, & Goal Gates</b></summary>

<br/>

**MCP Proxy and Rug-Pull Defense:**
![MCP Proxy and Rug-Pull Audit](docs/assets/mcp-proxy-audit.gif)

**Offline RE Checksec, Capa, and Keyless CVE/KEV Triage:**
![Offline RE Checksec, Capa, and Keyless CVE/KEV Triage](docs/assets/re-intel-triage.gif)

**Stateful Reverse Engineering Workbench:**
![Stateful Reverse Engineering Workbench](docs/assets/re-workbench.gif)

**Bounded Goal Check and Verification Gate:**
![Goal Check and Verification Gate](docs/assets/goal-vibe-check.gif)

**Keyless CVE/KEV Research Player:**
![CVE Research Player](docs/assets/cve-re-player.gif)

</details>

---

## Install on Linux, macOS, and Windows

### Option 1: One-Line Native Install (Builds Rust + Go + Links PATH + Syncs 24 Skills)

**Linux & macOS (Bash / Zsh):**

```sh
# Piped one-liner (clones into ~/.xt-forge-src if run outside a repo):
curl -fsSL https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.sh | bash

# Or from a local clone:
git clone https://github.com/XtrComSu/xt-forge-dev.git && cd xt-forge-dev && ./install.sh
```

**Windows (PowerShell 5.1+ / PowerShell 7+):**

```powershell
# Piped one-liner:
irm https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.ps1 | iex

# Or from a local clone:
git clone https://github.com/XtrComSu/xt-forge-dev.git; cd xt-forge-dev; .\install.ps1
```

### Option 2: Direct GitHub `npx` / `uv` / `pip` Install

```sh
# Node.js (18+) directly from GitHub (installs xt-forge, xtf, /xtf, and 24 XTF-* skills):
npx --yes github:XtrComSu/xt-forge-dev init

# Python (3.11+) wheel from GitHub Releases or git:
uv tool install git+https://github.com/XtrComSu/xt-forge-dev.git
# or: pip install git+https://github.com/XtrComSu/xt-forge-dev.git
```

### Option 3: Prebuilt Release Archives

Platform bundles with prebuilt Go and Rust components are attached to [GitHub Releases](https://github.com/XtrComSu/xt-forge-dev/releases):
- `xt-forge-0.4.8-linux-x86_64.tar.gz` (includes prebuilt `xtforge-native` Rust + `xtforge-hub` Go binaries)
- `xt-forge-0.4.8-darwin-arm64.tar.gz` (includes prebuilt `xtforge-hub` macOS arm64 binary)
- `xt-forge-0.4.8-windows-x86_64.zip` (includes prebuilt `xtforge-hub.exe` Windows x86_64 binary)

```sh
xt-forge --meta        # stdio MCP gateway (xt_discover, xt_schema, xt_call, xt_batch)
xt-forge doctor        # inspect workspace health, guard mode, and native engines
xt-forge skills        # list all 24 bundled XTF-* workflow skills
```

---

## Agent Self-Install Prompts

Want an AI coding agent (Claude Code, Codex CLI, OpenCode, DSH, Cursor) to install and verify `xt-forge` itself? Paste this prompt directly to the agent (see [prompts/install.md](prompts/install.md)):

> Install `xt-forge` (`https://github.com/XtrComSu/xt-forge-dev`) for this OS (`curl -fsSL https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.sh | bash` on Linux/macOS, `irm https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.ps1 | iex` on Windows PowerShell, or `npx --yes github:XtrComSu/xt-forge-dev init`), verify `xt-forge`, `xtf`, `/xtf`, and all 24 `XTF-*` skills are installed, register `xt-forge --meta` in the active MCP config if one exists, and run `xt-forge version --json` + `xt-forge doctor --json` + `tools/list` on `xt-forge --meta` to prove the setup works.

---

## Native Performance

Hot CLI paths run directly in Rust (`xtforge-native`) and Go (`xtforge-hub`), delivering 10x to 25x speedups over pure Python invocations:

| Workload | Native Engine | Native (ms) | Python (ms) | Speedup |
| --- | --- | ---: | ---: | ---: |
| `scan secrets xtforge` | Rust | 28.2 | 327.2 | **11.6x** |
| `route context xtforge --symbols` | Rust | 15.3 | 162.8 | **10.7x** |
| `code index xtforge` | Rust | 6.9 | 122.9 | **17.9x** |
| `codec entropy <elf>` | Rust | 7.7 | 197.5 | **25.8x** |
| `re checksec <elf>` | Go | 8.8 | 120.6 | **13.7x** |
| `re capa <elf>` | Go | 18.3 | 313.9 | **17.2x** |
| `intel sources` | Go | 6.0 | 109.3 | **18.2x** |

<p align="center">
  <img src="docs/assets/architecture-rust-go.png" alt="XT-Forge Hybrid Architecture" width="100%" />
</p>

<p align="center">
  <img src="docs/assets/release-review/workflow.svg" alt="Workflow showing input files, analysis steps, and CLI, MCP, or evidence output" width="100%" />
</p>

---

## 3-Tier Workflow Skills (`XTF-*`)

`xt-forge init` syncs **24 workflow skills** (8 Simple, 8 Complex, 8 Advanced) into `~/.agents/skills`, `~/.dsh/skills`, `~/.config/opencode/skills`, and `~/.claude/skills` so models pick exact commands instead of guessing:

| Tier | Count | Skills | Scope |
| --- | ---: | --- | --- |
| **Simple** | 8 | `XTF-RepoMap`, `XTF-CallGraph`, `XTF-CodeAudit`, `XTF-DispatchTrace`, `XTF-Notes`, `XTF-SecretScan`, `XTF-LogCompress`, `XTF-CVELookup` | Workspace maps, call graphs, multi-file AST correctness audits, active config/re-export dispatch traces, flash notes, secret/injection scans, log compression, keyless CVE lookup |
| **Complex** | 8 | `XTF-BinaryTriage`, `XTF-BinaryDiff`, `XTF-Disasm`, `XTF-LSPNavigate`, `XTF-IOCIntel`, `XTF-BinaryPatch`, `XTF-Unpack`, `XTF-DeepResearch` | Offline ELF/PE triage, normalized binary diffing + `.rodata` string annotation + reciprocal math decoding, disassembly/CFG/RTTI, Go LSP stdio navigation, IOC enrichment, guarded patching, ASAR/APK/HAR unpack, parallel research |
| **Advanced** | 8 | `XTF-Decompile`, `XTF-SwarmRE`, `XTF-MCPGateway`, `XTF-SessionRecovery`, `XTF-BugFix`, `XTF-CrashTriage`, `XTF-GoalLoop`, `XTF-MemoryEval` | XOR/stack string decoding, headless decompilation, parallel binary MapReduce & MCTS hypothesis solving, MCP rug-pull defense, crash-safe call journaling & idempotency recovery, verified bug fixes, minidump postmortem, bounded verification loops |

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
| **Kimi Code** | [integrations/kimi-code/](integrations/kimi-code/) | `mcp.json` (`xt-forge`, `ghidra`, `ida`), `config.toml` permission rules, and 24 `XTF-*` skills |
| **Qoder CLI** | [integrations/qoder/](integrations/qoder/) | `mcp.json` (`xt-forge --meta`, `ghidra`, `ida`) + `XTF-*` skill sync |
| **Gemini / Antigravity CLI** | [integrations/gemini-cli/](integrations/gemini-cli/) | `settings.json` MCP server wiring + `~/.gemini/skills` sync |
| **Cursor** | [integrations/cursor/](integrations/cursor/) | Drop-in `~/.cursor/mcp.json` / `.cursor/mcp.json` + skill sync |
| **Windsurf** | [integrations/windsurf/](integrations/windsurf/) | `mcp_config.json` for `xt-forge --meta`, `ghidra`, and `ida` |
| **Cline / Roo Code** | [integrations/cline/](integrations/cline/) | `cline_mcp_settings.json` with auto-approved `--meta` primitives |

---

## Common Commands

```sh
# Binary & Native Systems Reverse Engineering
xt-forge re overview ./app --json
xt-forge re functions ./app --limit 40 --json
xt-forge re disasm-native ./app --target main --flow --json
xt-forge re xrefs-native ./app --target main --json
xt-forge re diff bin_v1 bin_v2 --json
xt-forge re checksec ./app --json
xt-forge re deep-elf target.so --json

# Dependency Inventory & OSV Vulnerability Remediation
xt-forge re deps . --json
xt-forge re vulns . --json
xt-forge re remediate . --write

# Code Intelligence & AST Call Graph
xt-forge route context . --query "auth token dispatch" --json
xt-forge callers dispatch_request . --json
xt-forge trace dispatch_request . --json
xt-forge code audit . --json

# Keyless Threat Intelligence
xt-forge intel cve CVE-2024-3094 --json
xt-forge intel ip 1.1.1.1 --json

# MCP Gateway & Security
xt-forge --meta
xt-forge mcp connect ghidra --json
xt-forge mcp connect borer --json
xt-forge scan secrets .
```

---

## Documentation

- [Field Guide & Architecture Walkthrough](docs/GUIDE.md)
- [9-Tier Benchmark Methodology & Results](docs/BENCHMARKS.md)
- [CVE Research and Reverse Engineering Deep Dive](docs/CVE-AND-REVERSE-ENGINEERING.md)
- [24 Bundled 3-Tier Skills Reference (`XTF-*`)](docs/SKILLS.md)
- [MCP Meta-Gateway and Steering](docs/MCP-GATEWAY-AND-STEERING.md)
- [Rust + Go Hybrid Runtime Details](docs/ARCHITECTURE-RUST-GO.md)
- [RE Workbench Details](docs/RE-WORKBENCH.md)
- [Changelog](CHANGELOG.md)

## Tests

```sh
(cd native/xtforge-rs && cargo test --locked)
(cd native/xtforge-go && go test -race ./...)
python3 -m unittest discover -s tests
node --test plugins/xt-native/test/*.test.mjs
```

[MIT License](LICENSE) · **XT-OSS** · [xtrcom.xyz](https://xtrcom.xyz)
