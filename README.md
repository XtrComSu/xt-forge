<div align="center">
  <img src="docs/assets/xtforge-icon.png" alt="XT-Forge Icon" width="112" />
  <h1>xt-forge</h1>
  <p><strong>Local agent workbench for call-graph context, offline reverse engineering, keyless CVE intel, and sub-1KB MCP routing.</strong></p>
  <p>Built in Rust, Go, and zero-dependency Python.</p>
</div>

![XT-Forge Overview](docs/assets/overview-showcase.gif)

---

## Why Use xt-forge

Most coding and security agent setups burn thousands of context tokens on massive tool schemas, blind grep searches, and dead-end retries. `xt-forge` puts a fast, local workbench on your PATH with native Rust/Go performance and zero third-party runtime dependencies:

| Everyday Problem | What `xt-forge` Gives You | Command |
| --- | --- | --- |
| Bloated MCP catalogs eat 10K+ tokens per turn | `--meta` gateway exposes 4 meta-tools (`0.90 KB`) wrapping 50 local tools | `xt-forge --meta` |
| Regex grep misses callers, callees, and definitions | Incremental call graph and LSP multiplexer pack structural slices | `xt-forge code index .` |
| Binary triage usually drags in heavy GUI tools | Offline ELF/PE/Mach-O headers, `checksec`, `capa`, RTTI, CFG, XOR, ASAR, APK, HAR | [CVE & RE Guide](docs/CVE-AND-REVERSE-ENGINEERING.md) |
| Threat lookups stall behind API keys or rate limits | Keyless NVD, FIRST EPSS, CISA KEV, InternetDB, GreyNoise, and CIRCL | `xt-forge intel cve CVE-2024-3094` |
| Agents repeat failed fixes or claim done unverified | Negative failure memory, drift checks, and command-backed `goal verify` | [MCP & Steering Guide](docs/MCP-GATEWAY-AND-STEERING.md) |
| External MCP servers mutate schemas or inject prompts | SHA-256 trust pinning (`mcp audit`), guard proxy, and injection scanning | `xt-forge mcp audit` |

---

## Install & Run in Seconds

Node.js (`npx`) or Bash gives you global `xt-forge`, `xtf`, and slash command `/xtf` support immediately:

```sh
# Option A: instant global CLI, /xtf slash integration, and XTF-* skills via npx
npx xt-forge init

# Option B: build Rust + Go native engines from a local clone and link onto PATH
git clone https://github.com/XtrComSu/xt-forge.git && cd xt-forge
./install.sh
```

Launch the sub-1KB MCP gateway from any terminal, or call `/xtf --meta` inside supported agent harnesses:

```sh
xt-forge --meta        # stdio MCP gateway (xt_discover, xt_schema, xt_call, xt_batch)
xt-forge doctor        # check workspace health, guard mode, and native engines
xt-forge skills        # list the 18 bundled XTF-* workflow skills
```

When native Rust (`xtforge-native`) and Go (`xtforge-hub`) binaries are built, hot paths and concurrent daemons dispatch natively; otherwise `xt-forge` runs on zero-dependency Python 3.11+ (`XT_FORCE_PYTHON=1` selects pure Python anytime).

---

## 3-Tier Workflow Skills (`XTF-*`)

`xt-forge init` syncs **18 structured workflow skills** across three tiers into `~/.agents/skills`, `~/.dsh/skills`, `~/.config/opencode/skills`, and `~/.claude/skills` so models pick exact commands instead of guessing:

| Tier | Count | Skills | Scope |
| --- | ---: | --- | --- |
| **Simple** | 6 | `XTF-Pulse`, `XTF-Compass`, `XTF-Spark`, `XTF-Shield`, `XTF-Lumen`, `XTF-Gage` | Workspace maps, call graphs, flash scratchpad, secret/injection scans, log squeeze, keyless CVE triage |
| **Complex** | 6 | `XTF-Vise`, `XTF-Trace`, `XTF-Beacon`, `XTF-Anvil`, `XTF-Sliver`, `XTF-Chisel` | Offline ELF/PE triage, CFG/RTTI, binary IOC enrichment, guarded patching, ASAR/APK/HAR, parallel research |
| **Advanced** | 6 | `XTF-Wraith`, `XTF-Cipher`, `XTF-Cartographer`, `XTF-Scalpel`, `XTF-Sentinel`, `XTF-Crucible` | XOR/stack decoding, headless decompile, MCP rug-pull defense, minidump postmortem, bounded verification loops |

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

## Lean MCP Setup

Wire `xt-forge` once using `--meta`. Models discover tools on demand (`xt_discover` -> `xt_schema` -> `xt_call` or `xt_batch`), keeping initial prompt schema size at **0.90 KB** (`94%` smaller than mounting all 50 individual schemas upfront) and spilling large outputs cleanly to `$XT_HOME/cache/artifacts/`.

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

![MCP Prompt Schema Overhead](docs/assets/mcp-token-savings.png)

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

# Guardrails, Failure Memory & Security Scanning
xt-forge guard mode explore|ask|auto
xt-forge mem search "TLS" --k 3 --json
xt-forge scan secrets .
xt-forge mcp audit --server upstream --cmd "npx -y @org/server" --trust-on-first
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

Full dispatch details live in [docs/ARCHITECTURE-RUST-GO.md](docs/ARCHITECTURE-RUST-GO.md).

---

## Documentation

![XT-Forge Hybrid Architecture](docs/assets/architecture-rust-go.png)

- [Field Guide & Architecture Walkthrough](docs/GUIDE.md)
- [CVE Research and Reverse Engineering Deep Dive](docs/CVE-AND-REVERSE-ENGINEERING.md)
- [3-Tier Skills Reference (`XTF-*`)](docs/SKILLS.md)
- [MCP Meta-Gateway and Steering](docs/MCP-GATEWAY-AND-STEERING.md)
- [Rust + Go Hybrid Runtime Details](docs/ARCHITECTURE-RUST-GO.md)
- [RE Workbench Details](docs/RE-WORKBENCH.md)
- [0.4.0 Release Notes](docs/RELEASE-0.4.0.md)

## Tests

```sh
cd native/xtforge-rs && cargo test && cd ../..
cd native/xtforge-go && go test -race ./... && cd ../..
python3 -m unittest discover -s tests
node --test plugins/xt-native/test/*.test.mjs
python3 scripts/verify_artifact.py && python3 scripts/verify_dedup_matrix.py && python3 scripts/verify_knowledge.py && python3 scripts/verify_recall.py
```

MIT Licensed.
