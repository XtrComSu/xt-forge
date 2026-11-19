# XT-Forge Skills (`XTF-*`)

24 self-explanatory workflow skills organized into three operational tiers (8 Simple, 8 Complex, 8 Advanced) so models and humans immediately know which skill to run without bloating prompt context.

## Tiers

| Tier | Count | Skills | Focus |
| --- | ---: | --- | --- |
| **Simple** | 8 | `XTF-RepoMap`, `XTF-CallGraph`, `XTF-CodeAudit`, `XTF-DispatchTrace`, `XTF-Notes`, `XTF-SecretScan`, `XTF-LogCompress`, `XTF-CVELookup` | Daily repo maps, call graphs, AST correctness audits, active config/re-export dispatch traces, flash notes, secret/injection scans, log compression, keyless CVE lookup |
| **Complex** | 8 | `XTF-BinaryTriage`, `XTF-BinaryDiff`, `XTF-Disasm`, `XTF-LSPNavigate`, `XTF-IOCIntel`, `XTF-BinaryPatch`, `XTF-Unpack`, `XTF-DeepResearch` | Offline ELF/PE triage, normalized binary diffing + reciprocal math decoding, disassembly/CFG, Go LSP stdio navigation, IOC enrichment, guarded hex patching, ASAR/APK/HAR unpack, parallel research |
| **Advanced** | 8 | `XTF-Decompile`, `XTF-SwarmRE`, `XTF-MCPGateway`, `XTF-SessionRecovery`, `XTF-BugFix`, `XTF-CrashTriage`, `XTF-GoalLoop`, `XTF-MemoryEval` | String decoding/decompilation, binary MapReduce + MCTS hypothesis solving, MCP rug-pull defense, crash-safe call journaling & idempotency recovery, verified bug fixes, minidump postmortem, bounded loops, memory & evals |

## One-step install

Running either command syncs all 24 `XTF-*` folders into `~/.agents/skills`, `~/.dsh/skills`, `~/.config/opencode/skills`, and `~/.claude/skills`:

```sh
./install.sh
# or via npx directly from GitHub:
npx --yes github:XtrComSu/xt-forge init
```

See [docs/SKILLS.md](../docs/SKILLS.md) for usage examples and trigger patterns.
