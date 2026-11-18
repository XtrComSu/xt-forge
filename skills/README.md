# XT-Forge Skills (`XTF-*`)

18 self-explanatory workflow skills organized into three operational tiers so models and humans immediately know which skill to run without bloating prompt context.

## Tiers

| Tier | Count | Skills | Focus |
| --- | ---: | --- | --- |
| **Simple** | 6 | `XTF-RepoMap`, `XTF-CallGraph`, `XTF-Notes`, `XTF-SecretScan`, `XTF-LogCompress`, `XTF-CVELookup` | Daily repo maps, call graphs, flash notes, secret/injection scans, log compression, keyless CVE lookup |
| **Complex** | 6 | `XTF-BinaryTriage`, `XTF-Disasm`, `XTF-IOCIntel`, `XTF-BinaryPatch`, `XTF-Unpack`, `XTF-DeepResearch` | Offline ELF/PE triage, disassembly/CFG, IOC enrichment, guarded hex patching, ASAR/APK/HAR unpack, parallel research |
| **Advanced** | 6 | `XTF-Decompile`, `XTF-MCPGateway`, `XTF-BugFix`, `XTF-CrashTriage`, `XTF-GoalLoop`, `XTF-MemoryEval` | String decoding/decompilation, MCP rug-pull defense, verified bug fixes, minidump postmortem, bounded loops, memory & evals |

## One-step install

Running either command syncs all 18 `XTF-*` folders into `~/.agents/skills`, `~/.dsh/skills`, `~/.config/opencode/skills`, and `~/.claude/skills`:

```sh
npx xt-forge init
# or from a local clone:
./install.sh
```

See [docs/SKILLS.md](../docs/SKILLS.md) for usage examples and trigger patterns.
