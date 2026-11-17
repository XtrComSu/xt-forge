# XT-Forge Skills (`XTF-*`)

18 structured workflow skills organized into three operational tiers so models load targeted guidance without bloating prompt context.

## Tiers

| Tier | Count | Skills | Focus |
| --- | ---: | --- | --- |
| **Simple** | 6 | `XTF-Pulse`, `XTF-Compass`, `XTF-Spark`, `XTF-Shield`, `XTF-Lumen`, `XTF-Gage` | Daily navigation, flash memory, secret/injection scans, log squeeze, keyless CVE triage |
| **Complex** | 6 | `XTF-Vise`, `XTF-Trace`, `XTF-Beacon`, `XTF-Anvil`, `XTF-Sliver`, `XTF-Chisel` | Offline ELF/PE triage, CFG/RTTI, IOC enrichment, guarded patching, ASAR/APK/HAR, parallel research |
| **Advanced** | 6 | `XTF-Wraith`, `XTF-Cipher`, `XTF-Cartographer`, `XTF-Scalpel`, `XTF-Sentinel`, `XTF-Crucible` | Obfuscated string decoding, MCP rug-pull defense, verified repair loops, minidump postmortem, bounded orchestration |

## One-step install

Running either command syncs all 18 `XTF-*` folders into `~/.agents/skills`, `~/.dsh/skills`, `~/.config/opencode/skills`, and `~/.claude/skills`:

```sh
npx xt-forge init
# or from a local clone:
./install.sh
```

See [docs/SKILLS.md](../docs/SKILLS.md) for usage examples and trigger patterns.
