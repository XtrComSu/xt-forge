# XT-Forge Skill Suite (`XTF-*`)

XT-Forge ships 18 original workflow skills grouped into **Simple**, **Complex**, and **Advanced** tiers. Each skill pairs exact `xt-forge` commands with clear verification guardrails so your agent picks the sharpest local tool on the first step instead of guessing shell one-liners.

## Installation

Install all 18 skills alongside the `xt-forge` CLI and `/xtf` slash command in one command:

```sh
npx xt-forge init
```

Or run `./install.sh` from a cloned checkout. To inspect the catalog directly from any terminal:

```sh
xt-forge skills
```

## Skill tiers

### Simple (6 skills)

Daily low-overhead habits for context discipline, quick navigation, secret safety, and fast vulnerability lookup.

| Skill | Job | Core commands | Source |
| --- | --- | --- | --- |
| **XTF-Pulse** | Budgeted workspace map and slice peeks | `route context`, `route find`, `route grep`, `route peek` | [SKILL.md](../skills/simple/XTF-Pulse/SKILL.md) |
| **XTF-Compass** | Symbol callers, outlines, and LSP queries | `code index`, `code graph`, `code outline`, `code lsp` | [SKILL.md](../skills/simple/XTF-Compass/SKILL.md) |
| **XTF-Spark** | Hot scratchpad state across turns | `flash set`, `flash pin`, `/mp`, `/mw`, `/mu` | [SKILL.md](../skills/simple/XTF-Spark/SKILL.md) |
| **XTF-Shield** | Pre-share secrets and injection defense | `scan secrets`, `scan injection`, `scan mcp` | [SKILL.md](../skills/simple/XTF-Shield/SKILL.md) |
| **XTF-Lumen** | Log collapse preserving error traces | `compress L1`, `route errors` | [SKILL.md](../skills/simple/XTF-Lumen/SKILL.md) |
| **XTF-Gage** | Keyless CVE, EPSS, and CISA KEV lookup | `intel cve`, `intel search`, `intel kev` | [SKILL.md](../skills/simple/XTF-Gage/SKILL.md) |

### Complex (6 skills)

Multi-step investigation loops across static binaries, network indicators, packaged apps, and concurrent codebase research.

| Skill | Job | Core commands | Source |
| --- | --- | --- | --- |
| **XTF-Vise** | Offline ELF/PE hardening and capability audit | `re inspect`, `re checksec`, `re capa`, `re pe` | [SKILL.md](../skills/complex/XTF-Vise/SKILL.md) |
| **XTF-Trace** | Disassembly, CFG, and C++ RTTI recovery | `re graph`, `re disasm`, `re cfg`, `re rtti` | [SKILL.md](../skills/complex/XTF-Trace/SKILL.md) |
| **XTF-Beacon** | Extract binary IOCs and enrich upstream | `re ioc`, `intel ip`, `intel domain`, `intel hash` | [SKILL.md](../skills/complex/XTF-Beacon/SKILL.md) |
| **XTF-Anvil** | Binary diffing and token-guarded patching | `re diff`, `re patch --dry-run`, `re patch --confirm` | [SKILL.md](../skills/complex/XTF-Anvil/SKILL.md) |
| **XTF-Sliver** | Pure-Go ASAR, Android APK, and HAR/SAZ teardown | `re asar`, `re apk`, `re netcap` | [SKILL.md](../skills/complex/XTF-Sliver/SKILL.md) |
| **XTF-Chisel** | Parallel research across code, memory, and CVEs | `research run`, `search`, `mem put` | [SKILL.md](../skills/complex/XTF-Chisel/SKILL.md) |

### Advanced (6 skills)

End-to-end hardening, obfuscated binary recovery, MCP schema trust enforcement, crash triage, and proof-gated loops.

| Skill | Job | Core commands | Source |
| --- | --- | --- | --- |
| **XTF-Wraith** | XOR/stack strings, headless decompile, safe trace | `re xor`, `re stack-strings`, `re decompile`, `re trace` | [SKILL.md](../skills/advanced/XTF-Wraith/SKILL.md) |
| **XTF-Cipher** | MCP rug-pull audit, proxy, and sub-1KB gateway | `mcp audit`, `mcp proxy`, `xt-forge --meta` | [SKILL.md](../skills/advanced/XTF-Cipher/SKILL.md) |
| **XTF-Cartographer** | Cross-module bug localization with scope checks | `code graph`, `goal check`, `goal verify` | [SKILL.md](../skills/advanced/XTF-Cartographer/SKILL.md) |
| **XTF-Scalpel** | Crash minidump postmortem and recon reporting | `re crash`, `re symbols`, `recon new`, `recon finding` | [SKILL.md](../skills/advanced/XTF-Scalpel/SKILL.md) |
| **XTF-Sentinel** | Bounded goal loops and daemonized monitors | `loop schedule`, `goal verify`, `guard status` | [SKILL.md](../skills/advanced/XTF-Sentinel/SKILL.md) |
| **XTF-Crucible** | Memory linking, taste calibration, eval tracking | `mem link`, `taste learn`, `eval record` | [SKILL.md](../skills/advanced/XTF-Crucible/SKILL.md) |

## Interactive walkthrough

For a visual walkthrough of XT-Forge tool routing and MCP gateway workflows, watch [xtforge-overview.mp4](videos/xtforge-overview.mp4) and explore the harness guides in [GUIDE.md](GUIDE.md).
