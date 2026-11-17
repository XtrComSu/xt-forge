# xt-forge for DSH (DeepSeek Harness)

![DSH Setup Preview](dsh-setup.gif)

This edition integrates cleanly with DSH (`cordis`) profiles, native `/xtf` slash commands, and account-isolated harness workspaces. See the [DSH setup walkthrough video](dsh-setup.mp4) alongside this guide if you want a visual step-by-step tour.

## Why DSH users use this setup

- **One-command PATH and `/xtf` setup**: running `npx xt-forge init` (or `./install.sh`) links `xt-forge` globally, installs `/xtf` into `~/.dsh/commands/xtf.md`, and syncs all 18 `XTF-*` workflow skills into `~/.dsh/skills`.
- **Native `/xtf --meta` invocation**: invoke `/xtf --meta` inside DSH or run `xt-forge --meta` in any shell to wire the 0.90 KB MCP gateway without editing brittle script paths.
- **No hallucinated tool names**: `xt-forge prompt inject` inspects the active profile and reports the exact tools available in the session.

## Quick Setup

1. Install binaries, `/xtf`, and `XTF-*` skills:

```sh
npx xt-forge init
# or from a local clone: ./install.sh
```

2. Add the MCP block from [`mcp-patch.json`](mcp-patch.json) into your DSH profile config (`"command": "xt-forge", "args": ["--meta"]`) and copy [`AGENTS.md`](AGENTS.md) into your workspace root.

3. Verify the live mount and switch session guard modes as needed:

```sh
xt-forge mcp status --probe
xt-forge guard mode explore   # read-only search, RE, CVE lookups
xt-forge guard mode ask       # default: require confirm token on writes
xt-forge guard mode auto      # allow edits inside allowlisted workspace
```

## Included Files

- [`mcp-patch.json`](mcp-patch.json): DSH / `cordis` MCP entry wired as `xt-forge --meta`
- [`AGENTS.md`](AGENTS.md): concise DSH system instructions using `xt-forge` and `/xtf`
- [`dsh-setup.mp4`](dsh-setup.mp4) and [`dsh-setup.gif`](dsh-setup.gif): embedded DSH setup visual walkthrough
