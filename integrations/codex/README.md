# xt-forge for Codex CLI

![Codex CLI Setup Preview](codex-setup.gif)

Codex CLI connects cleanly via `~/.codex/config.toml` and reads project instructions from `AGENTS.md`. Wiring `xt-forge --meta` gives Codex access to 50 local tools while keeping the upfront schema at 0.90 KB. See the [Codex setup walkthrough](codex-setup.mp4) for a guided walkthrough alongside this setup.

## Quick Setup

1. Put `xt-forge` on PATH and install the `XTF-*` skills:

```sh
npx xt-forge init
# or from a local clone: ./install.sh
```

2. Append [`config.toml`](config.toml) to `~/.codex/config.toml`:

```sh
cat integrations/codex/config.toml >> ~/.codex/config.toml
```

3. Copy [`AGENTS.md`](AGENTS.md) to your repository root (or merge into your existing `AGENTS.md`):

```sh
cp integrations/codex/AGENTS.md /path/to/your/repo/AGENTS.md
```

4. Verify Codex can reach the MCP gateway and test a read-only pass:

```sh
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | xt-forge --meta
xt-forge guard mode explore
```

## Included Files

- [`config.toml`](config.toml): `[mcp_servers.xt_forge]` block with `xt-forge --meta` and `XT_PERM_MODE=ask`
- [`AGENTS.md`](AGENTS.md): compact Codex workflow rules for call-graph context, negative memory, and verification
- [`codex-setup.mp4`](codex-setup.mp4) and [`codex-setup.gif`](codex-setup.gif): Codex setup walkthrough
