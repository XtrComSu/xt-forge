# xt-forge for Kimi Code

Kimi Code (`~/.kimi-code`) reads MCP servers from `~/.kimi-code/mcp.json`, permissions and hooks from `~/.kimi-code/config.toml`, and `XTF-*` skills from `~/.kimi-code/skills/`.

## Quick Setup

1. Install `xt-forge` and sync all 24 `XTF-*` skills to `~/.kimi-code/skills`:

```sh
npx --yes github:XtrComSu/xt-forge init
# or from a local clone: ./install.sh
```

2. Add `xt-forge`, `ghidra` (Sober-hardened RE), and `ida` (IDA Pro + Borer fallback) to `~/.kimi-code/mcp.json` (see [`mcp.json`](mcp.json)).

3. Allow read-only workbench & RE calls in `~/.kimi-code/config.toml` while keeping binary patch writes gated behind `ask` (see [`config.snippet.toml`](config.snippet.toml)).
