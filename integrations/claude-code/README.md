# xt-forge for Claude Code

![Claude Code Setup Preview](claude-code-setup.gif)

Claude Code supports project-scoped `.mcp.json` discovery, `/xtf` slash commands (`~/.claude/commands/xtf.md`), and repository playbooks in `CLAUDE.md`. Using `xt-forge --meta` exposes just four tools (`xt_discover`, `xt_schema`, `xt_call`, `xt_batch`) so you get call-graph routing, reverse engineering, CVE intel, and anti-drift checks without bloating your context window. See [claude-code-setup.mp4](claude-code-setup.mp4) for a visual walkthrough alongside these setup steps.

## Quick Setup

1. Install `xt-forge` on PATH, `/xtf`, and all `XTF-*` skills into `~/.claude/skills`:

```sh
npx xt-forge init
# or from a local clone: ./install.sh
```

2. Copy `.mcp.json` and `CLAUDE.md` into your target project directory, or register `xt-forge --meta` at user scope:

```sh
cp integrations/claude-code/.mcp.json integrations/claude-code/CLAUDE.md /path/to/your/project/
# or via CLI:
claude mcp add xt-forge xt-forge --meta
```

3. Pin any external MCP servers you run so silent schema mutations are caught immediately:

```sh
xt-forge mcp audit --server fs-helper --cmd "npx -y @org/mcp-fs" --trust-on-first
xt-forge mcp trust --json
```

## Included Files

- [`.mcp.json`](.mcp.json): drop-in project MCP config running `xt-forge --meta`
- [`CLAUDE.md`](CLAUDE.md): Claude Code project instructions covering symbol packing, RE workflows, and `goal verify`
- [`claude-code-setup.mp4`](claude-code-setup.mp4) and [`claude-code-setup.gif`](claude-code-setup.gif): Claude Code walkthrough
