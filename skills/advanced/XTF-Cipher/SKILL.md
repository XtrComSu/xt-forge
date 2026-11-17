---
name: XTF-Cipher
description: Audit external MCP servers against schema rug-pulls and wrap tools behind the sub-1KB gateway.
---

# XTF-Cipher (Advanced Tier)

Protect your agent runtime from prompt-poisoned MCP tool descriptions, post-install schema mutations (rug-pulls), and bloated tool catalogs.

## When to use
- Wiring a new third-party MCP server into DSH, OpenCode, Codex, or Claude Code.
- Slashing MCP token overhead from 10K-40K schema tokens down to the 4-tool gateway (`xt-forge --meta`).

## Workflow
1. Measure current MCP context overhead and inspect proxy recommendations:
   ```sh
   xt-forge mcp status
   xt-forge mcp advice
   ```
2. Audit and trust-pin a candidate upstream MCP server on first verification:
   ```sh
   xt-forge mcp audit --server upstream --cmd "npx -y @org/mcp-server" --trust-on-first
   ```
3. Re-audit before reuse; any post-pin mutation to tool schemas or hidden shell instructions triggers non-zero rug-pull failure:
   ```sh
   xt-forge mcp audit --server upstream --cmd "npx -y @org/mcp-server"
   ```
4. Serve XT-Forge itself in ultra-compact meta-tool mode (4 tools: `xt_discover`, `xt_schema`, `xt_call`, `xt_batch`):
   ```sh
   xt-forge --meta
   ```
5. Wrap untrusted upstreams behind the Go trust-enforcing proxy:
   ```sh
   xt-forge mcp proxy --prefix ext --cmd "node server.js"
   ```

## Guardrails
- Never bypass a rug-pull checksum mismatch without inspecting the raw diff between schema versions.
