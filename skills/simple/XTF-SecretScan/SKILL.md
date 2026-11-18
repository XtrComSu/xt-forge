---
name: XTF-SecretScan
description: Scan repositories, tool descriptions, and MCP schemas for leaked secrets or prompt injection.
---

# XTF-SecretScan (Simple Tier)

**Quick start:** `xt-forge scan secrets .`

Run fast deterministic security checks before commits, releases, log sharing, or connecting unfamiliar MCP servers.

## When to use
- Preparing a repository or patch for publication or sharing.
- Before trusting untrusted Markdown files, logs, or external MCP JSON tool manifests.

## Workflow
1. Scan the repository for keys, tokens, private paths, and credentials (masked by default):
   ```sh
   xt-forge scan secrets .
   ```
2. Scan untrusted documents or downloaded dumps for hidden prompt-injection directives:
   ```sh
   xt-forge scan injection untrusted.md
   ```
3. Scan a candidate MCP tool schema file for hidden exfiltration or shell-pipe instructions:
   ```sh
   xt-forge scan mcp server-schema.json
   ```

## Guardrails
- Treat non-zero exit codes from `scan secrets` or `scan mcp` as release blockers until resolved.
- Never bypass masking flags when pasting findings into reports.
