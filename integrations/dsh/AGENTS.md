# xt-forge Workspace Contract (DSH Edition)

Use `xt-forge` on PATH (or `/xtf <command>` directly in DSH) for codebase call graphs, binary analysis, CVE checks, and memory persistence.

## Default Workflow

1. Configure or inspect the sub-1KB MCP gateway anytime with `/xtf --meta` or `xt-forge --meta`.
2. Index call/import structure once: `xt-forge code index .`
3. Pack relevant files and callers instead of dumping whole directories: `xt-forge route context . --query "<topic>" --symbols`
4. Check prior session mistakes before retrying fixes: `xt-forge mem search "<topic>" --k 3 --json`
5. Record failures immediately so they surface next time: `xt-forge mem record-failure --title "<short claim>" --error-sig "<CODE>" --body "<why>"`
6. Verify against criteria before saying done: `xt-forge goal check` and `xt-forge goal verify`

## Security & Privacy Rules

- Run `xt-forge scan secrets .` before sharing diffs or logs.
- Use `--meta` when connecting external MCP catalogs, and audit untrusted servers with `xt-forge mcp audit <cmd>` before trusting.
- Never bypass `XT_PERM_MODE=explore` or confirm tokens.
