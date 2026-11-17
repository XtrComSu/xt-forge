# xt-forge Workspace Contract (DSH Edition)

Use the local launcher (`./bin/xtforge` or `$HOME/.dsh/agy-accounts/<id>/bin/xtforge`) for codebase lookup, binary analysis, CVE checks, and memory persistence.

## Default Workflow

1. Index call/import structure once: `./bin/xtforge code index .`
2. Pack relevant files + callers instead of reading whole directories: `./bin/xtforge route context . --query "<topic>" --symbols`
3. Check prior session mistakes before retrying fixes: `./bin/xtforge mem search "<topic>" --k 3 --json`
4. Record failures immediately so they surface next time: `./bin/xtforge mem record-failure --title "<short claim>" --error-sig "<CODE>" --body "<why>"`
5. Verify against criteria before saying done: `./bin/xtforge goal check` and `./bin/xtforge goal verify`

## Security & Privacy Rules

- Run `./bin/xtforge scan secrets .` before sharing diffs or logs.
- Use `--meta` when connecting external or heavy MCP catalogs, and audit untrusted servers with `./bin/xtforge mcp audit <cmd>` before trusting.
- Never bypass `XT_PERM_MODE=explore` or confirm tokens.
