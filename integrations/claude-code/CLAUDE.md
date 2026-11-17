# CLAUDE.md (xt-forge Integration)

You have the `xt-forge` MCP server mounted in `--meta` mode (`xt_discover`, `xt_schema`, `xt_call`, `xt_batch`).

## Working Agreements

- **Navigate by structure**: run `code index .` and `route context --symbols` before reading multiple files with `Read`.
- **Use batch calls**: bundle related read-only queries (`xt_batch`) when investigating across memory, code symbols, and CVEs.
- **Avoid repeat blind alleys**: run `mem search` on unfamiliar errors and record confirmed dead ends with `mem record-failure`.
- **Stay honest before done**: run `goal check` to catch scope drift or repeated errors, then verify changes with real tests or `goal verify`.
- **Security hygiene**: scan diffs for leaked secrets (`scan secrets .`) and audit third-party MCP servers (`mcp audit`) before trusting them.
