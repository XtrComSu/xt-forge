# Repository Agent Guide (Codex Edition)

This repository uses `xt-forge` for fast symbol navigation, failure tracking, binary triage, and CVE enrichment.

## Fast Discovery

- Start with `xt_discover` (`xt-forge` MCP) or `./bin/xtforge code index .` followed by `./bin/xtforge route context . --query "<symbol>" --symbols` instead of dumping whole files.
- Batch related calls via `xt_batch` (up to 10 subcalls per turn) to avoid extra round trips.

## Failure Prevention & Checks

- Search prior mistakes before debugging: `./bin/xtforge mem search "<error>" --k 3`.
- Log dead ends with `mem record-failure --error-sig <CODE>` so later Codex sessions receive automatic `warnings`.
- Before concluding, run `./bin/xtforge goal check` and `./bin/xtforge scan secrets .`.
