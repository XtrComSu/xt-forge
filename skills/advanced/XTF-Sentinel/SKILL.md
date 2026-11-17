---
name: XTF-Sentinel
description: Govern long-running bounded loops and recurring background monitors with hard verification gates.
---

# XTF-Sentinel (Advanced Tier)

Drive bounded iterative work or restart-safe recurring checks without unbounded retries or self-certified completion claims.

## When to use
- Running multi-round autonomous tasks under `/goal`, `goal run`, or `loop schedule`.
- Monitoring tests, builds, or security feeds at fixed intervals cleanly.

## Workflow
1. Check existing session guardrails and memory warnings before starting:
   ```sh
   xt-forge guard status
   xt-forge goal check --objective "Target deliverable" --criteria "tests pass; zero secret leaks"
   ```
2. Register recurring safe probes via the Go loop daemon when needed:
   ```sh
   xt-forge loop schedule 5m --cmd "xt-forge doctor --json"
   xt-forge loop list
   ```
3. Bind completion strictly to objective verification commands (`/goal check <cmd>` or `goal run --verify "<cmd>"`):
   ```sh
   xt-forge goal verify --verify "cargo test && go test ./..." --body-file marker.txt
   ```
4. Tear down temporary loops cleanly when finished:
   ```sh
   xt-forge loop stop all
   ```

## Guardrails
- Never claim completion without fresh verification exit code `0` observed after the final edit.
- Disable or stop scheduled loops if `loop list` shows stalled runs.
