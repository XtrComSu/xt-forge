---
name: XTF-DeepResearch
description: Run concurrent cross-layer research across memory, call graphs, workspace files, and threat intel.
---

# XTF-DeepResearch (Complex Tier)

**Quick start:** `xt-forge research run "<topic>" --json`

Combine local repository knowledge, symbol relationships, recon history, and optional web/CVE intel in one structured pass.

## When to use
- Gathering full context before writing an architectural plan or security audit report.
- Checking whether an issue pattern or CVE already appeared in prior sessions.

## Workflow
1. Execute the Go concurrent research orchestrator across memory, code graph, and files:
   ```sh
   xt-forge research run "JWT validation bypass or signature mismatch" --json
   ```
2. Include CVE/public intel feeds when evaluating external dependencies or protocols:
   ```sh
   xt-forge research run "libexpat XML entity expansion" --web --json
   ```
3. Review fused results via unified search across local code and memory:
   ```sh
   xt-forge search "verifyToken" --json
   ```
4. Capture distilled conclusions as durable structured records:
   ```sh
   printf '%s\n' "Evidence summary..." | xt-forge mem put --title "JWT alg=none rejected in auth.go:88" --body-file - --tag security
   ```

## Guardrails
- Label every claim with file path and line number (`path:line`) verified after retrieval.
