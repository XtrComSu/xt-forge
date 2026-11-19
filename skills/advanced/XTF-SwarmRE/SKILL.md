---
name: XTF-SwarmRE
description: Run high-concurrency binary MapReduce analysis and MCTS speculative hypothesis solving across complex targets.
---

# XTF-SwarmRE (Advanced Tier)

**Quick start:** `xt-forge swarm map <binary> --workers 8 --json`

Coordinate parallel reverse-engineering sweeps across large binaries and rank competing root-cause or vulnerability hypotheses using Monte Carlo Tree Search (MCTS).

## When to use
- Triaging stripped or multi-hundred-function binaries where sequential function inspection is too slow.
- Exploring competing exploitability or behavioral hypotheses (`swarm mcts`) with evidence scoring.

## Workflow
1. Fan out parallel function/section/string/entropy extraction across worker goroutines:
   ```sh
   xt-forge swarm map path/to/target.bin --workers 8 --json
   ```
2. Run MCTS hypothesis evaluation over candidate functions or crash paths:
   ```sh
   xt-forge swarm mcts path/to/target.bin --goal "locate auth bypass or command injection sink" --rounds 12 --json
   ```
3. Persist verified high-confidence findings into the stateful overlay and recon ledger:
   ```sh
   xt-forge re annotate path/to/target.bin --rva 0x4012a0 --name "auth_check_vuln" --comment "Bypass when flag==2"
   xt-forge recon finding --target target.bin --severity high --title "Auth check bypass at 0x4012a0"
   ```

## Guardrails
- Always verify top-ranked MCTS hypotheses with `re decompile` or `re disasm` before recording a high-severity finding.
