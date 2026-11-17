---
name: XTF-Lumen
description: Collapse noisy build, test, and runtime logs into clean digests without dropping error lines.
---

# XTF-Lumen (Simple Tier)

Turn thousands of lines of verbose compiler or CI output into compact, error-preserving digests.

## When to use
- Build or test suites fail with repetitive output drowning the actual stack trace.
- Reading oversized log files cleanly under strict context budgets.

## Workflow
1. Extract error windows directly from a build or test log:
   ```sh
   xt-forge route errors build.log --max-lines 40 --token-budget 800
   ```
2. Squeeze a verbose log at progressive levels (`L0` structural, `L1` balanced, `L2` tight, `L3` ultra):
   ```sh
   xt-forge compress L1 --path test-output.log --stats
   ```
3. Pipe live output directly into compression:
   ```sh
   cargo test 2>&1 | xt-forge compress L2 --text-file -
   ```

## Guardrails
- Verify the final error trace line directly before applying fixes based on digested summaries.
