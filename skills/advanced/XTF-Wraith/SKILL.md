---
name: XTF-Wraith
description: Recover obfuscated XOR/stack strings, run headless decompilation, and dry-run dynamic tracing.
---

# XTF-Wraith (Advanced Tier)

Push past stripped symbols and light string obfuscation by chaining byte-level decoders, headless decompilers, and guarded dynamic tracing.

## When to use
- Static `re strings` misses C2 endpoints, license checks, or keys constructed on the stack or XOR-encoded.
- Pseudocode or API trace output is needed before writing a full vulnerability analysis.

## Workflow
1. Sweep the binary for single-byte and rolling XOR strings or stack-constructed ASCII:
   ```sh
   xt-forge re xor target.bin
   xt-forge re stack-strings target.bin --min-len 5
   ```
2. Decompile a suspicious symbol via `rizin`/`radare2` or headless Ghidra through the Go hub:
   ```sh
   xt-forge re decompile target.bin --symbol check_auth --engine auto --max-lines 160
   ```
3. Preview capability-scoped dynamic tracing presets (`api_trace`, `tls_keys`, `crypto_hooks`, `crash_capture`) safely in dry-run:
   ```sh
   xt-forge re trace target.bin --preset api_trace --dry-run
   ```
4. Execute tracing only in an isolated test environment after passing the confirm token returned by dry-run.

## Guardrails
- `XT_PERM_MODE=explore` strictly blocks dynamic process execution; switch modes only inside sandboxed labs.
- Cross-check any speculative XOR decode (`xt-forge swarm solve`) against surrounding instructions before recording an IOC.
