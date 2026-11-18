---
name: XTF-BinaryTriage
description: Perform offline ELF and PE binary triage for mitigations, sections, imports, and capabilities.
---

# XTF-BinaryTriage (Complex Tier)

**Quick start:** `xt-forge re inspect target.bin --json && xt-forge re checksec target.bin`

Assess an unknown executable offline in under a second before committing heavy decompiler time.

## When to use
- Auditing compiled binaries (`ELF`, `PE`/`DLL`, Mach-O) for hardening gaps or suspicious behavior.
- Comparing release binaries or investigating stripped executables safely (read-only).

## Workflow
1. Identify format, architecture, entrypoints, and sections:
   ```sh
   xt-forge re inspect target.bin --json
   xt-forge re sections target.bin --json
   ```
2. Audit binary security mitigations (ASLR, DEP/NX, PIE, RELRO, stack canaries, CFG):
   ```sh
   xt-forge re checksec target.bin
   ```
3. Run behavioral capability detection across imports and string indicators:
   ```sh
   xt-forge re capa target.bin
   ```
4. For Windows PE files, inspect imports, exports, headers, and Authenticode presence:
   ```sh
   xt-forge re pe imports target.exe
   xt-forge re pe exports target.dll
   ```
5. Pull ASCII/UTF-16 strings and compute section entropy to spot packed regions:
   ```sh
   xt-forge re strings target.bin --min-len 6
   ```

## Guardrails
- Keep analysis strictly read-only (`guard` read-only mode works out of the box).
- Treat high-entropy sections paired with minimal clear strings as packed or encrypted until proven otherwise.
