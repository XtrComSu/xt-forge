---
name: XTF-BinaryPatch
description: Diff two binaries structurally and apply token-guarded hex patches safely with backups.
---

# XTF-BinaryPatch (Complex Tier)

**Quick start:** `xt-forge re diff a.bin b.bin` / `xt-forge re patch copy.bin --rva 0x1040 --hex "9090" --dry-run`

Compare builds byte-for-byte or symbol-for-symbol and test safe, reversible binary patches under explicit confirmation tokens.

## When to use
- Investigating security patches between vendor binary versions (N-day patch diffing).
- Applying minimal byte patches in defensive validation or controlled lab environments.

## Workflow
1. Diff two binary revisions across headers, sections, symbols, and imports:
   ```sh
   xt-forge re diff original.bin patched.bin
   ```
2. Inspect exact bytes around a target file offset or virtual address before modifying anything:
   ```sh
   xt-forge re disasm original.bin --rva 0x1040 --max-lines 40
   ```
3. Preview the patch cleanly in dry-run mode to inspect byte delta and obtain a confirmation token:
   ```sh
   xt-forge re patch working-copy.bin --rva 0x1040 --hex "9090" --dry-run
   ```
4. Apply the patch only on a `-patch` copy using the generated confirm token:
   ```sh
   xt-forge re patch working-copy.bin --rva 0x1040 --hex "9090" --confirm <token>
   ```

## Guardrails
- Never patch original artifacts in place; always copy to `*-patch` first.
- Verify the resulting binary with `xt-forge re diff original.bin working-copy.bin`.
