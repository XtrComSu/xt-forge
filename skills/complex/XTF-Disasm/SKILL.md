---
name: XTF-Disasm
description: Map native disassembly, control-flow graphs, cross-references, and C++ RTTI hierarchies.
---

# XTF-Disasm (Complex Tier)

**Quick start:** `xt-forge re disasm target.bin --symbol main && xt-forge re cfg target.bin --symbol main`

Follow execution paths inside stripped or C++ binaries from entrypoints to target sinks.

## When to use
- Reconstructing what an exported or internal routine calls and where it branches.
- Resolving C++ vtables and polymorphic dispatch in native artifacts.

## Workflow
1. Build the binary import/export/call-site map and list recovered symbols:
   ```sh
   xt-forge re graph target.bin
   xt-forge re symbols target.bin --limit 100
   ```
2. Disassemble a specific symbol or address range and extract its control-flow graph:
   ```sh
   xt-forge re disasm target.bin --symbol main
   xt-forge re cfg target.bin --symbol main
   ```
3. Recover C++ RTTI typeinfo/vtables or Go/Rust runtime metadata:
   ```sh
   xt-forge re rtti target.bin
   xt-forge re runtimes target.bin
   ```
4. Annotate addresses cleanly during reversing so notes stay structured across passes:
   ```sh
   xt-forge re annotate target.bin --rva 0x1040 --name verify_license --comment "Checks HMAC footer"
   ```

## Guardrails
- Pin confirmed function RVAs and names into durable memory via `xt-forge mem put` or `re annotate`.
