---
name: XTF-BinaryDiff
description: Diff two compiled binaries with normalized instruction diffing, .rodata string annotations, and reciprocal division math decoding.
---

# XTF-BinaryDiff (Complex Tier)

**Quick start:** `xt-forge diff <bin_v1> <bin_v2> --json` (or `xt_call` → `re_diff`)

Pinpoint behavioral regressions, silent constant changes, and security patches between two native ELF/PE/Mach-O builds in a single call.

## When to use
- Comparing `v1` and `v2` binaries to find which function changed and how its logic or arithmetic shifted.
- Detecting compiler strength-reduced division changes (`imul` + `sar`/`shr` magic constants) or `.rodata` string additions/removals.

## Workflow
1. Run normalized binary diffing across both builds:
   ```sh
   xt-forge diff path/to/bin_v1 path/to/bin_v2 --json
   ```
   Or via the `--meta` MCP gateway:
   ```json
   {"name": "re_diff", "arguments": {"bin1": "path/to/bin_v1", "bin2": "path/to/bin_v2"}}
   ```
2. Inspect `modified_functions`:
   - `insn_diff`: address-normalized unified assembly diff (`-` v1 vs `+` v2).
   - `diff_notes`: automatic decoding of GCC/Clang reciprocal division constants (e.g. `/10 (10%) in v1 -> /20 (5%) in v2`).
   - `function_disasm_v1` & `function_disasm_v2`: full per-function disassembly annotated inline with resolved `.rodata` string literals (`; str="..."`).
3. Check `strings_added` and `strings_removed` for format string or banner changes.

## Guardrails
- Start with `re_diff` before running raw `objdump` or `re_symbols` loops.
- Use `diff_notes` and the annotated `function_disasm_v1`/`v2` output directly when `evidence_complete: true`.
