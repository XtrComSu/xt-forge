---
name: XTF-Decompile
description: Recover obfuscated XOR/stack strings, run headless decompilation, and dry-run dynamic tracing.
---

# XTF-Decompile (Advanced Tier)

**Quick start:** `xt-forge re xor target.bin && xt-forge re decompile target.bin --symbol <fn>`

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
3. For huge stripped binaries (>50 MB like `libroblox.so`), **never** run whole-binary `objdump -d` or unbounded headless Ghidra first. Resolve string anchors via streaming RIP-relative `lea` scan and slice an O(1) disassembly window:
   ```sh
   xt-forge re anchors target.so --target "bytecode version mismatch" --json
   xt-forge re slice target.so --start 0x36085e4 --json
   ```
4. For live sandboxed processes (Flatpak/`bwrap`, `ptrace_scope=1`), probe `process_vm_readv` and `/memfd:` mappings with `smaps` RSS budgeting:
   ```sh
   xt-forge re live-probe <pid> --json
   ```
5. Preview capability-scoped dynamic tracing presets (`api_trace`, `tls_keys`, `crypto_hooks`, `crash_capture`) safely in dry-run:
   ```sh
   xt-forge re trace target.bin --preset api_trace --dry-run
   ```

## Guardrails (Sober RE Hardened)
- `XT_PERM_MODE=explore` strictly blocks dynamic process execution; switch modes only inside sandboxed labs.
- **No 100+ MB Ghidra OOM**: Always use `ghidra.resolve_string_anchors` + `ghidra.slice_disasm_window` (or `borer` targeted symbol lift) on >50 MB stripped binaries before launching headless Ghidra.
- **No 118 GB Sparse-Page Inflation OOM**: Never linearly read large `rw-p` `MAP_ANONYMOUS` allocations via `process_vm_readv` without checking `smaps` `Rss:` or probing one 4 KB page per 1 MB chunk first; reading unmapped anonymous pages faults physical zero pages into RSS and OOM-kills the target.
- **Check string-xref alias collisions**: Different diagnostic strings (e.g. `"version mismatch"` vs `"corrupted"`) often converge into the same shared formatter function; verify distinct `enclosing_function_va` in `resolve_string_anchors` before hooking.
- **Tagged constant-pool strides**: In serialized bytecode/model formats (e.g. `.rbxm` Luau constant pools examined via `xt-forge re rbxm`), verify per-element type tags (`0x02 <f64>` = 9-byte stride, 27 bytes per triple) instead of writing contiguous raw floats.
