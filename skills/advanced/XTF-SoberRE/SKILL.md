---
name: XTF-SoberRE
description: Analyze 100+ MB stripped ELFs, sectionless binaries (e_shnum=0), Android Bionic APS2 relocations, Roblox .rbxm containers, and safe process_vm_readv memory probes.
---

# XTF-SoberRE (Advanced Tier)

**Quick start:** `xt-forge re deep-elf <elf> --json` | `xt-forge re anchors <elf> --target "<str>" --json`

Hardened native reverse engineering for massive or stripped Linux/Android/Roblox targets where Ghidra OOMs or standard tools misdiagnose `e_shnum=0` as packed.

## When to use
- Stripped 100+ MB C++ ELFs (`libroblox.so`, game engines, runtimes) where `objdump -d` or Ghidra stalls.
- Sectionless ELFs (`e_shnum=0`) or Android Bionic ELFs (`SHT_ANDROID_RELA` APS2 relocations, `pthread_mutex_t` 4B ABI warnings).
- Live process memory inspection when `/proc/<pid>/mem` returns `EACCES` or `smaps` has 100+ GB sparse mappings.
- Roblox `.rbxm` / `.rbxl` binary model inspection (`SIGN` Ed25519 chunks vs unsigned Luau bytecode).

## Workflow
1. Triage ELF structure without false "packed" alerts:
   ```sh
   xt-forge re deep-elf target.so --json
   ```
2. Stream RIP-relative `lea` string anchors directly to enclosing function prologues:
   ```sh
   xt-forge re anchors target.so --target "bytecode version mismatch" --json
   ```
3. Run O(1) windowed disassembly around a discovered address:
   ```sh
   xt-forge re slice target.so --start 0x36085e4 --json
   ```
4. Inspect live process RSS and `process_vm_readv` reachability safely:
   ```sh
   xt-forge re live-probe <pid> --json
   ```

## Guardrails
- Always check `smaps` RSS before reading `/memfd:` or large anonymous mappings to avoid sparse zero-fill OOMs.
- Use `re_anchors` + `re_slice` instead of full-binary `objdump -d` on binaries > 20 MB.
