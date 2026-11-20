---
name: XTF-BinaryTriage
description: Perform offline ELF and PE binary triage for mitigations, sections, imports, and capabilities.
---

# XTF-BinaryTriage (Complex Tier)

**Quick start:** `xt-forge re triage target.bin --json` (or `xt_call` → `re_triage`)

Assess an unknown executable offline in a single `<200ms` call (`info`, `checksec`, `sections`, `rtti`, top `borer` functions, and strings) before committing heavy decompiler time.

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
5. Pull ASCII/UTF-16 strings (use `--min-len 3` when hunting short engine symbols like `IsA`) and compute section entropy:
   ```sh
   xt-forge re strings target.bin --min-len 3
   ```
6. Inspect section-header-stripped ELFs (`e_shnum == 0`) or Android Bionic ELFs (`APS2` packed relocations):
   ```sh
   xt-forge re deep-elf target.so --json
   ```

## Guardrails (Sober RE Hardened)
- Keep analysis strictly read-only (`guard` read-only mode works out of the box, including `/var/lib/flatpak` and `/usr`).
- **Never misdiagnose `e_shnum == 0` as packed**: When `readelf -S` reports 0 sections, run `xt-forge re deep-elf` (`ghidra.inspect_elf_deep`) to parse `PT_LOAD` and `PT_DYNAMIC` directly.
- **Android Bionic on glibc ABI traps**: If `is_android_bionic: true` or `has_android_aps2_rela: true`, glibc `ld.so` silently skips `SHT_ANDROID_RELA` (`0x60000002`, `"APS2"` magic) leaving `.init_array` NULL (`rip=0x0`), and Bionic `pthread_mutex_t` is 4 bytes vs glibc's 40 bytes (direct glibc `pthread_mutex_lock` overwrites 36 bytes of adjacent struct fields).
- **Itanium C++ mangled class names vs filenames**: Strings matching `N<len><ns><len><Class>E` (e.g. `N3RBX17ClientAppSettingsE`) are RTTI typeinfo strings (`RBX::ClientAppSettings`), not config filenames on disk.
