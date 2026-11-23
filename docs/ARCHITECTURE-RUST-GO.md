# Rust, Go, and Python Hybrid Architecture

XT-Forge 0.4.0 uses a three-layer architecture designed around one rule: keep every tool functional in zero-dependency Python while letting compiled Rust and Go binaries handle the work each language is best suited for.

![Three-Tier Architecture Diagram](assets/architecture-rust-go.png)

## XT-Forge-SYS

XT-Forge-SYS is the binary and systems analysis component within XT-Forge. Its native image overview runs in the Go hub and uses the Go standard library to read ELF, PE, Mach-O and ZIP structures. The Rust launcher and Python CLI expose the same overview. Existing Ghidra, Borer, and IDA integrations provide backend analysis through their respective adapters.

| Input | Native overview coverage |
| --- | --- |
| Linux ELF | Architecture, preferred entry address, loadable segments, sections, and dynamic dependencies |
| Windows PE | Architecture, preferred entry address, virtual sections, and dependencies from the import directory |
| macOS Mach-O | Thin images and standard universal slices, architecture, entry from `LC_MAIN`, segments, sections, and linked libraries |
| iOS IPA | Mach-O overview for a selected executable member under `Payload/*.app` |

```sh
xtforge re overview ./fixture --json
xtforge re overview ./fixture.ipa --member Payload/Fixture.app/Fixture --json
```

Omit `--member` to use the unique executable named after its app directory. IPA inspection reads the selected member in memory with a 128 MiB limit. The overview reports preferred virtual addresses and image-relative file offsets. `entry_file_offset` is populated when the entry maps to a readable file-backed byte. Use `slice_offset` to translate a universal slice’s file offsets to the containing Mach-O. Missing entry fields are represented as `null`.

In Go MCP, call `re_overview` via `xt_call`. In the Python MCP surface, use `re_inspect` with `verb: overview`. Both use the native hub. Native disassembly, function recovery, and pseudocode parity are tracked in the [SYS implementation plan](superpowers/plans/2026-11-21-xt-forge-sys.md).

### Native function index

```sh
xtforge re functions ./fixture --limit 40 --json
xtforge re functions ./fixture.ipa --arch arm64 --limit 40 --json
```

The index merges function starts by preferred virtual address and reports a file offset, metadata source, and any available name and size. The result reports the number of indexed starts and whether the output was truncated. An architecture filter selects matching universal slices. A file-backed entry point is included when present.

| Format | Sources |
| --- | --- |
| ELF | Function symbols in static and dynamic tables, and fixed-width starts from GNU exception-frame headers. [LSB exception-frame header](https://refspecs.linuxfoundation.org/LSB_2.0.0/LSB-Core/LSB-Core/ehframehdr.html) |
| PE | x86-64 and arm64 exception directory entries, plus COFF function symbols when present |
| Mach-O and IPA | `LC_FUNCTION_STARTS` entries and symbols from instruction sections. Instruction-section symbols may include labels |

Use `re_functions` through Go MCP and `re_inspect` with `verb: functions` through Python MCP. The index reports metadata-backed candidates.

### Native instruction decoding and control flow

```sh
xtforge re disasm-native ./fixture --target choose --flow --json
xtforge re disasm-native ./fixture.ipa --arch arm64 --target _choose --flow --json
```

SYS decodes little-endian x86, x86-64, and arm64 instructions in process with vendored Go architecture decoders. A target can be an exact indexed name, a preferred address, or the image entry point. For universal images, select an unambiguous architecture. The command bounds reads to one file-backed window and accepts explicit byte and instruction limits.

The default mode decodes linearly. Flow mode follows reachable direct branches in the selected window and reports basic blocks, call and branch targets, and PC-relative references. Calls are recorded as edges. Indirect destinations remain unresolved and edges outside the decoded window retain their target when available.

Use `re_disasm_native` through Go MCP and `re_inspect` with `verb: disasm-native` through Python MCP. The cross-format check builds synthetic ELF, PE, Mach-O, and IPA fixtures and compares direct calls against LLVM objdump. Run `python3 scripts/verify_sys_native.py` on a Linux x86-64 host with Go, cached Cargo dependencies, a C compiler, MinGW, Clang, LLD, and LLVM objdump. Pass `--native-binary` to test an existing Rust launcher build.

### Cross-function references

```sh
xtforge re xrefs-native ./fixture --target increment --max-functions 512 --json
xtforge re xrefs-native ./fixture.ipa --arch arm64 --target _increment --json
```

SYS seeds the scan from the entry point and metadata-backed starts in file-backed executable regions. Direct calls can add candidate function starts with `direct_call_target` provenance. A direct jump to another known start is reported as a tail-jump candidate. Data references include decoded PC-relative operands and arm64 addresses resolved from adjacent page-base and offset instructions in the same basic block.

Use `re_xrefs_native` through Go MCP and `re_inspect` with `verb: xrefs-native` through Python MCP. Omit the target to list references to any address within the scanned scope. The scan exposes pending and limited function counts, unresolved indirect call sites, and the number of matching references before the output limit.

### Native IR and pseudocode

```sh
xtforge re decompile-native ./fixture --target choose --json
```

SYS lifts reachable instructions to typed register, immediate, and memory operations grouped by basic block. The current lifter covers common integer arithmetic and flag-setting operations, explicit branches and calls, selected loads and stores, x86 register pushes and pops, and arm64 register-pair loads and stores. Register aliases and flag predicates refer to the selected ISA. Each operation reads pre-instruction inputs, and writeback records changes to the address register.

The renderer emits register-level pseudocode. It preserves opaque instructions with addresses and raw disassembly, keeps direct targets visible, and reports decoded, lifted, and opaque instruction counts. These counts measure supported instruction semantics within the selected window. They do not measure function completeness, source-level type recovery, or parity with a reference decompiler.

Use `re_decompile_native` through Go MCP and `re_inspect` with `verb: decompile-native` through Python MCP. The synthetic verifier checks arithmetic width and control-flow targets on all four formats.

### ABI-aware structured C

`decompile-native` can also return a `structured` result alongside the raw IR and register-level listing. SYS uses the image format and architecture to select the ordinary integer calling convention. It tracks register values, private stack spills, flags, and return paths to infer argument registers and integer widths. [System V AMD64 ABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex) · [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention) · [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)

The result uses unsigned C integer types for observed bit widths. It can reconstruct acyclic branches, optimized conditional selections, and direct calls or tail transfers to independently recovered functions in the same image. SYS memoizes callees per request, tracks ABI clobbers, and emits each recovered helper once. The structured result lists those dependencies with their original addresses.

SYS omits the structured result when analysis encounters unsupported instructions, unresolved callees, non-stack memory accesses, recursive or unresolved paths, or inconsistent return widths. Raw IR remains available in those cases.

The verifier builds branching leaf and direct-call fixtures at `-O0` and `-O2` for ELF, PE, Mach-O, and IPA. It recompiles the emitted C and compares the return values with the original fixture on 4,096 inputs per recovered function, including zero and the largest 32-bit unsigned value.

## Why Split Rust and Go?

Trying to solve every workload in one runtime creates trade-offs you can feel immediately at the command line:

| Layer | Binary / Package | Strengths Used in XT-Forge | Storage Owned |
| --- | --- | --- | --- |
| Fast Native CLI | `xtforge-native` (`native/xtforge-rs/`) | Sub-10ms SQLite queries, full secret/pattern/injection scanning, codec hashing & entropy, query + `--symbols` packing, Mach-O/XOR scanners, AST/regex code indexing | `mem.db`, `flash/`, `code_graph.db`, `re_overlay.db` |
| Concurrency & Gateway Hub | `xtforge-hub` (`native/xtforge-go/`) | Goroutines + stdio pipes, concurrent keyless threat intel (`nvd`/`epss`/`kev`/`greynoise`/`internetdb`/`circl`), ELF/PE/Mach-O `checksec` & `capa`, JSON-RPC MCP multiplexing, LSP lifecycle, ASAR/ZIP/HAR unpacking | `mcp_trust.json`, `guard_mode.txt`, `loops/schedules.json`, `cache/net/`, `audit/*.jsonl` |
| Reference & Fallback Core | `xtforge/` (`python3 -m xtforge.cli`) | Pure stdlib portability, complex orchestration (`build`, `taste`, `docs`, `hub`, `design`, `artifact`, `knowledge`), offline test harness | Compatible schema mirrors for every store |

All three engines follow the exact same SQLite schemas, JSON envelopes, secret-redaction regexes, and `DENY_GLOBS` path protections. Switching between native mode and `XT_FORCE_PYTHON=1` reads and writes the exact same databases without migration friction.

## Measured Native Speedups

Median elapsed wall time over 5 cold subprocess invocations comparing native Rust/Go execution against `XT_FORCE_PYTHON=1` (pure Python reference):

| Command | Native Runtime | Native (ms) | Python (ms) | Speedup |
| --- | --- | ---: | ---: | ---: |
| `scan secrets xtforge --json` | Rust (`xtforge-native`) | 28.2 | 327.2 | 11.6x |
| `route context xtforge --query route_context --symbols` | Rust (`xtforge-native`) | 15.3 | 162.8 | 10.7x |
| `code index xtforge --json` | Rust (`xtforge-native`) | 6.9 | 122.9 | 17.9x |
| `codec entropy --path native/xtforge-rs/...` | Rust (`xtforge-native`) | 7.7 | 197.5 | 25.8x |
| `re checksec native/xtforge-go/xtforge-hub --json` | Go (`xtforge-hub`) | 8.8 | 120.6 | 13.7x |
| `re capa native/xtforge-go/xtforge-hub --json` | Go (`xtforge-hub`) | 18.3 | 313.9 | 17.2x |
| `intel sources --json` | Go (`xtforge-hub`) | 6.0 | 109.3 | 18.2x |

## Request Dispatch Flow

When you run `xt-forge <noun> <verb> [flags]` (or `xt-forge --meta`):

1. `bin/xtforge` checks `XT_FORCE_PYTHON`. If unset (`0`) and `native/xtforge-rs/target/release/xtforge-native` is executable, it `exec`s directly into Rust (~2ms startup).
2. `native/xtforge-rs/src/main.rs` parses flags and checks `wants_hub(&p)` or top-level `--meta`:
   * `--meta` (`mcp serve --meta`), `mcp proxy`, `mcp audit`, `mcp trust`
   * `intel sources|ip|cve|kev|search|hash|domain`
   * `code lsp`
   * `re checksec|capa|asar|netcap|apk|decompile|trace`
   * `research`
   * `loop schedule|list|stop|status`
   * `guard mode`
   If `XT_NATIVE_HUB` is not `"0"` and `xtforge-hub` is present beside the binary (or at `native/xtforge-go/xtforge-hub`), Rust `exec`s into Go in the caller's original working directory.
3. Otherwise Rust handles `flash`, `route` (including `context --query ... --symbols`), `compress`, `mem`, `code index|graph`, `codec` (`hash|encode|decode|roundtrip|entropy`), `re annotate|entropy|info|strings --xor`, `scan` (`secrets|patterns|injection|mcp`), and `calibrate` directly in compiled native code.
4. Any remaining noun (`build`, `taste`, `docs`, `hub`, `design`, `artifact`, `knowledge`, `plugin`, `scan deps`, or `mcp serve` in default 50-tool mode) cleanly `exec`s `python3 -m xtforge.cli`.

## Shared Data Contracts

### `mem.db` (Schema v3)

Both `native/xtforge-rs/src/mem.rs` and `xtforge/core/mem/store.py` open SQLite in WAL mode and run additive `PRAGMA table_info(mem)` migrations so older v1/v2 databases upgrade safely in place:

* Added `failed_attempt` and `anti_pattern` to `KINDS`
* Added `error_sig` and `outcome` columns on `mem`
* Added `consolidation_log` table tracking threshold, merge count, and summary count
* Consolidated summary notes create typed `derived_from` rows in `links`

### `code_graph.db`

Populated incrementally via SHA-256 file hashes in both `native/xtforge-rs/src/code_graph.rs` and `xtforge/core/code/graph.py`:

* `files (path, lang, sha256, mtime, loc)`
* `symbols (id, file_path, name, fqname, kind, line, signature)`
* `edges (id, src_name, dst_name, rel, file_path, line)`

### `re_overlay.db`

Keyed by target binary SHA-256 in both `native/xtforge-rs/src/re_fast.rs` and `xtforge/core/re/annotate.py`:

* `binaries (sha256, name, format, size, updated)`
* `annotations (id, sha256, rva, kind, orig_name, new_name, type_decl, comment, confidence, updated)`

## Safety Invariants Across Runtimes

Both Go's `internal/guard` and Rust's `src/guard.rs` mirror Python's `xtforge/core/route/guard.py`:

* Canonical realpath verification against `DEFAULT_ROOTS` (including `.dsh` account-scoped homes automatically)
* Hard deny globs for SSH keys, `.env` secrets, keystores, and credentials
* Confirm-token issuance for write mutations or live process tracers (`re trace`)
* Automatic output compression and artifact spilling (`cache/artifacts/spill_*.json`) whenever a proxy or gateway payload exceeds threshold bytes
