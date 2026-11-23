# xt-forge binary workbench handoff

Build a local binary workbench that an analyst can use from first inspection through a saved analysis. The first release target is a reliable workflow on **Mach-O, Windows PE, and Linux ELF on x86-64 and arm64**, with 32-bit x86 and ARM/Thumb following. ARM64 is an instruction set. Support must be measured separately for every executable format, ABI, and analysis operation.

Use IDA Pro as the benchmark for that workflow. An analyst should be able to load a file, navigate assembly, functions, graphs and cross-references, inspect pseudocode, rename and retype items, and reopen the analysis. The milestone order below is a recommendation. Full IDA feature and processor coverage is a longer-term goal. [IDA Pro capabilities](https://hex-rays.com/ida-pro) · [IDA supported formats](https://docs.hex-rays.com/core/disassembler/specification/supported-file-formats.md)

## Start here

1. Inspect `git status --short --branch` and preserve the existing 0.4.7 work in progress. Read the [November 22 handoff](HANDOFF-2026-11-22.md), its [baseline](plans/2026-11-22-ida-parity-baseline.md), and the [architecture guide](../ARCHITECTURE-RUST-GO.md). The older handoff repeats some completed work in its next-actions list. Check the code and tests before taking an item.
2. Follow the existing entry points. Go owns SYS image loading and native analysis in [internal/sysimage](../../native/xtforge-go/internal/sysimage). The [Go hub](../../native/xtforge-go/cmd/xtforge-hub/main.go), [Rust launcher](../../native/xtforge-rs/src/main.rs), and [Python adapter](../../xtforge/core/re/sysimage.py) expose it. Reuse [annotation storage](../../xtforge/core/re/annotate.py) and the optional [IDA bridge](../../xtforge/core/re/ida.py). Keep existing command and MCP contracts compatible.
3. Extend [the existing cross-format verifier](../../scripts/verify_sys_native.py), which already checks CLI/MCP paths on generated fixtures. Start with one missing arm64 lane, preferably **Windows PE arm64**. Generate a tiny program with a known function, direct call, branch and string. Verify the file mapping, function address, decoded instructions, control flow, and xrefs. Confirm what the current implementation already passes, then fix the first demonstrated gap before moving on to additional formats.
4. Restore trust in release checks alongside that first slice. Reconcile `uv.lock` with the project version. For `xtforge test --pattern`, distinguish zero selected tests from a pass, define what the filter matches for unittest, and reject unsupported filter semantics explicitly.

The handoff review ran `python3 scripts/verify_sys_native.py --native-binary native/xtforge-rs/target/release/xtforge-native` successfully. The verifier built the Go hub from the current tree and reused the existing Rust launcher. It exercised x86-64 ELF, PE and Mach-O, arm64 Mach-O in IPA, and both MCP entry points on the arm64 fixture. Its optimized and unoptimized arm64 loop cases passed. Keep those tests as regression coverage when expanding to Windows and Linux on arm64.

## Coverage to deliver

| Stage | Format and CPU | Evidence required |
| --- | --- | --- |
| 1 | Linux and Android ELF x86-64 and arm64, including shared objects | Load and map segments, inspect dependencies, recover functions, assembly, CFG and xrefs. Exercise stripped, PIE and sectionless inputs as well as ordinary executables. |
| 1 | Windows PE32+ x86-64 and arm64 EXEs and DLLs | Verify RVA, VA and file offsets, imports and exports, and unwind-derived starts. Test the Windows ABI separately from System V or AAPCS64 calls. |
| 1 | macOS and iOS thin and universal Mach-O x86-64 and arm64, plus selected IPA/DMG members | Verify slice and member selection, file-backed mappings and metadata-derived names. Include arm64e subtype identification and report any analysis limits separately. |
| 2 | ELF and PE on 32-bit x86 and ARM/Thumb where applicable, legacy 32-bit Mach-O | Exercise instruction mode, relocations, and correct calling conventions for each claimed combination. |
| 2 | ELF/Mach-O/COFF objects and archives, raw images, Intel HEX and S-record | Inspect members and relocations. For raw input require an explicit architecture, byte order where applicable, and a load address. |
| 3 | dyld shared caches, kernelcaches, mixed PE ARM64EC/ARM64X, RISC-V, MIPS, PowerPC | Ship each loader or processor module with independent fixtures. The current dyld and kernelcache helpers provide header parsing and detection, respectively. |
| Later | DEX/APK, .NET assemblies, WASM, firmware containers and crash dumps | Give bytecode, containers and dumps their own analysis capabilities. Begin with metadata and member enumeration where deeper analysis is pending. |

Keep a versioned support matrix with independent statuses for identification, loader, instruction decoding, functions/CFG, xrefs, pseudocode and symbols/types. Accept any regular file for identification and bounded byte inspection. Give unknown formats a documented fallback with size, hash, bounded strings/hex, and supported next actions. Detect by content, with explicit overrides and ambiguity reporting. For nested input, keep format, container/member and slice identity available through the whole analysis.

## Features after the first cross-format slice

- **Analysis quality.** Extend the existing CFG and IR using fixtures for tail calls, switch tables, multi-block loops, stack locals and ABI-specific calls at different optimization levels. Preserve instruction addresses and provenance for recovered facts. Report unresolved edges, incomplete scope and opaque instructions. Verify pseudocode semantics on benign, source-known fixtures, including signedness and load/store behavior.
- **Analyst state and symbols.** Add portable, versioned session state for named functions, comments, typed arguments, structures and bookmarks. Anchor state to file identity and slice/member, and test save, reopen and export. Apply analyst names/types to assembly and pseudocode. Improve DWARF/dSYM and PDB import, Objective-C and Swift metadata, and local signature matching against a curated library corpus.
- **Navigation and integrations.** Add an original workbench view after the data contract stabilizes. Link assembly, function list, hex, CFG, xrefs, types and pseudocode by address. Give headless callers the same data via paginated JSON/MCP. Keep optional engines explicit in output and use them as enrichment or comparison backends. Later, assess debugger integration with analyst-owned fixtures and explicit launch controls.
- **Agent workflows.** Update [XTF-BinaryTriage and XTF-Disasm](../../skills/index.json) for the format matrix, provenance and partial results. Propose one new **XTF-BinaryWorkbench** skill for the complete workflow from identification through an evidence-backed saved project. Have it select the actual format/CPU/backend, verify one function with bytes and xrefs, and report incomplete coverage. Update the skill registry and its package checks when shipping it.

## Acceptance and reporting

- For each Stage 1 format/CPU lane, run labeled fixtures through the packaged CLI and MCP. Include debug and stripped builds, optimization variation, libraries and executable entry points where applicable, plus truncated headers and invalid member/slice indexes. Exercise address round trips and zero-filled ranges. Keep reads, decompression, recursion and output bounded. Run parser tests offline on benign generated inputs.
- Ground comparisons in source and linker maps for known function boundaries, and a pinned independent disassembler for instruction addresses and direct targets. Use licensed IDA when available on the same corpus and record its version and configuration. Report unavailable comparison runs explicitly. Record per-lane function and xref precision/recall, pseudocode semantic pass rates, and wall time/peak RSS. Missing lanes and partial analyses belong in the release report.
- Run the commands below from the repository root. The native verifier requires the toolchains in the [architecture guide](../ARCHITECTURE-RUST-GO.md#native-instruction-decoding-and-control-flow). Also run the full Go race suite on a runner that permits loopback sockets and the Node plugin suite documented in the [README](../../README.md). Publish the matrix with exact commands and outcomes before using “IDA parity” in release copy.

```sh
uv lock --check --offline
UV_OFFLINE=1 python3 -m unittest discover -s tests
(cd native/xtforge-go && go test -race ./...)
(cd native/xtforge-rs && cargo test --locked --offline)
node --test plugins/xt-native/test/*.test.mjs
python3 scripts/verify_sys_native.py
```
