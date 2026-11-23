# Baseline — IDA-parity work, 2026-11-22

Recorded before any commit, per the delivery workflow. Everything here is
**verified** by running it, not remembered.

## Repository state

| Fact | Value |
|---|---|
| branch | `main` |
| HEAD | `5600247 docs(readme): add first-screen quick navigation links` |
| dirty paths | 35 (21 modified, 14 untracked — the v0.4.7 SYS body of work) |
| `VERSION` | `0.4.7`, codename `Damascus` |
| Go module | `xtforge-hub`, `go 1.24` |
| toolchain present | go 1.27.3, cargo 1.99.1, node v22.23.3, clang + `ld.lld` + `ld64.lld`, LLVM 23.1.3 (`llvm-objdump`, `llvm-readobj`, `llvm-nm`, `llvm-otool`, `llvm-dwarfdump`), `7z`, `bsdtar` |

No `xt-product` skill exists in this session's catalog (`skill` reports it
unknown, and `xt_search` finds nothing); the ten-step workflow is being followed
directly instead.

## Baseline checks

| Suite | Command | Baseline result |
|---|---|---|
| Go build | `go build ./...` | clean (after fixing one type error in new `container_dmg.go`) |
| Go vet | `go vet ./...` | clean |
| Go tests | `go test ./... -skip '^TestConcurrentCVEEnrichmentWithMockServers$'` | **1 pre-existing failure**, now fixed — see below |
| Python tests | `python3 -m unittest discover -s tests` | **524 tests, OK** |
| gofmt | `gofmt -l internal/` | clean except two pre-existing files (`internal/lsp/lsp.go`, `internal/rehub/rehub.go`) |

### The one pre-existing failure, and why it was real

`TestARMVariableShiftPreservesFlags` failed at baseline with:

```
arm64 variable shift lost operands: Operation{Opcode:"opaque", Raw:"asr w0, w1, w2"}
```

This was **not** a flaky or misplaced test. `decodeInstruction` decoded
`asr w0, w1, w2` correctly, but `liftAArch64` had no case for the variable-shift
mnemonics, so the operation degraded to `opaque`. Two real gaps behind it:

1. `lsl`/`lsr`/`asr`/`ror` with a **register** amount were never dispatched.
   Only the *constant* shift form (a `Scale` field on a shifted-register
   operand) was handled.
2. `structured_state.go` required the shift-count register to be `cl`, which is
   an x86-only fact. On arm64 the count register is named in the instruction, so
   every arm64 variable shift was declined even once lifted.

Fixed in this batch, both tests now pass.

## What already exists (so scope is honest)

Present before this work: ELF, PE, Mach-O (thin + fat), IPA with `--member`,
dispatch/jump-table recovery, structured decompilation for acyclic functions and
single-block loops, xrefs, DWARF-free function indexing via symbol tables and
`LC_FUNCTION_STARTS`.

Measured absent before this work (`grep` over the tree returned nothing):

| Feature | Evidence |
|---|---|
| DMG / UDIF container | no match for `dmg\|UDIF\|koly\|LZFSE` |
| Objective-C metadata | no match for `__objc\|objc_class\|objc_method` |
| DWARF debug info | no match for `dwarf\|DWARF` |
| Swift demangling | no `swift-demangle`; only MSVC/Itanium C++ in `rtti.py` |
| bzip2/LZMA DMG chunks | no decoder wired |
| dyld shared cache | no match for `dyld_shared_cache` |
| kernelcache | no match for `kernelcache` |

## Acceptance criteria for this batch

Each is a behaviour that can be demonstrated on a real artifact, not a shape
assertion:

1. **DMG container** — `re overview delta.dmg` reports `format: dmg` and recovers
   functions from the app binary inside; extraction is cross-checked against an
   independent extractor (7z) so "it produced bytes" is not mistaken for "it
   produced the right bytes".
2. **No external tool dependency** — DMG decompression happens in process, in
   keeping with the rest of SYS.
3. **arm64 variable shifts** — lift to `sar`/`shr`/`shl` with two operands rather
   than `opaque`.
4. **Objective-C metadata** — recover class/method names from `__objc_classlist`
   so `__objc_methname` strings become callable symbols.
5. **DWARF** — import function names/types from debug info when present.
6. **Swift demangling** — demangle `_$s...` symbols.
7. **LLVM bridge** — expose the vendored LLVM binaries through the CLI and the
   `xt-native` plugin, since LLVM is already the disassembly backend.

## Known environment constraints

- `/usr/local/bin` is not writable; `/tmp` is.
- No arm64 runtime libs (`crtbeginS.o`, `-lgcc` absent): build arm64 fixtures as
  Mach-O via `clang -c -target arm64-apple-ios13.0` + `ld64.lld`, exactly as
  `scripts/verify_sys_native.py` already does.
- An unlinked `.o` is rejected by the format sniffer; test through a linked
  binary.
- Real sample on disk: `/home/xtrcom/Downloads/delta.dmg` — UDIF v4, LZFSE,
  41 377 792-byte APFS partition, contains a universal (x86_64 + arm64) Swift
  app with `__objc_classlist`, `__swift5_types`, and `__objc_methname`.
