# Commit plan — IDA parity, 2026-11-22

Six commits, each independently verifiable and each with its own test. Ordered so
that every commit leaves the tree building and the suites green.

---

## Commit 1 — `feat(sys): arm64 variable shifts`

**Files** `internal/sysimage/lift_aarch64.go`, `internal/sysimage/structured_state.go`

**Why** Baseline test failure, real gap: `asr w0, w1, w2` lifted to `opaque`.

**Change** Dispatch `lsl`/`lsr`/`asr`/`ror` when the amount is a register.
Map to the shared `shl`/`shr`/`sar` opcodes. Allow any count register on arm64
instead of requiring x86's `cl`. Do not clear flags for arm64 shifts, which do
not write flags.

**Verify** `go test ./internal/sysimage -run 'TestARMVariableShift|TestX86VariableShift'`
plus a differential check: compile an arm64 function with a variable shift,
recover it, run both against 4096 inputs.

---

## Commit 2 — `feat(udif): read Apple disk images in process`

**Files** `internal/udif/udif.go`, `internal/udif/udif_test.go`,
`internal/thirdparty/lzfse/*`

**Why** No DMG support at all. `hdiutil` does not exist on Linux, and shelling out
to `7z` would break the "no external tool" property the rest of SYS holds.

**Change** Parse the `koly` trailer, walk the XML plist as tokens (a plist is
key/value siblings, so struct tags cannot describe it), decode `mish` chunk
tables, decompress `raw`/`zero`/`zlib`/`adc`/`lzfse` chunks. Vendor the
public-domain LZFSE decoder with provenance.

**Verify** Synthetic fixtures for each chunk kind and for four corruption cases,
plus the real `delta.dmg`:
- trailer, 8 GPT partitions, LZFSE whole-data whole-slice
- extracted APFS partition is 41 377 792 bytes and probes as `apfs`
- **cross-check**: a file 7z recovered independently from the same DMG must
  appear verbatim inside our extracted partition (verified at offset 700928)

---

## Commit 3 — `feat(sys): open DMG as a container`

**Files** `internal/sysimage/container_dmg.go`, `internal/sysimage/overview.go`

**Why** A DMG is a container; an analyst wants the app binary inside it.

**Change** Detect UDIF by the `koly` trailer rather than the extension. Extract
the filesystem partition, scan for a Mach-O that validates completely (header,
every load command, segment extents), report `format: dmg`. Bound in-memory
expansion at 512 MiB with a clear message.

**Verify** `re overview delta.dmg --json` → `format: dmg`, `arch: x86_64`,
200 functions recovered; `re functions` on the same file; IPA path unchanged
(`TestMachOverviewAndIPAMember` still passes).

---

## Commit 4 — `feat(sys): Objective-C metadata`

**Files** `internal/sysimage/objc.go` + test

**Why** 199 of 200 functions recovered from the real DMG have no name. On Apple
binaries the names are in `__objc_classlist`/`__objc_methname`.

**Change** Parse `__objc_classlist` → class struct → `method_list_t` → method
names, and name the corresponding code addresses. Supplement with an
`__objc_methname` string pass for names whose class is stripped.

**Verify** On `delta.dmg`: count named functions before/after, and assert
specific known method names appear.

---

## Commit 5 — `feat(sys): DWARF function names`

**Files** `internal/sysimage/dwarf.go` + test

**Why** `llvm-dwarfdump` exists but SYS should read the data itself; debug builds
carry exact names and types.

**Change** Read `.debug_info`/`.debug_abbrev`/`.debug_str` via
`debug/dwarf`, map subprogram low-PC to names. Report the source as `dwarf`.

**Verify** Compile a fixture with `-g`; assert names match the source function
names, and assert no false positives on the stripped real DMG.

---

## Commit 6 — `feat(llvm): bridge the LLVM toolchain`

**Files** `xtforge/core/re/llvm.py`, `xtforge/cli/__init__.py`,
`plugins/xt-native/index.ts` (+ tests)

**Why** The user's agent had to drive `llvm-objdump`/`ld64.lld` by hand. LLVM is
already the disassembly backend; the bridge makes it addressable from the CLI and
the plugin instead of from ad-hoc shell.

**Change** A thin, typed wrapper that locates toolchain binaries, runs them with
timeouts, and returns parsed JSON. Expose `re llvm <verb>` and an `xt-native`
command so an agent can ask for sections/symbols/dwarf/otool output without
composing command lines.

**Verify** Each verb against the real DMG and a fixture with debug info; plugin
test asserts the command is registered and returns parsed output.

---

## Secret / privacy scan plan

Before each commit, scan exactly the staged paths for: absolute home paths,
tokens/keys, machine-specific temp paths, and any sample artifact that should not
ship. The real DMG lives in `~/Downloads` and is referenced only by an
opt-in test that skips when absent, so it never ships.

## Release-artifact plan

After the six commits: rebuild the hub, rebuild the wheel and npm package, re-run
both suites plus `scripts/verify_sys_native.py`, and only then consider a version
bump. Publishing requires separate authorization.
