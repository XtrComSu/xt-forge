# xt-forge install and workbench continuation plan

> For the implementing agent. Use the executing-plans skill to work through the checkboxes and return the diff and execution evidence to the reviewer. Budget 4 hours 20 minutes for the core work and up to 8 hours with the extension tasks. Times are planning estimates.

**Goal**

Make repeated installation safe and make Windows setup verifiable. Then close the highest-priority correctness and coverage gaps in the binary workbench.

**Architecture**

Keep the existing PowerShell, Bash, and npm launch paths. Make runtime selection, source updates, and install verification consistent at their entry points. Extend the existing Python/LLVM bridge and the native CLI/MCP verifier with independent fixtures.

**Tech stack**

PowerShell 5.1 and 7, Windows CMD, Bash, Node, Python 3.11+, Rust launcher, Go hub, Clang/LLD, LLVM inspection tools.

**Read first**

[November 23 implementation handoff](../HANDOFF-2026-11-23.md) · [Installer and REA brief](../HANDOFF-INSTALL-AND-REA.md) · [Binary workbench roadmap](../HANDOFF-BINARY-WORKBENCH.md)

## What the review established

- The checked-out working tree contains substantial uncommitted 0.4.7 work. The review saw HEAD `5600247`, but current files include the new installer, parser, and verification work. Record the actual state at your start. Use the dated handoff for background and current code for decisions.
- Linux verification ran 582 Python tests with one expected failure for the platform archives. Go passed with the loopback HTTP test excluded due to the sandbox. The native verifier passed with a newly built Go hub and an existing Rust launcher. The lockfile check passed.
- Both source installers still contain destructive update commands. Windows setup selects a Python command before testing its version, and npm's Windows shim still writes an ASCII path. The Windows tests inspected text, so actual Windows install behavior remains unverified.
- The native verifier covers Windows PE x86, PE ARM64 EXE/DLL, and PDB on the CLI. The Go and Python MCP cases currently use ARM64 IPA. A separate generated PE probe still showed `re llvm sections` returning a zero address and size for `.text` while LLVM reported real values.

## Working boundaries

Keep prior edits and untracked fixtures intact. Review an explicit file list before any staging. If isolating work, carry forward the relevant working-tree changes because HEAD alone lacks the current native engine. Keep package publishing and release uploads outside this session. Build any candidate archives locally or as CI artifacts. Use synthetic binaries and owned fixtures for inspection tests.

Treat runner access as a dependency. Only a Windows run can close the Windows acceptance gate and only a macOS run can close the macOS gate. If a runner is unavailable, add a runnable smoke job or script, record its exact invocation and move on to the next independent task. Report it as pending in the handoff back.

## Core work · 0:00–4:20

### 1. Reconcile the starting state · 0:00–0:20

- [ ] Capture `git status --short --untracked-files=all`, `git diff --stat`, and tool availability. Record whether a disposable Windows x64 and macOS arm64 environment can be reached. Run `git diff --check` and `uv lock --check --offline`.
- [ ] Read [the package tests](../../../tests/test_shipped_packages.py), [PowerShell tests](../../../tests/test_install_ps1.py), and [POSIX launcher tests](../../../tests/test_posix_launcher.py). Identify which use real executables and which inspect text. Record the existing archive failure as a separate baseline item.
- [ ] Use temporary profiles and local Git remotes for install tests. Capture failing logs as you go. Keep enough fixture information to replay every failure and avoid relying on an existing PATH or installed xt-forge.

### 2. Make Windows setup choose a working runtime · 0:20–1:40

**Files**

[install.ps1](../../../install.ps1), [bin/xtforge.cmd](../../../bin/xtforge.cmd), [bin/npx-xtforge.mjs](../../../bin/npx-xtforge.mjs), and the existing [launcher tests](../../../tests/test_windows_launcher.py) and [npm PATH tests](../../../tests/test_npm_path_advice.py).

- [ ] Add a regression where the first Python candidate fails or reports a version below 3.11, while the next candidate succeeds. Cover the `py -3` route and an explicit `XT_PYTHON` path with spaces. Confirm the current setup fails the candidate-fallback case first.
- [ ] Probe candidates before selecting one. Make preflight and installed dispatch agree about the interpreter. Verify a Python-backed command even if a native executable answers `version`. Keep the runtime error actionable with the failed candidate and the supported Python floor.
- [ ] Exercise every alias from a different directory with a relative argument. Include paths with spaces, Unicode, and a literal exclamation mark, and a command that intentionally returns nonzero. Check both npm/Node and standalone PowerShell shim generation. Remove any encoding or additional argument expansion that breaks these cases.
- [ ] Install twice. Confirm setup verifies the launcher before changing user PATH, preserves existing entries, adds its directory once, and makes the command available in the calling shell. Test the documented script invocation on PowerShell 5.1 and 7, including the bootstrap form if it remains documented.

**Exit gate**

Working interpreter selected, three aliases usable, relative arguments and exit status preserved, and second install leaves PATH stable. Record live run or pending Windows runner.

### 3. Make source updates safe on all platforms · 1:40–2:55

**Files**

[install.sh](../../../install.sh), [install.ps1](../../../install.ps1), [bin/xtforge](../../../bin/xtforge), [README](../../../README.md), and shipped-package tests.

- [ ] Reproduce update behavior in disposable clones against a local remote. Cases are clean fast-forward, modified tracked file, divergent branch, failed fetch, and fresh install. Add a failure-mode test before changing the update path.
- [ ] Replace hard resets with a checked fast-forward on the intended branch or a staged replacement that preserves the usable install. Refuse an unsafe update with a path-specific error. A source fetch failure must remain visible and must not activate a different tree or change installed aliases.
- [ ] Make optional native build failure visible. Keep the existing user-facing behavior where practical, and provide an explicit way to install without compiling. Report which backend is available and verify a representative command before success. For PowerShell, restore the caller's directory after a failing build.
- [ ] Retest the POSIX launcher with an absolute link, a relative link chain, and a reader without `readlink -f`. Exercise a fresh macOS shell where possible. Update only the install instructions affected by the actual behavior.

**Exit gate**

User edits and the previous usable command survive a failed reinstall. A clean reinstall succeeds. A fresh user can tell which backend was installed and how to use it.

### 4. Fix the LLVM PE section result · 2:55–3:40

**Files**

[LLVM bridge](../../../xtforge/core/re/llvm.py), [CLI adapter](../../../xtforge/cli/scan_cmd.py), [LLVM tests](../../../tests/test_re_llvm.py), and [CLI tests](../../../tests/test_re_llvm_cli.py).

- [ ] Compile a tiny PE and compare `.text` with `llvm-objdump --section-headers` or independently derive its address from the PE image base and section RVA. Assert a normalized section name, an accurate size, and a consistent address convention. Keep ELF and Mach-O fixtures in the same regression group.
- [ ] Route PE through a format-neutral section command or parse COFF's actual field names. If supporting a second parser, make its address convention agree with the primary parser. Distinguish an empty table from a backend failure. Test malformed input and a missing tool and make the CLI surface their status.
- [ ] Replay the PE oracle comparison through the public CLI. Record the value from each side and the behavior for ELF and Mach-O.

### 5. Core review checkpoint · 3:40–4:20

- [ ] Run targeted installer, LLVM and package tests. Confirm the version and lockfile agree. Start the broader checks early enough to read the final exit codes.
- [ ] Report core status by Windows, Linux, and macOS, showing source versus package install and native versus Python fallback. Include pending runner tests and the archive expected failure. Attach the exact commands and artifact locations.
- [ ] If core work runs over, spend extension time on these gates first. Avoid starting a second packaging design while installer correctness is unresolved.

## Extension work · 4:20–8:00

### 6. Bring MCP coverage in line with CLI coverage · 4:20–5:15

**Files**

[Cross-format verifier](../../../scripts/verify_sys_native.py), Go hub and Python MCP only where routing requires a fix, and the coverage statements in the [November 23 handoff](../HANDOFF-2026-11-23.md).

- [ ] Reuse the existing Windows ARM64 EXE/DLL and PDB fixtures. Compare the same facts via the CLI, Go MCP, and Python MCP where the operation is exposed. Use a known export, entry mapping where applicable, and a proven call edge. Preserve the ARM64 IPA tests. Report each fixture/transport separately.
- [ ] Add one Linux ARM64 ELF fixture with a cross toolchain if available. Begin with a mapped entry, an independently checked direct call and xref, and format/architecture identification. Keep symbol and pseudocode assertions at the level the fixture can prove. Make absent prerequisites visible as a skip.
- [ ] Correct the handoff's transport claim from recorded results. Windows PE machine recognition, decoding, and structured decompilation need distinct evidence.

### 7. Prove the native archive contract · 5:15–6:45

**Files**

[Package tests](../../../tests/test_shipped_packages.py), [install documentation](../../../README.md), and the release build or CI files responsible for creating platform artifacts.

- [ ] Inventory current platform artifacts and where they come from. The reviewed local Windows and macOS archives lacked the documented executables. Pick the binary layout the launchers already resolve and validate archive entries, architecture, and checksums. Record any Python runtime dependency explicitly.
- [ ] Build one Windows x64 candidate and one macOS arm64 candidate with the necessary CI or native runners. Test a Linux candidate too. Use a clean profile and run `doctor --json`, a native `re overview` on a generated fixture, and an MCP handshake. Record the resolved executable and backend. A Python fallback alone cannot satisfy a native archive smoke test.
- [ ] Put the candidate-archive check in CI or provide a repeatable build-and-test entry point. Test generated artifacts independently of older local release archives. Keep the historic failure visible until an actual replacement is proven. No publication is needed to complete this task.

### 8. Close the test-filter verification gap · 6:45–7:25

**Files**

[Test runner](../../../xtforge/core/build/test_runner.py), [existing regression tests](../../../tests/test_test_runner_pattern.py), and its CLI/help only if the contract changes.

- [ ] Re-run a misspelled Go filter against a temporary module and an npm filter against a tiny Node project. Record the false success for zero selected Go tests and npm's ignored filter if still reproducible. Also check a real match and an intentional failing test.
- [ ] Use runner output that reliably distinguishes zero selected tests where supported. Reject unsupported npm filter semantics with a useful message. Keep Python name filtering working and apply the same zero-selection rule consistently to supported runners.
- [ ] Verify the JSON status and CLI exit status for match, failure, no match, and unsupported filter. Avoid treating earlier unrelated output as proof that a test ran.

### 9. Return a reviewable result · 7:25–8:00

- [ ] Run final checks from the repository root. Use the scoped Go invocation only where sockets are restricted. On a runner with loopback, run the unfiltered module suite as well.

```sh
git diff --check
uv lock --check --offline
UV_OFFLINE=1 python3 -m unittest discover -s tests
(cd native/xtforge-go && go test -count=1 ./... -skip '^TestConcurrentCVEEnrichmentWithMockServers$')
(cd native/xtforge-rs && cargo test --locked --offline)
node --test plugins/xt-native/test/*.test.mjs
python3 scripts/verify_sys_native.py
```

- [ ] Hand back a scoped diff, before/after reproductions, command output or log paths, and a table of actual platform and format coverage. Identify each skip, expected failure, intermittent failure, and reused binary. State which artifacts were built and which were exercised. Avoid broad release claims based on green Linux tests.
- [ ] List the files to include in the eventual commit and keep unrelated working-tree changes out of the review. Leave any remaining platform or feature work with the first failing check and the next concrete step.

## Backlog after this session

The REA follow-up brief remains the reference for evidence records, debug-file identity, and offline container inventory. Build on the existing doctor repair checks and analyst project storage before adding more tools. Prioritize evidence tied to file hash, member, slice, and backend. Expand real Apple container coverage, Linux ARM64 analysis, and typed symbol import as separate verified milestones.
