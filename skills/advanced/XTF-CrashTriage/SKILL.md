---
name: XTF-CrashTriage
description: Analyze crash minidumps, extract faulting frames, and track findings in a recon ledger.
---

# XTF-CrashTriage (Advanced Tier)

**Quick start:** `xt-forge re crash crash.dmp --json` & `xt-forge recon finding <target> ...`

Perform structured postmortem triage on Windows minidumps (`.dmp`) or ELF crashes and log evidence into a clean audit ledger.

## When to use
- Reproducing crashes, investigating unhandled exceptions, or documenting security audit findings.
- Maintaining reproducible evidence trails across long multi-target assessments.

## Workflow
1. Initialize a campaign ledger in XT-Forge:
   ```sh
   xt-forge recon new service-audit
   ```
2. Inspect crash dump metadata, exception codes, faulting addresses, and loaded modules:
   ```sh
   xt-forge re crash crash.dmp --json
   xt-forge re crash crash.dmp --extract-modules
   ```
3. Correlate crash addresses with binary symbols, checksec posture, and C++ RTTI:
   ```sh
   xt-forge re symbols service.exe --limit 100
   xt-forge re checksec service.exe
   ```
4. Log severity-ranked findings and render a scrubbed Markdown report:
   ```sh
   xt-forge recon finding service-audit --severity high --title "Null deref in parseHeader()" --body "Observed at RVA 0x18a20"
   xt-forge recon report service-audit
   ```

## Guardrails
- Run `xt-forge scan secrets` on generated recon reports before exporting outside your local host.
