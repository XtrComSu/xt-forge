---
name: XTF-CVELookup
description: Look up CVEs, CVSS scores, EPSS exploit probabilities, and CISA KEV status without API keys.
---

# XTF-CVELookup (Simple Tier)

**Quick start:** `xt-forge intel cve CVE-2024-3094`

Enrich vulnerabilities and software components rapidly using cached, keyless public feeds.

## When to use
- Triaging dependency audit warnings, security advisories, or discovered product versions.
- Prioritizing patching by combining severity with real-world exploitation likelihood.

## Workflow
1. Inspect full CVE context (NVD CVSS + CWE + FIRST EPSS + CISA KEV):
   ```sh
   xt-forge intel cve CVE-2024-3094
   ```
2. Search NVD by software keyword, optionally bounded by recent publication window:
   ```sh
   xt-forge intel search openssh --since 90 --limit 10
   ```
3. Check the CISA Known Exploited Vulnerabilities feed:
   ```sh
   xt-forge intel kev --query ivanti --limit 15
   ```

## Guardrails
- Pass only public CVE IDs or generic software keywords.
- Set `XT_NET_OFFLINE=1` when verifying strictly from the local cache.
