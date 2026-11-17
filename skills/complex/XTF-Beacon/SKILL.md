---
name: XTF-Beacon
description: Extract network IOCs, hashes, paths, and credentials from artifacts and enrich via keyless intel.
---

# XTF-Beacon (Complex Tier)

Chain local indicator extraction directly into keyless threat intelligence enrichment.

## When to use
- Triaging suspicious scripts, firmware dumps, binaries, or captured configuration artifacts.
- Turning raw string dumps into verified IPs, domains, hashes, and CVEs.

## Workflow
1. Extract indicators (URLs, IPs, domains, emails, MD5/SHA1/SHA256, CVEs, registry keys, credential URLs with passwords masked):
   ```sh
   xt-forge re ioc artifact.bin --json
   ```
2. Enrich discovered public IPs via InternetDB and GreyNoise:
   ```sh
   xt-forge intel ip 203.0.113.10
   ```
3. Resolve DNS records and mail posture (SPF/DMARC hints) for extracted domains:
   ```sh
   xt-forge intel domain suspicious-domain.example
   ```
4. Verify benign vs unknown file hashes against CIRCL hashlookup:
   ```sh
   xt-forge intel hash <sha256>
   ```

## Guardrails
- Never submit internal hostnames, private IPs, or raw credentials upstream.
- Record verified IOC hits directly into the active recon ledger (`xt-forge recon finding`).
