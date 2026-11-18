---
name: XTF-Unpack
description: Unpack Electron ASAR bundles, inspect Android APKs, and triage HAR/SAZ network captures offline.
---

# XTF-Unpack (Complex Tier)

**Quick start:** `xt-forge re asar app.asar --limit 100` | `xt-forge re apk app.apk` | `xt-forge re netcap session.har`

Dissect packaged client bundles, mobile installers, and HTTP traffic archives in pure Go without launching Electron or heavyweight interceptors.

## When to use
- Auditing desktop Electron apps (`.asar`), Android APKs (`.apk`), or saved HAR/Fiddler SAZ HTTP logs.
- Looking for exposed source maps, excessive Android permissions, or leaked Authorization headers.

## Workflow
1. List files, detect exposed `.map` source maps, and selectively unpack Electron ASAR archives:
   ```sh
   xt-forge re asar resources/app.asar --limit 100
   xt-forge re asar resources/app.asar --out ./unpacked-asar
   ```
2. Parse Android APK manifests, requested permissions, activities, receivers, and bundled `.so`/`.dex` entries:
   ```sh
   xt-forge re apk target.apk
   ```
3. Triage HAR or SAZ traffic captures with automatic credential redaction:
   ```sh
   xt-forge re netcap session.har --limit 50
   ```
4. Pair unpacked JS or API routes with secret scanning:
   ```sh
   xt-forge scan secrets ./unpacked-asar
   ```

## Guardrails
- Set `--out` only inside an allowlisted writable directory; all secrets in `netcap` output stay masked.
