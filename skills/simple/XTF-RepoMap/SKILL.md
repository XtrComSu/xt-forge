---
name: XTF-RepoMap
description: Map workspace structure and budgeted excerpts before opening files blindly.
---

# XTF-RepoMap (Simple Tier)

**Quick start:** `xt-forge route context . --token-budget 1200`

Get fast structural situational awareness in one call without dumping raw trees or bloating context.

## When to use
- Starting work in an unfamiliar repository or module.
- Before grepping blindly across large directories.

## Workflow
1. Pull a token-budgeted map and key file excerpts:
   ```sh
   xt-forge route context . --token-budget 1200
   ```
2. Find files by glob or locate candidate entrypoints:
   ```sh
   xt-forge route find . --glob "*.rs" --limit 25
   ```
3. Search ranked pattern matches with bounded context:
   ```sh
   xt-forge route grep . --pattern "ServeMeta" --limit 10
   ```
4. Peek only the exact slices needed:
   ```sh
   xt-forge route peek path/to/file.py --start 1 --count 60
   ```

## Guardrails
- Keep `--token-budget` between 600 and 1600 on initial orientation.
- Do not cat entire multi-thousand-line files when `route peek` covers the slice.
