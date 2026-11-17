---
name: XTF-Crucible
description: Curate durable memory, taste rules, and benchmark deltas across sessions without drift.
---

# XTF-Crucible (Advanced Tier)

Compound verified architectural facts, negative anti-patterns, deterministic style preferences, and quantitative eval regressions across sessions.

## When to use
- Capturing hard-won lessons (`failed_attempt`, `anti_pattern`, architectural decisions) so future sessions do not repeat mistakes.
- Reviewing user preferences (`taste`) and tracking benchmark scores (`eval`).

## Workflow
1. Search existing durable memory before re-deriving past solutions:
   ```sh
   xt-forge mem search "auth middleware timeout" --k 3 --json
   ```
2. Record verified conclusions or anti-patterns and link related entries:
   ```sh
   printf '%s\n' "Verified cause at router.go:114" | xt-forge mem put --title "router timeout stems from unbuffered ctx" --body-file - --kind fact --tag architecture
   xt-forge mem link <new_id> <old_bug_id> --rel fixes
   ```
3. Manage deterministic preference rules (`taste`):
   ```sh
   xt-forge taste learn --body-file - <<< "Always verify Go builds with -race"
   xt-forge taste stats
   xt-forge prompt inject
   ```
4. Log benchmark metrics and compare deltas across commits:
   ```sh
   printf '{"pass_rate": 1.0, "ms": 42}\n' | xt-forge eval record --suite core --body-file -
   xt-forge eval compare core
   ```

## Guardrails
- Never record secrets, passwords, tokens, or unverified hypotheses as settled facts (`--pending` if unsure).
- Treat stored memory entries as claims to verify against the current file on disk.
