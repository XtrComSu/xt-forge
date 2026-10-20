# <app> agent bootstrap

**Version:** <version>

This file is generated and maintained by `<app>` (adapted per harness).
It registers reasoning rules and tool surfaces; slash commands work through
the harness shell passthrough.

## What <app> is

Harness-agnostic agent toolkit:
- **Flash memory**: sub-50ms key/value notes with #hashtags, TTLs, pins.
- **Universal memory**: SQLite WAL + FTS5 shared across every harness.
- **Taste learning**: deterministic preference learning, enforced rules ride
  along with the session.
- **Goal loop**: bounded autonomous rounds with hard stop conditions.
- **Build mode**: staged pipeline with fresh context per phase + handoffs.
- **Compression**: L1/L2 squeezers that never drop error lines.
- **Route tools**: safe capturing filesystem/process/device inspection.

## Commands (run via shell; requires no model call)

Use the absolute launcher path: `<bin>`. The harness shell PATH usually lacks
`~/bin` and the tool prefix, so bare `python3` / `<app>` will fail.

    <bin> flash set "note #tag"          # /m
    <bin> flash get <key>                # /mg
    <bin> flash list [n]                 # /ml
    <bin> flash pin <key>                # /mp
    <bin> flash delete <key>|--all       # /mx
    <bin> flash compact                  # /mc
    <bin> flash list --pin-only          # /mw (wired prefix context)
    <bin> mem put|get|search|list|forget|review|export|sync
    <bin> route tree|find|grep|peek|du|recent|where|index|context|errors
    <bin> taste search|show|review|stats|learn|forget|inject
    <bin> goal status|pause|resume|stop|extend|run|verify
    <bin> build list|run|resume|status|graph|lint|new
    <bin> calibrate [--force|--status]     # reboot recalibration (WAL/flash/caps)
    <bin> compress L1 --text "..."          # L0..L3, never drops error lines
    <bin> slash /m "note"                  # any slash command, scripted
    <bin> sync --dry-run                   # verify harness wiring
    <bin> doctor                           # environment probe + integration
    <bin> version

For one-liners (reporting, jq-free pipelines) add `--json` anywhere:
`<bin> mem search "WAL" --k 3 --json`.

## Paths

- tool root: `<root>`
- runtime state: `<xt_home>`
- installed at: `<home>`

## Trust order for decisions

user instructions > gates/verifier feedback > handoff packets > memory > guesses.
Never fabricate command output. Prefer a verify step after every change.

## Safety rules

- Read-only by default; writes require an allowlisted root and a confirm token.
- Never encode engine submissions in the body when the report contract forbids them.
