# xt-forge

Harness-agnostic agent toolkit for Termux/Android. Two implementations of one
tool surface: a Python reference (`xtforge/`) and a native Rust CLI
(`native/xtforge-rs/`), plus an MCP server and slash-command passthrough.

**Version:** `0.3.0-Damascus`. The root `VERSION` file is the single source of
truth (`name= / version= / codename=`) — read by `xtforge/version.py` and by
`xtforge version`.

## What's inside

- **cli** — unified dispatcher (`xtforge <group> <verb>`) + slash passthrough
- **mcp** — stdio MCP server exposing the full tool surface (38 tools)
- **flash** — sub-50ms key/value notes (#tags, TTLs, pins)
- **mem** — universal SQLite WAL + FTS5 memory, BM25 + recency search
- **goal** — bounded autonomous rounds with hard stop conditions
- **build** — staged pipeline: schema, DAG, per-phase fresh context, handoffs
- **route** — bounded filesystem/process inspection (tree/find/grep/peek/…)
- **compress** — L0–L3 squeezers that never drop error lines
- **calibrate** — reboot recalibration (WAL checkpoint, expiry purge, caps)
- **guard** — write-op safety gates (allowlist roots, confirm tokens)

## Layout

```
xt_forge/
├── VERSION                  # name=xt-forge / version= / codename=
├── bin/
│   ├── xtforge              # portable self-locating launcher (this repo)
│   └── xtforge-termux       # original absolute-path launcher (reference)
├── xtforge/                 # Python reference implementation
│   ├── cli/  core/  adapters/
│   └── version.py           # reads VERSION from repo root
├── native/xtforge-rs/       # Rust CLI (source + bench harness)
│   ├── src/                 # args calibrate compress flash guard main mem paths pyjson route util
│   └── bench-home/ bench.jsonl
├── data/                    # live-store snapshot from the origin phone
│   ├── mem.db  mem.db-wal   # SQLite WAL + FTS5 store
│   ├── flash/  cache/  runs/
└── AGENTS-BOOTSTRAP.md      # generated agent bootstrap doc (origin)
```

## Run

```sh
./bin/xtforge version
./bin/xtforge flash set "note #demo"
./bin/xtforge mem search "WAL" --k 3 --json
./bin/xtforge route tree .
```

Native build (optional, faster): `cd native/xtforge-rs && cargo build --release`.
The launcher prefers `target/release/xtforge-native` when present and falls
back to `python3 -m xtforge.cli`; `XT_FORCE_PYTHON=1` forces Python. If any
tool invocation fails because of a stripped harness PATH, set
`export PATH="/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/home/bin:$PATH"`
first.

## Data

Runtime state lives in `$XT_HOME` (default `~/.xt-forge`): `mem.db` (+WAL),
`flash/`, `cache/`, `runs/`. `data/` here is a snapshot of the live store from
the origin phone — copy it to `~/.xt-forge` to resume identical state, or point
the launcher at it directly:

```sh
XT_HOME="$PWD/data" ./bin/xtforge mem search "campaign" --k 5
```

## Notes

- Python package is stdlib-only (no pip deps).
- `native/xtforge-rs` needs a Rust toolchain to build; source syncs are manual.
- Slash commands (`/m` `/mg` `/ml` `/mp` `/mx` `/mc` `/mw` `/mu` `/help`) run
  via `xtforge slash` and need no model call.
