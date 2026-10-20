# Changelog

Version scheme: `MAJOR.MINOR.PATCH-<codename>`; the root `VERSION` file is the
single source of truth. This repo is a consolidation snapshot of the xt-forge
line (origin: `sample-app/xtforge` + `native/xtforge-rs`, plus the live
`~/.xt-forge` store), created 2026-10-19 for portable backup and install.

## 0.3.2-Damascus — 2026-10-21

Three defects in the shipped taste plugin, found by auditing a live profile
rather than by reading the code. All three made the profile lie about what
the user had asked for.

- **fix(taste): a rule the user avoided was injected as an instruction to
  do it.** The statement is the subject of a preference ("fabricate output")
  and the polarity says which way it points, but the injected block rendered
  the statement alone. A user who wrote "Never fabricate output" had
  `<rule>fabricate output</rule>` injected into every session — the exact
  opposite of the instruction. The block now renders a negative learning as
  a prohibition, and a statement that is already a prohibition is not
  prefixed twice
- **fix(taste): one prompt was ingested once per location.** The plugin is
  loaded once per location, so the prompt hook fired two or three times for
  the same prompt and each copy counted as another piece of evidence. A rule
  the user stated *once* reached `enforced` and was injected into every
  session, while the evidence log showed the same quote repeated. The
  prompt carries an id that is unique per admitted prompt, so it is now the
  deduplication key: one prompt, one signal
- **fix(taste): `xtforge taste repair`** collapses evidence the plugin
  recorded twice and recomputes the counters it inflated. Two rows are the
  same observation when they carry the same kind, quote and source and were
  recorded in the same second; a user who states the same thing again
  later is evidence and is kept, and a deliberate `manual` learning is never
  collapsed. Read-only unless `--apply`
- cli: `xtforge taste repair` (report by default, `--apply` to fix)
- 408 python tests + 17 plugin tests green

## 0.3.1-Damascus — 2026-10-20

- plugin: the OpenCode taste plugin is source in this repo
  (`plugins/xt-native/`) and ships with `xtforge plugin install|status|
  uninstall`; `xtforge sync` installs it too. Installed byte-for-byte and
  stamped with the paths the plugin needs, so the copy on a machine is not
  pinned to one home directory. Without a stamp the plugin degrades to a
  no-op instead of guessing
- plugin: D2 acceptance — **10 scripted sessions -> 6 expected learnings, 0
  invented keys, 1 enforced rule injected** (`plugins/xt-native/test/
  taste.sessions.test.mjs`); near-miss prompts stay silent and a hint never
  reaches the session
- plugin: 11 contract tests drive the real plugin with a mock OpenCode
  context (`plugins/xt-native/test/plugin.test.mjs`) — commands, hooks, the
  injected block, a fabricated completion claim, loop scheduling, and
  degradation when xt-forge is missing
- doctor: reports the plugin as installed / registered / current, with the
  drift list, instead of a single boolean that could not see it
- sync: writes the OpenCode config in the shape OpenCode v2 reads
  (`mcp.servers`, `plugins`), leaves a working MCP command alone, and backs
  up the config it rewrites
- sync: the AGENTS.md template ships again (`adapters/generic/AGENTS.md.tpl`)
  and the generated launcher points at an interpreter and a shell that exist
- cli: `xtforge plugin install|status|uninstall|manifest`
- taste: the extractor only creates a key from a preference word (always,
  never, prefer, avoid, please use, "use X not Y"). A bare "use" is a work
  order far more often than it is a durable preference — 19 of the 23 live
  learnings were invented by the old, looser rules
- taste: `taste prune` retires the learnings the current rules would no
  longer invent, so a scheduled tidy can clean the profile without guesswork
- taste: concurrent writes no longer lose evidence. Absorbing a signal is a
  read-modify-write, and SQLite's deferred transaction did the read *outside*
  the write lock — so two processes learning the same key both read the same
  row and both wrote it back, and one piece of evidence was gone. Four
  concurrent writers recorded **1** piece of evidence instead of 4, so the
  rule never reached `enforced` and was never injected into a session. The
  store now takes the write lock before the read (`BEGIN IMMEDIATE`): 4
  writers record 4 pieces of evidence and the rule is `enforced`
  (`scripts/repro_taste_lost_update.py`; regression test in
  `tests/test_taste.py`)
- taste plugin: prompt ingests are serialised, so a learning's statement is
  decided by the order the preference was said, not by process timing
- goal/loop: session-scoped goals, restart-safe loops, self-paced backoff
- suite: 393 tests green, including the plugin's own runtime tests on Node

## 0.3.0-Damascus — 2026-10-06

- build: type 2 (specbuild) pipeline
- theme: XT-Code AMOLED

## 0.2.0-Damascus — 2026-10-06

- release: harness sync, plugin wiring, 38-tool MCP server, doctor
- build: mid-phase crash resume re-executes exactly once (A8)
- cli: package split; MCP flash/compress/goal tools; audit S18 fixes
- docs+tests: protocol/README/decisions, hardening suite, PROGRESS

## 0.1.0-Damascus — 2026-10-05

- cli+mcp: unified CLI dispatcher, MCP stdio server
- adapters: OpenCode adapter + generic harness + slash core
- build: staged pipeline — schema, DAG, handoff, gates, runner, drivers

## Snapshot notes — 2026-10-19

- included: `xtforge/` Python package (stdlib-only), `native/xtforge-rs`
  source + bench harness, `bin/` launchers (portable + origin reference),
  live store snapshot under `data/`
- excluded: native build artifacts (`target/`), `__pycache__/`, `mem.db-shm`
