# xt-forge

Harness-agnostic agent toolkit for Termux/Android. Two implementations of one
tool surface: a Python reference (`xtforge/`) and a native Rust CLI
(`native/xtforge-rs/`), plus an MCP server and slash-command passthrough.

**Version:** `0.3.0-Damascus`. The root `VERSION` file is the single source of
truth (`name= / version= / codename=`) — read by `xtforge/version.py` and by
`xtforge version`.

## What's inside

- **cli** — unified dispatcher (`xtforge <group> <verb>`) + slash passthrough
- **mcp** — stdio MCP server exposing the full tool surface (51 tools)
- **taste** — deterministic preference learning: `taste learn|ingest|search|show|
  review|forget|export|import|inject|stats|prune|repair`, contradictions flagged
  not overwritten. Drives the `/taste` command and system-block injection in the
  OpenCode plugin (`plugins/xt-native/`, installed to
  `~/.config/opencode/plugins/xt-native/`)
- **plugin** — the OpenCode plugin is source in this repo (`plugins/xt-native/`)
  and `xtforge plugin install|status|uninstall|manifest` puts it on a machine:
  install copies the source, stamps the paths the plugin needs and registers
  it in the OpenCode config; `status` reports drift between the installed copy
  and the source. `xtforge sync` asks the same code to do the work
- **repos** — bundled top-repos catalog, offline (list/search/show/domains/suggest/plan/stats/export)
- **flash** — sub-50ms key/value notes (#tags, TTLs, pins)
- **mem** — universal SQLite WAL + FTS5 memory: hybrid BM25 + embedding search,
  typed links, and a review queue for staged candidates
- **goal** — bounded autonomous rounds with hard stop conditions, plus the
  `<goal-done>` completion protocol: evidence is replayed and re-checked, and
  unproven "done" claims are rejected (5/5 fabrications caught in tests)
- **build** — staged pipeline: schema, DAG, per-phase fresh context, handoffs
- **route** — bounded filesystem/process inspection (tree/find/grep/peek/…),
  plus ranked grep and query-aware context packing (`route context --query`)
- **code** — structure extraction: `code symbols|outline|refs`, real AST for
  Python and conservative declaration heuristics elsewhere
- **scan** — static safety scan: `scan secrets|patterns|deps`; matched values
  are masked unless you pass `--reveal`
- **re** — binary inspection and native RE: `re info|needed|sections|symbols|
  strings|entropy|pack|ioc|disasm|graph`. `ioc` extracts indicators with
  credentials masked; `graph` maps imports, exports and call sites — the
  native alternative to a 200-tool RE server
- **docs** — live library documentation (`docs search|resolve|show`), from
  Context7's HTTP API as one verb instead of two MCP schemas
- **intel** — keyless threat intel (`intel ip|domain|cve|kev|search|hash`):
  Shodan InternetDB, GreyNoise, NVD, EPSS, CISA KEV, CIRCL and native DNS in
  one verb, including SPF/DMARC spoofability. VirusTotal and MalwareBazaar
  join automatically when `XT_VT_KEY` / `XT_ABUSECH_KEY` are set
- **hub** — HuggingFace (`hub models|datasets|show|files`): what exists, how
  big each quantisation is, what a model is based on
- **codec** — hash, encode/decode, round-trip check, entropy, and `inspect`
  that identifies JWT, PEM, UUID, semver, timestamps, URLs and more
- **recon** — scoped findings ledger (`new note finding list report stats`)
  whose report regenerates byte-identical from the ledger
- **eval** — benchmark runs (`record list show compare report`); `compare`
  calls regressions by direction and exits non-zero, so a bench can gate a
  release
- **skills** — 67 agent skills in `~/.config/opencode/skills/`: 7 for this
  toolkit, 21 software, 8 engineering-process, 7 AI/ML and 24 harvested
  security skills (Apache-2.0, licence-clean). One skill per job, enforced by
  the generators. Harvest record and context budget: `docs/SKILLS.md`
- **integrations** — MCP/plugin survey with decisions in `docs/INTEGRATIONS.md`.
  Installed `context7` (2 tools, live library docs). Tool schemas cost context
  every step, so the rule is "does this earn its schema?" — which rejected a
  200-tool RE server in favour of folding its capability into `re`
- **loop** — scheduled work with a real grammar: `xtforge loop parse|normalize|
  markers|next|policy`, plus `/loop`, `/loops`, `/loop-stop` in the plugin.
  Self-paced iterations end in `<loop-next>`/`<loop-done>`; a missing marker
  gets one safety check, not a guess
- **compress** — L0–L3 squeezers that never drop error lines
- **calibrate** — reboot recalibration (WAL checkpoint, expiry purge, caps)
- **guard** — write-op safety gates (allowlist roots, confirm tokens)

## Planning artifacts

- **`catalog/top-repos/`** — rebuilt corpus: 4,810 unique repos across 65
  sections, scored and grouped by CS domain. Start with `ANALYSIS.md` or the
  short `TOP-IDEAS.md`.
- **`docs/plan-top-repos-learning.md`** — 12-round proposal for turning the
  catalog into capability families, with acceptance criteria and open questions.
- **`docs/OPENCODE-NATIVE-TASTE-LOOP.md`** — native OpenCode design for taste
  learning, `/goal` and `/loop`, including budgets, verification and privacy.

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
├── adapters/mcp/server.py   # MCP server (44 tools) + snippets/ for new surfaces
├── adapters/generic/        # AGENTS.md template for shell-only harnesses
├── plugins/xt-native/       # the OpenCode plugin: source, its own tests
│   ├── index.ts  package.json
│   └── test/                # node --test plugins/xt-native/test/
├── catalog/top-repos/       # 4,810-repo corpus: index.json, ANALYSIS.md, TOP-IDEAS.md
├── scripts/                 # catalog_top_repos, analyze_catalog, validate_catalog,
│                            # scaffold_tool, bench_mem_recall, bench_context_pack,
│                            # bench_secret_scan
├── tests/                   # contract tests: python3 -m unittest discover -s tests
├── docs/                    # plan-top-repos-learning.md, OPENCODE-NATIVE-TASTE-LOOP.md, specs/
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
./bin/xtforge repos suggest memory --limit 5
./bin/xtforge repos plan mem0ai/mem0 --ns mem --tool-verb recall
./bin/xtforge code symbols xtforge/core/mem/search.py
./bin/xtforge route context . --query "where is the write guard"
./bin/xtforge scan secrets . --limit 20
./bin/xtforge re info /bin/ls
./bin/xtforge plugin install     # ship the OpenCode plugin
./bin/xtforge plugin status      # installed? registered? still current?
python3 -m unittest discover -s tests
node --test plugins/xt-native/test/            # the plugin's own tests
python3 scripts/bench_mem_recall.py && python3 scripts/bench_context_pack.py \
  && python3 scripts/bench_secret_scan.py
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
