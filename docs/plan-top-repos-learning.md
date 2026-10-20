# Plan: turn the top-repos catalog into xt-forge capability

Status: **rounds 1–3 shipped (2026-10-19)** · owner: xt-forge · version target `0.4.0`
Companions: `catalog/top-repos/ANALYSIS.md`,
`docs/OPENCODE-NATIVE-TASTE-LOOP.md`

---

## 1. Objective

Use the most-starred repositories in the ecosystem as **design evidence**, not
as dependencies. For each capability family we extract the mechanic that makes
the top repos good, rebuild it in xt-forge's own stdlib-first style, and expose
it through the same surfaces every existing tool already has:

1. a CLI verb with `--json`
2. an MCP tool with a strict schema (when promoted; CLI-first otherwise)
3. a guarded implementation with tests and a measured before/after

The deliverable is **not 1,888 tools**. It is a small set of composable
surfaces that make the agent's daily loop faster, safer and more predictable.

---

## 2. What the catalog contains

The corpus was rebuilt with `scripts/catalog_top_repos.py` (65 GitHub Search
queries, top 100 each, deduplicated by `full_name`):

- **4,810** unique repositories
- **65** sections / queries
- **36** CS domains
- licenses: MIT 1,615 · Apache-2.0 1,034 · NOASSERTION 668 · none 502 · GPL-3.0 348
- fit analysis: `scripts/analyze_catalog.py` → `ANALYSIS.md` and
  `tool-candidates.json`

The categories that matter most for xt-forge, by candidate count:

| CS field (union) | repos | what it informs |
|---|---:|---|
| information retrieval + databases | 357 | memory, embeddings, context packing |
| cybersecurity + red teaming + RE | 934 | guard, scanning, binary inspection |
| software engineering + workflow | 911 | CLI, testing, workflow, git |
| AI + agents + protocols | 661 | prompts, agents, inference, datasets |
| systems + databases + networking | 998 | storage, scheduling, process control |
| education + knowledge | 480 | learning corpus and exercises |

Counts are unique repos whose domain tags intersect each row's set; a repo can
appear in more than one row. Per-domain numbers are in `ANALYSIS.md`.

The full per-domain breakdown, top 250 ranked candidates and the adoption rules
are in `catalog/top-repos/ANALYSIS.md`. A review-friendly shortlist (at most
three repos per proposed surface) is in `catalog/top-repos/TOP-IDEAS.md`.

**Provenance.** The original corpus was produced on 2026-10-15 by goal run
`goal-a33d846014` (1,888 repos / 56 sections) and lived on the phone at
`~/goal-artifacts/top-repos/`. Those files are not recoverable on this host.
This rebuild supersedes them: it uses 65 explicit queries and is reproducible
from `scripts/catalog_top_repos.py`. Counts may differ because the query set
and GitHub's index changed; the original run metadata is preserved in
`~/.xt-forge/runs/goal-a33d846014/goal.json`.

---

## 3. Capability families (what is useful for what)

Instead of one tool per repo, candidates graduate into twelve families. A
family ships only when it has a clear caller in the agent loop.

| # | family | repos that define the state of the art | xt-forge surface | priority |
|---|---|---|---|---|
| 1 | Memory & retrieval | mem0, Letta, txtai, FAISS, LanceDB, Qdrant | `mem`, `mem embed`, `mem link` | P0 |
| 2 | CLI & config UX | cobra, typer, fzf, jq, delta, starship | `cli`, `config` | P0 |
| 3 | Filesystem & code navigation | ripgrep, fd, ast-grep, tree-sitter | `route`, `code parse` | P0 |
| 4 | Compression & context | headroom, repomix, rtk, RAGFlow | `compress`, `route context` | P0 |
| 5 | Safety & security | trufflehog, semgrep, gitleaks, nuclei, radare2 | `guard`, `scan`, `re` | P0 |
| 6 | Goals, loops & scheduling | AutoGPT, OpenHands, SWE-agent, Temporal, healthchecks | `goal`, `loop` | P0 |
| 7 | MCP & tool protocols | MCP servers, fastmcp, mcp-toolbox, github-mcp-server | `mcp bridge`, `tool registry` | P0 |
| 8 | Evaluation & testing | pytest, hypothesis, promptfoo, SWE-agent, cua | `eval`, `bench` | P1 |
| 9 | Docs & learning | mkdocs-material, Docusaurus, awesome lists, roadmaps | `docs`, `learning corpus` | P1 |
| 10 | Observability | OpenTelemetry Collector, Sentry, rich | `route errors`, `doctor` | P1 |
| 11 | Git & workflow | git, gh, delta, pre-commit (study-only) | `git tools`, `build` | P1 |
| 12 | Device & edge | Termux, llama.cpp, on-device runtimes | `phone`, `model` | P2 |

### Priority rationale

- **P0** removes friction or risk from every session: retrieval, navigation,
  context size, safety, autonomy, protocol plumbing.
- **P1** improves quality but is not on the critical path.
- **P2** is environment-specific; it must degrade gracefully on non-Termux
  hosts.

---

## 4. The repo → tool pipeline

```
harvest ─▶ normalize ─▶ classify ─▶ rank ─▶ distill ─▶ scaffold ─▶ verify
 (done)      (done)       (done)     (done)    (manual)    (round 3)   (round 3)
```

| stage | input | output | status |
|---|---|---|---|
| harvest | 65 queries | `catalog/top-repos/raw/*.json` | done |
| normalize | raw responses | deduped `index.json`, CSV, markdown | done |
| classify | section + topics + description | `domains`, `cs_fields` | done |
| rank | keyword fit + stars + recency + license | `fit_score`, `verdict`, `tool_ideas` | done |
| distill | top candidate | one-page **tool spec**: problem, mechanic, API, checks | round 3 |
| scaffold | tool spec | dry-run CLI/MCP/test skeleton, no deps | round 3 |
| verify | scaffold | parity tests, guard path, benchmark | every round |

**Adoption tiers** (recorded per candidate):

| tier | meaning | allowed action |
|---|---|---|
| `adopt` | mechanic is directly useful, permissive license, active | clean-room reimplementation |
| `borrow` | useful mechanic, integration cost or license caveat | adapt one idea, cite the repo |
| `study` | conceptual value only | notes, no code |
| `skip` | stale, archived, fork, unclear license, or no caller | nothing |

Rules:

1. **No vendoring.** Repos are read; xt-forge keeps its own implementations.
2. **License first.** GPL/AGPL is study-only. No license means all rights
   reserved.
3. **One caller rule.** A tool ships only if a CLI verb, MCP schema, or an
   agent loop actually calls it.
4. **Dependency budget.** New runtime dependencies require explicit approval
   and a capability probe + graceful fallback.
5. **Measure or it did not happen.** Every adopted mechanic records latency,
   tokens or correctness before/after in the changelog.

### Tool spec template

Every candidate that leaves `study` gets one page before code:

```markdown
# <owner/name> → <surface>

- tier: adopt | borrow · license: <spdx> · stars: <n> · last push: <date>
- mechanic (what actually makes it good): <one paragraph>
- why now (caller): <the CLI verb / agent loop that needs this>
- surface: `xtforge <noun> <verb> --json` + `<noun>_<verb>` MCP tool
- data: <files, indexes, schemas> · writes: <none | guarded path>
- failure modes: <missing tool, huge input, binary file, encoding>
- guard: <read-only | write token | allowlist root>
- tests: <fixtures + parity + negative cases>
- measurement: <latency / tokens / recall / pass rate before-after>
- decision: <implement | defer | reject, with reason>
```

---

## 5. New surfaces

### 5.1 `repos` — the catalog, offline

The catalog is bundled; no network call is needed at runtime.

```
xtforge repos list [--domain X] [--verdict adopt|borrow|study] [--limit N]
xtforge repos search <query> [--k N]
xtforge repos show <owner/name>
xtforge repos domains
xtforge repos suggest --capability memory|security|cli|...
xtforge repos plan <owner/name>          # print the distillation template
xtforge repos stats
xtforge repos export --format json|csv|md
```

MCP additions (6 — matches the original plan's 41→47 shape):

| tool | purpose |
|---|---|
| `repos_search` | BM25-ish search over name/description/topics |
| `repos_show` | full record + fit + proposed ideas |
| `repos_domains` | domain counts and representative repos |
| `repos_suggest` | candidates for a capability family |
| `repos_plan` | distillation template for one candidate |
| `repos_stats` | corpus/license/verdict summary |

Storage: `catalog/top-repos/index.json` loaded lazily, indexed in memory.
Latency target: p95 < 100 ms, zero writes, read-only guard.

### 5.2 `taste` — local preference learning

Six MCP tools and a CLI namespace, described in
`docs/OPENCODE-NATIVE-TASTE-LOOP.md`:

```
xtforge taste ingest|search|show|review|learn|forget|export|import|stats
```

### 5.3 `goal` / `loop` — bounded autonomy

```
xtforge goal start|status|tick|verify|pause|resume|stop|log
xtforge loop parse|list|cancel        # pure helpers; scheduling in the harness
```

MCP: six `goal_*` tools including `goal_tick` and `goal_verify`; loop helpers
are read-only.

### 5.4 Capability tools derived from the catalog

| namespace | first verbs | source families |
|---|---|---|
| `code parse` | `ast`, `symbols`, `refs` | tree-sitter, ast-grep, ctags |
| `scan` | `secrets`, `patterns`, `deps` | trufflehog, semgrep, gitleaks |
| `re` | `info`, `sections`, `symbols`, `strings`, `entropy` | radare2, LIEF, pefile |
| `eval` | `run`, `score`, `compare`, `record` | pytest, promptfoo, inspect_ai |
| `git tools` | `diff`, `apply`, `worktree`, `pr` | git, gh, pre-commit |
| `docs` | `index`, `drift`, `render` | mkdocs, Docusaurus |
| `net` | `dns`, `http`, `probe` | curl, dig, mkcert |
| `model` | `list`, `probe`, `quant` | llama.cpp, gguf tools |

Each follows the same acceptance gate: CLI `--json`, guard path, tests and a
benchmark. In `0.4.0` these ship **CLI-first**: MCP promotion is deferred so
the tool-count cap holds. Promoting one requires retiring or merging another
tool first.

### 5.5 Learning corpus (JSONL)

The catalog doubles as a learning dataset. `xtforge repos export --format
jsonl` emits one row per repo:

```json
{"id":"owner/name","url":"https://github.com/owner/name","stars":12345,
 "section":"security","domain":"cybersecurity","cs_field":"program analysis",
 "mechanic":"rule-based static analysis","tool_idea":"scan patterns",
 "exercise":"Implement a 20-line rule engine and run it on a fixture.",
 "difficulty":"intermediate","license":"MIT"}
```

Rules:

- exercises are generated from **templates per capability family**, not by an
  LLM, so they stay reproducible and license-safe
- `difficulty` is derived from stars, language and family (beginner /
  intermediate / advanced)
- rows are filtered to permissive licenses for public distribution; copyleft
  rows keep metadata but no copied text
- the dataset is an artifact (`catalog/top-repos/learning.jsonl`), not a
  runtime dependency

---

## 6. Taste, goal and loop in OpenCode

Command Code's public mechanics are adapted natively:

- **Taste**: deterministic symbolic learner (`alpha/beta` confidence, fixed
  categories, contradiction flagged, markdown export). No proprietary model and
  no LLM-written confidence. Signals come from prompt text, correction diffs,
  permission decisions and tool outcomes; enforced rules are injected as a
  bounded `<taste>` system block.
- **Goal**: standing objective with turn/token/time budgets, a completion
  marker, and an **independent verifier** that replays evidence and rejects
  unproven claims. Restored goals are idle, never auto-running.
- **Loop**: fixed or self-paced scheduler, cron-normalised intervals,
  quiet-streak backoff, seven-day lifetime, `loop.md`, prompt-injection fencing
  and explicit cancellation.

Full design and acceptance tests: `docs/OPENCODE-NATIVE-TASTE-LOOP.md`.

---

## 7. Twelve rounds

Each round ends with a green test run, a changelog entry and a measured check.

| round | deliverable | files | acceptance |
|---:|---|---|---|
| 1 | Bundle catalog + validator + `repos list/search/show` | `catalog/top-repos/`, `xtforge/core/repos/`, `cli/repos_cmd.py` | 65-query rebuild reproduces ≥1,888 unique; 10/10 invariants pass |
| 2 | `repos suggest/domains/stats` + 6 MCP tools + ranking | `core/repos/rank.py`, `adapters/mcp/server.py` | CLI/MCP JSON parity; p95 <100 ms; no network |
| 3 | Distill/scaffold pipeline: tool spec template, dry-run scaffold, registry hook | `core/repos/spec.py`, `scripts/scaffold_tool.py` | 5 candidates produce valid specs; scaffold writes nothing without `--write` |
| 4 | Memory family (mem0, Letta, txtai, FAISS): hybrid BM25+embedding fallback, typed links, review queue | `core/mem/`, `cli/mem_cmd.py` | recall@5 improves on a 50-query fixture; FTS-only path unchanged |
| 5 | Route/code family (ripgrep, ast-grep, tree-sitter, repomix): AST parse, ranked grep, context packing | `core/route/`, `core/code/` | 30% token reduction at equal answer accuracy on 20 tasks |
| 6 | Safety family (trufflehog, semgrep, gitleaks, nuclei, radare2): secret scan, pattern audit, `re` info/sections/strings | `core/scan/`, `core/re/`, `cli/scan_cmd.py` | 0 false negatives on a seeded secret fixture; no file writes |
| 7 | Compress/eval family (headroom, promptfoo, pytest, hypothesis): structured squeezers, eval recorder | `core/compress/`, `core/eval/` | error lines preserved 100%; eval replay is deterministic |
| 8 | Taste core: schema, learner, SQLite, markdown, CLI, 6 MCP tools | `core/taste/`, `cli/taste_cmd.py` | confidence monotonic; contradiction flagged; deterministic replay |
| 9 | OpenCode taste plugin: signals, injection, `/taste` | `~/.config/opencode/plugins/xt-native/` | 10 scripted sessions → expected learnings, zero invented keys |
| 10 | Goal machine (AutoGPT, OpenHands, SWE-agent) + verifier + `/goal` | `core/goal/`, plugin `goal/` | 5/5 false completion claims rejected; budget pause works |
| 11 | Loop parser/scheduler (healthchecks, Temporal) + `/loop` + `loop.md` | `core/loop/`, plugin `loop/` | interval table passes; restart-safe; cancel leaves no timer |
| 12 | Hardening + docs + benchmarks + release | docs, tests, `CHANGELOG.md`, `VERSION` | all pre-existing tools (38 at baseline) unchanged; suite green; `0.4.0` tag |

**Progress (2026-10-19).** Rounds 1–6 are shipped and measured:

- `xtforge repos list|search|show|domains|suggest|plan|stats|export`, all
  read-only and `--json`-parity with the MCP tools
- 6 new MCP tools (`repos_search`, `repos_show`, `repos_domains`,
  `repos_suggest`, `repos_plan`, `repos_stats`) — the server now exposes 44
- parity is structural: CLI and MCP both call `xtforge.core.repos.api.run()`,
  and a test asserts byte-identical output for six verbs
- latency: in-process MCP **p50 4.9 ms / p95 39 ms** (subprocess fallback
  255 ms, which is why the fast path exists); first catalog load ~105 ms,
  cached after that
- catalog validator 10/10; 24 contract tests green
  (`python3 -m unittest discover -s tests`)
- `scripts/scaffold_tool.py` distills a candidate into a one-page spec plus an
  inert skeleton; it writes nothing without `--write` (5 candidates → 5 valid
  specs, 25 generated files compile)
- learning corpus export: `repos export --format jsonl` (template exercises,
  no repository text)

Round 4 (memory family), also shipped:

- **hybrid retrieval** — FTS5/BM25 fused with a local embedding pass via
  reciprocal-rank fusion. recall@5 **0.860 → 0.940**, MRR 0.725 → 0.780 on the
  50-query fixture (`tests/fixtures/mem_recall.json`, 45 records)
- **the lexical path is unchanged** — `--no-hybrid` / `--embed-mode off`
  reproduces the original scoring formula exactly; a test asserts it term by
  term, so old behaviour is a regression gate
- embeddings are dependency-free and deterministic (hashed stems + word shape
  + TF-IDF); `XT_EMBED_CMD` plugs in a real model and falls back gracefully
- **typed links** — closed relation vocabulary (`caused_by`, `supersedes`, …),
  validated, deduped, bidirectional reads, cascade on forget. CLI-first:
  `mem link|links|unlink`
- **live review queue** — `mem capture` stages candidates from log lines,
  `mem review --action promote|drop` decides them. A pending candidate can no
  longer overwrite promoted memory (it reports `dup_of_promoted` instead)
- 54 tests green; `scripts/bench_mem_recall.py` gates on hybrid ≥ lexical

Round 5 (route/code family), also shipped:

- **AST layer** — `xtforge code symbols|outline|refs` (`core/code/parse.py`).
  Real `ast` parsing for Python, conservative declaration heuristics for 15
  other languages, and `method: ast|regex|none` so a caller knows how much to
  trust the result. A syntax error degrades to regex with an `error` note.
- **ranked grep** — `route grep --rank` scores lines (exact term > stem >
  prefix, plus identifier splitting, declaration/assignment and error
  bonuses). Definitions rank first; stopwords match nothing.
- **query-aware context packing** — `route context --query` spends the budget
  on the lines that answer instead of dumping file heads. Same envelope,
  deterministic, and a matched failure line is trimmed to fit rather than
  dropped. `route context` without a query is byte-for-byte the old map.
- measured on 20 tasks over `tests/fixtures/mini_project`: tokens per recovered
  answer **5,440 → 979 (−82%)** at accuracy **0.15 → 0.80**; target was −30%
  at equal accuracy
- 76 tests green; `scripts/bench_context_pack.py` gates on the claim

Round 6 (safety family), also shipped:

- **`xtforge scan secrets|patterns|deps`** (`core/scan/`) — 13 secret rules
  (AWS, GitHub, Slack, Stripe, Google, JWT, PEM, bearer, URL creds, generic
  assignments), a high-entropy catch-all, 13 risky-code rules (eval, pickle,
  `shell=True`, weak hashes, TLS off, SQL interpolation) and 5 manifest rules
  (unpinned, floating ranges, plain-HTTP indexes)
- findings are **masked by default** — the scanner must not leak the key it
  just found; `--reveal` is explicit. Secrets split across adjacent string
  literals are folded and matched
- **`xtforge re info|needed|sections|symbols|strings|entropy`** — the existing
  dependency-free ELF parser is now reachable from the CLI, plus a new
  `entropy` verb (overall and per-block, with a packed/encrypted verdict)
- **guard**: system binary roots added so `re` can read `/bin`, `/usr/lib`;
  unexpanded `$VAR` roots are dropped so a missing `PREFIX` can never widen
  the allowlist; the deny list still blocks `.ssh`, `*.key`, `shadow`
- measured on `tests/fixtures/secret_hunt`: **12/12 planted secrets found,
  10/10 pattern rules fired, 5/5 manifest rules fired, 0 decoy findings,
  0 file writes**
- 103 tests green; `scripts/bench_secret_scan.py` gates on the claim

**Scope change (same day).** The working plan is now `docs/TOOL-BACKLOG.md`:
33 named tools across 6 tracks. Per that plan, Track D (taste, goal verify,
loop) is pulled ahead of round 7, and the catalog breadth follows it.

Round 8 (taste core), shipped:

- **`xtforge core/taste`** — schema, deterministic Beta learner, SQLite store,
  markdown mirror. Extraction is a pattern grammar, the decision model is
  arithmetic: no LLM anywhere in the loop
- **contradiction is visible, never overwritten** — evidence *for* raises
  `alpha`, evidence *against* raises `beta`; both arms carrying weight marks
  the learning `conflict`, and a balance flip adopts the opposing statement
  with the arms swapped
- confidence is auditable: every `absorb` returns a before/after delta, and
  `taste show` prints the evidence log behind a number
- **import never overwrites**: an imported statement that disagrees is
  recorded as contradicting evidence and shows up in `taste review`
- 6 `taste_*` MCP tools (`learn search show review export stats`) — the server
  now exposes **50**
- 141 tests green (38 new): confidence monotonic, conflict flagged,
  deterministic replay across stores, CLI/MCP parity

Round 9 (taste in OpenCode), shipped:

- **`~/.config/opencode/plugins/xt-native/`** — a local OpenCode plugin
  (TypeScript, no npm dependency) registering `/taste`, capturing prompt
  signals, and injecting enforced rules as a system block
- **verified end to end against the live request**: the `<taste>` block is
  present in the body sent to the model provider (`http.request taste=true`),
  not merely in the plugin's own bookkeeping
- `/taste show|review|stats|learn <stmt>|why <id>|forget <id>|on|off` — every
  command verified through the OpenCode API (`session/{id}/command`)
- the block is rendered by `xtforge taste inject`, so plugin and CLI cannot
  drift; `render_block` is covered by 7 tests including tag-escape and caps
- degrades to a no-op when xt-forge is missing — a taste failure never costs
  a session. Diagnostics behind `XT_NATIVE_DEBUG=1` only
- 148 tests green

Round 10 (goal verification), shipped:

- **`<goal-done>` completion protocol** (`core/goal/completion.py`) — a claim
  plus evidence items (`cmd` + `exit`, or `file` + `change`), verified by five
  independent checks: marker shape, **replayed** command exit codes, file
  existence inside the workspace, criteria-with-evidence, and an integrity
  pass (cwd switches, workspace escapes, self-serving test edits)
- **an unapproved command is never executed and is not proof** — that is the
  difference between verification and arbitrary shell access
- **5/5 fabricated claims rejected**, asserted as a single gate: no evidence,
  lying exit code, missing file, workspace escape, unapproved command. A
  genuine claim with an approved check passes
- **budget pause proven** — `BUDGET_HIT` on token budget and round cap, with
  tests driving the real engine loop
- `/goal <objective> | status | check <cmd> | done <marker> | stop` in the
  plugin, plus auto-verification: when an assistant message carries
  `<goal-done>`, the verdict is injected into the same request as
  `<goal-verification>`, so a false claim is contradicted immediately
- `goal verify` CLI + `goal_verify` MCP tool (51 tools total)
- 172 tests green

Round 11 (loop scheduler), shipped — **Track D is complete**:

- **loop grammar** (`core/loop/parse.py`) — `/loop <interval> <task>`,
  `<task> every <interval>`, self-paced `<task>`, and cadence-only forms
  defaulting to `loop.md`. Intervals snap to clean cadence steps
  (1m…30m, 1h…12h, 1d…7d), clamped to 60s–7d
- **iteration policy** — `<loop-next delay>` / `<loop-done reason>` markers;
  a missing marker gets **one** 20-minute safety check and the second omission
  stops the loop ("refusing to guess"); conflicting markers stop it; quiet
  streaks double the delay, capped at 4×
- **scheduling policy** (`core/loop/schedule.py`) — 50 tasks per conversation,
  one self-paced loop per conversation, 7-day lifetime, deterministic jitter
  (±10%, capped 15 min), and `XT_NATIVE_LOOP=0` kills everything at load
- **restart-safe** — tasks persist and re-arm on boot; a mid-iteration task
  becomes a safety check rather than a guessed restart
- `/loop`, `/loops`, `/loop-stop` in the plugin, with task text fenced as
  `<loop-task>` **data** — a scheduled task cannot widen permissions
- `xtforge loop parse|normalize|markers|next|policy` — the harness owns the
  timers, xt-forge owns the rules, so an interval or a cap is defined once
- 204 tests green (32 new)

The three mechanics from the original request — taste, `/goal`, `/loop` — are
now implemented, verified end to end, and measured.

**Breadth phase 2** (`docs/TOOL-BACKLOG.md` A1/A3/A8), shipped:

- **`xtforge codec`** — hash (8 algorithms), encode/decode (10 schemes),
  round-trip verification, entropy with per-block breakdown, and `inspect`
  which identifies and decodes JWT, PEM, UUID, semver, colours, timestamps,
  URLs, hex and base64 — including flagging credentials embedded in URLs
- **`xtforge recon`** — a scoped findings ledger: `new note finding list
  report stats`. Reports are build artifacts: the same ledger renders
  byte-identical output every time, and the target is a label that cannot
  escape `$XT_HOME/recon/`
- **`xtforge re pack`** — packing triage on top of the ELF parser: entropy,
  long-string density and per-section entropy, with a verdict. Long-string
  density is the tell (random bytes produce short printable runs by chance,
  which is what a naive entropy check gets wrong)
- 247 tests green (43 new)

Skills harvest, shipped:

- **31 skills installed** in `~/.config/opencode/skills/` originally; now **67**:
  7 xt-forge, 21 software, 8 engineering-process, 7 AI/ML, and 24 harvested
  from
  [`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
  (Apache-2.0, 818 skills) across red teaming, pentesting, malware analysis
  and forensics
- **context-budgeted**: 12 advertised, 12 load-on-demand via
  `metadata.opencode/autoinvoke: false`. All 818 would cost ~25k tokens per
  model step; the shipped set costs ~1.2k
- **licence-clean**: each skill keeps its own `LICENSE`, and every modified
  `SKILL.md` carries a `HARVEST.md` recording source, commit and the exact
  change (Apache-2.0 requires prominent notice of modification)
- the full upstream clone stays at
  `~/.local/share/opencode/skills-src/anthropic-cybersecurity` so anything can
  be pulled in later; `scripts/harvest_skills.py` is idempotent with
  `--dry-run`
- harvest record and the "why not all 818" trade-off: `docs/SKILLS.md`

Two further skill tracks, shipped later the same day:

- **engineering-process (8)** — research, spec, plan, implement, TDD,
  diagnose, review, ship. Distilled from
  [`mattpocock/skills`](https://github.com/mattpocock/skills) (MIT) and
  decoupled from that project's tooling: the methodology survives, the
  references to their issue tracker and glossary do not
- **AI/ML (7)** — training, **distillation**, datasets, eval, inference,
  systems, agent design. Written for the work this toolkit actually supports;
  `ml-distillation` covers signal ordering (preference > response > logits),
  capacity mismatch for small students, and the format-collapses-but-reasoning-
  dies failure
- **one skill per job is enforced by construction**: duplicate ids or two
  skills claiming the same job abort the build, and the check runs against
  skills already installed by a different generator. Current library:
  **67 unique jobs, 0 collisions**
- advertised budget: 55 skills ≈ 2,451 tokens per step; 12 more load on demand

`eval` recorder (B1), shipped:

- `xtforge eval record|list|show|compare|report` — bench runs are stored under
  `$XT_HOME/evals/` so a regression cannot hide in a scrollback buffer
- `compare` classifies per metric against the suite's declared direction
  (`higher` is better for recall, `lower` for token cost) and exits non-zero
  on regression, so it can gate a release
- the three `scripts/bench_*.py` re-express into runs and **agree on numbers**,
  asserted by test
- 259 tests green (24 new)

Model eval harness, shipped — the quality gate for distillation work:

- **`scripts/eval_model.py`** runs fixed cases against any model and scores
  them with **deterministic checks** — no judge model, no vibes. Backends:
  `ollama` (what this host has) and `cmd` for any stdin/stdout model
- checks: `contains`, `not_contains`, `regex`, `starts_with`, `json`,
  `max_chars`, `min_chars`, `refuses` — each case states what a pass looks
  like before the model runs
- 15 cases in `tests/fixtures/model_eval.json`, sized for 1B–2B students:
  format compliance, instruction following, refusal, honest-unknown, code
  fences, conciseness
- reports pass rate, per-check-type rate, latency (mean/p95) and output size,
  and emits straight into `xtforge eval record model-eval` so runs compare
- **per-metric direction**: pass rate is higher-is-better, latency and output
  size are lower-is-better, and `eval compare` calls them correctly
- first run already surfaced three real defects in the current student model:
  fenced JSON where bare JSON was asked for, prose before answers, and
  narrating instead of obeying a verbatim instruction
- 275 tests green (16 new)

Ecosystem survey, shipped:

- **`docs/INTEGRATIONS.md`** — MCP/plugin decisions, not a link dump
- **installed `context7`** (2 tools, remote HTTP, 63k★, MIT): live library
  docs. Highest value-per-token integration available; it removes the class
  of bug where the agent writes against an API version that no longer exists
- **blocked on this host**: no Node, no Java — which rules out playwright-mcp
  and ghidra-mcp, and most npm servers generally
- **rejected on budget**: `ghidra-mcp`'s 200 tools would cost more schema than
  every other tool combined. Its capability belongs in `re` verbs instead
  (`re graph`, `re pe` — already in the backlog)
- **absorbed as ideas**: `terse`'s lossless MCP output compression → the
  `compress` family

Native replacements, built instead of installed:

- **`xtforge docs search|resolve|show`** — Context7's live library docs as one
  verb, calling the HTTP API directly. Same capability as the 2-tool MCP
  server, none of the per-step schema cost
- **`xtforge re ioc|disasm|graph`** — the Ghidra alternative, built on the
  binutils already present (objdump, nm, strings):
  - `ioc` — IPs, domains, URLs, emails, hashes, CVEs, file paths, registry
    keys, with **credentials masked** (`admin:***@host`) and the
    password-as-email artefact suppressed
  - `disasm` — parsed instructions with mnemonic histogram, by symbol or
    section
  - `graph` — imports, exports, call sites with resolved symbols, hot targets
  - on `/bin/ls`: 112 imports, 15 exports, 200 call sites
- decompilation remains the one Ghidra capability not replicated — named as a
  gap rather than pretended away

Round 7 (compress/eval squeezers) and phase 3 (memory consolidation, graph
queries, symbol-aware packing) stay queued. Still open: permission/tool-retry
taste signals and the taste A/B measurement.

### Why this order

- The catalog is already built, so rounds 1–3 deliver visible value first.
- Memory/navigation/safety come before autonomy; an autonomous loop is only
  safe when retrieval and guards are solid.
- Taste lands before goal/loop because both benefit from preference context.
- Every round leaves the repo shippable; no round depends on a future one.

---

## 8. Acceptance criteria (9)

1. **Catalog reproducible** — 65 queries, ≥1,888 unique repos, deterministic
   order, validator 10/10.
2. **Offline `repos`** — 6 MCP tools, no network, p95 <100 ms, read-only.
3. **Surface parity** — every MCP-promoted capability has a CLI `--json` verb
   with the same arguments and result shape; CLI-only tools list `mcp: false`.
4. **Guard coverage** — every write path goes through `route.guard`; every
   destructive action needs a confirm token.
5. **No dependency drift** — stdlib-only by default; optional dependencies
   are pinned, probed, and degrade gracefully.
6. **Taste correctness** — confidence rises with support, falls with
   contradiction, conflicts are never silently overwritten; A/B shows ≥15%
   fewer corrections with no test-pass regression.
7. **Goal honesty** — a goal is `achieved` only after an independent check;
   5/5 fabricated completion claims are rejected.
8. **Loop safety** — fixed and self-paced modes, 7-day cap, 50-task cap,
   restart-safe, cancellable, prompt-injection fenced.
9. **No regressions** — all pre-existing tests and 38 MCP tools keep working;
   docs, changelog and version updated.

---

## 9. Metrics

| metric | baseline | target |
|---|---|---|
| `repos` search p95 | 255 ms (subprocess) | <100 ms (in-process: 39 ms measured) |
| memory recall@5 (50-query fixture) | 0.860 lexical (round 4) | +20% relative → **actual +9.3% (0.940)** |
| context tokens for 20 tasks | 5,440 tok/hit (map packing, round 5) | −30% → **actual −82% (979 tok/hit)**; accuracy 0.15 → 0.80 |
| secret-scan false negatives | 12 planted + 10 decoy lines (round 6) | 0 → **met: 12/12 found, 0 decoy hits, 0 writes** |
| taste correction rate | record at round 9 | −15% |
| goal false-completion rate | 5/5 rejected | 5/5 |
| MCP tool count | 38 | ≤56 in `0.4.0` (6 repos + 6 taste + 6 goal); ≤64 in `0.5.0` |
| test suite | green | green |

**Recall target: missed, on purpose.** Hybrid retrieval improved recall@5 from
0.860 to 0.940 (+8.0 points, +9.3% relative), short of the +20% relative
target. The closing gap is synonym-level meaning ("allocation failure" ≈
"OOM"), which a deterministic hashed-embedding cannot encode: it handles stems
and word shape, not semantics. Two honest options, both deferred: plug a real
embedding model behind `XT_EMBED_CMD` (already wired, capability-probed), or
grow the fixture with a second annotator and re-measure. Raising the number by
re-weighting against our own fixture would be overfitting, so the gap stays
visible.

The MCP cap is deliberate: context is scarce, and every tool competes with the
task. New capability must justify its schema tokens.

---

## 10. Risks

| risk | impact | mitigation |
|---|---|---|
| Scope explosion (1,888 repos) | never ships | capability families + one-caller rule + 12 rounds |
| License contamination | legal | adopt/borrow/study tiers; AGPL study-only; no vendoring |
| Tool/context bloat | worse agent performance | hard MCP cap; consolidate verbs; measure tokens |
| Prompt injection via repo descriptions or loop tasks | unsafe actions | data fencing, no permission widening, allowlists |
| Dependency creep | fragile install | stdlib default, pinned optional extras, capability probes |
| Autonomous loops burn budget | cost | turn/token/time caps, pause semantics, stuck detector |
| Taste overfits noise | bad defaults | explicit-only new keys, ≥3 evidence, conflict review |
| OpenCode plugin API churn | breakage | thin adapter, version pin, contract tests |
| Verifier runs harmful commands | security | one-time approval, allowlist, timeout, cwd pin |

---

## 11. Approval questions

1. **Scope** — approve the twelve capability families, or narrow the first
   release to the six P0 families only? Recommended: six P0 first, P1/P2 after
   `0.4.0`.
2. **MCP budget** — approve growing 38 → 56 tools (6 repos + 6 taste + 6 goal),
   with a hard cap and no per-repo tools? Alternative: keep `repos` CLI-only
   and add MCP later.
3. **Dependency policy** — keep stdlib-only as the default, allowing optional
   extras only for embeddings/OCR/inference behind capability probes?
   Alternative: permit pinned crates/pip packages for P0 families.

Taste privacy, verifier approvals and autonomy defaults are the three
questions in `docs/OPENCODE-NATIVE-TASTE-LOOP.md` §8.

---

## 12. What happens after approval

1. I create a branch, implement rounds 1–3, and show the catalog + `repos`
   surface working before touching memory or autonomy.
2. I pause after round 3 for a scope check; then rounds 4–8 (capabilities),
   9–11 (taste/goal/loop), 12 (release).
3. Each round reports evidence: commands run, tests, measurements, diffs.
4. Nothing ships on intent; a round that misses its acceptance criterion is
   revised, not declared done.
