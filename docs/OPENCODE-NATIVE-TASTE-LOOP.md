# Native OpenCode design: taste, goal, loop

Status: **shipped** · target: OpenCode V2 (`v2.0.32` here) ·
companion to `docs/plan-top-repos-learning.md`

This document designs three mechanics that Command Code popularised —
**taste learning**, **`/goal`**, and **`/loop`** — as native OpenCode
features backed by xt-forge state. The design was agreed before the code
was written; this file records what shipped and where it lives.

| Surface | Where it lives |
|---|---|
| taste core (schema, learner, store, markdown) | `xtforge/core/taste/` |
| goal machine + verifier | `xtforge/core/goal/` |
| loop grammar + policy | `xtforge/core/loop/` |
| OpenCode plugin (`/taste`, `/goal`, `/loop`, injection) | `plugins/xt-native/` |
| install / drift check | `xtforge plugin install\|status` (also `xtforge sync`) |
| design record | this file |

---

## 0. What we borrow, and what we do not

Command Code's public docs describe:

- **Taste** as a four-stage loop: an LLM turns interactions into structured
  signals, a non-LLM decision model (`taste-1`) classifies each signal into a
  fixed category with calibrated confidence, an LLM writes markdown, and the
  CLI stores `taste.md` per project/global package.
- **`/goal`** as a standing objective with a turn budget (default 100, max
  1000), a completion marker, and an **independent verification check** that
  can reject a false completion claim.
- **`/loop`** as a scheduler: fixed cadence (`5m`, `2h`, `every 2 hours`,
  cron-normalised) or self-paced (the agent picks the next delay between one
  minute and one hour), with quiet-streak backoff, a seven-day lifetime,
  prompt-injection fencing, and `loop.md` for the default task.

We adopt the **mechanics and safety properties**. We cannot adopt `taste-1`
(proprietary, hosted, no local weights), so the decision layer below is a
deterministic symbolic learner built from the same primitives: fixed
categories, explicit polarity, confidence that moves with evidence, and
contradiction detection instead of silent overwrite. Optional LLM extraction
is allowed only at the edges; the decision itself is never sampled.

---

## 1. Where the code lives

```
~/.config/opencode/
├── opencode.json                  # plugins: ["./plugins/xt-native"]
└── plugins/xt-native/
    ├── package.json
    ├── src/
    │   ├── index.ts               # Plugin.define + registrations
    │   ├── commands/
    │   │   ├── taste.ts
    │   │   ├── goal.ts
    │   │   └── loop.ts
    │   ├── taste/
    │   │   ├── schema.ts          # categories, learning record, signal record
    │   │   ├── extract.ts         # explicit-preference + diff signals
    │   │   ├── learn.ts           # deterministic Beta-confidence learner
    │   │   ├── store.ts           # ctx.storage cache + xt-forge bridge
    │   │   └── inject.ts          # <taste> system block
    │   ├── goal/
    │   │   ├── machine.ts         # idle/active/verifying/achieved/paused
    │   │   ├── verify.ts          # independent checks + command runner
    │   │   └── continue.ts        # continuation packet + digest
    │   ├── loop/
    │   │   ├── parse.ts           # interval + task grammar
    │   │   ├── schedule.ts        # fixed/self-paced scheduler
    │   │   └── markers.ts         # <loop-next>, <loop-done>
    │   └── bridge/
    │       └── xtforge.ts         # batched CLI calls, JSON only
    └── test/
        ├── taste.learner.test.ts
        ├── goal.machine.test.ts
        └── loop.parse.test.ts
```

A project can override any file by placing the plugin under
`.opencode/plugins/xt-native/`; the nearest registration wins. The plugin is
TypeScript, loaded by OpenCode's plugin runtime, and uses only documented V2
context APIs:

| Need | API |
|---|---|
| register `/taste`, `/goal`, `/loop` | `ctx.command.transform(editor => editor.add(...))` |
| inject taste into every model call | `ctx.session.hook("context", ...)` |
| observe prompts and explicit preferences | `ctx.session.hook("prompt", ...)` |
| observe edits/shell/read calls | `ctx.tool.hook("execute.before"/"execute.after", ...)` |
| observe permission accept/reject | `ctx.permission.hook("evaluate", ...)` |
| watch session lifecycle | `ctx.event.subscribe({ signal })` |
| durable local cache | `ctx.storage.get/set/scan` |
| continue a goal | `ctx.session.prompt` / `ctx.session.synthetic` |
| verify a claim | `child_process.spawn` with timeout and output caps |
| optional LLM extraction | `ctx.generate.text` |

> Design rule: the plugin never becomes the source of truth for durable
> knowledge. Cache in `ctx.storage`; flush learnings/goals to xt-forge so the
> same state is visible to the CLI and MCP server.

---

## 2. Taste

### 2.1 What a taste learning is

A learning is one **typed, falsifiable preference**, not free-form prose:

```ts
type Category =
  | "cli" | "python" | "typescript" | "rust" | "architecture"
  | "testing" | "docs" | "security" | "performance" | "naming"
  | "errors" | "dependencies" | "git" | "ui"

interface Learning {
  id: string                  // sha256(category + key + polarity)
  category: Category
  key: string                 // normalised, e.g. "semicolons"
  statement: string           // "Omit semicolons in TypeScript."
  polarity: 1 | -1            // prefer / avoid
  alpha: number               // evidence for
  beta: number                // evidence against
  confidence: number          // alpha / (alpha + beta)
  status: "hint" | "enforced" | "conflict" | "retired"
  evidence: SignalRef[]       // capped at 20, newest first
  firstSeen: number
  lastSeen: number
  scope: "project" | "global"
}
```

`confidence` is **computed**, never written by a model:

```
confidence = alpha / (alpha + beta)
```

New evidence adds weight to `alpha` (supports) or `beta` (contradicts).
A learning is:

- `enforced` when `confidence >= 0.85` and `evidence.length >= 3`
- `hint` when `0.60 <= confidence < 0.85`
- `conflict` when both `alpha > 1.5` and `beta > 1.5`
- `retired` after 90 days with no evidence, or explicit `/taste forget`

This gives the two properties that matter: **repetition raises confidence**
and **contradiction is visible instead of overwriting**. It is deterministic:
the same ordered signals produce the same state.

One qualification, and it is the whole point of the `evidence` count: a
piece of evidence is one *observation*. The plugin is loaded once per
location, so its prompt hook fires more than once for the same prompt, and
each copy would otherwise count as another observation — a rule the user
stated *once* would reach `enforced` and be injected into every session.
The prompt carries an id that is unique per admitted prompt, so that id is
the deduplication key: one prompt, one signal. A user who states the same
thing again later is a second observation and is kept.

### 2.2 Signal sources

| Signal | Source | Weight | Notes |
|---|---|---|---|
| Explicit preference | prompt hook: "always/never/prefer/use X not Y" | 1.0 | highest quality; parsed by regex + constrained LLM fallback |
| Correction diff | compare agent-written file hashes with working tree at idle | 0.7 | only when the user changed an agent edit; category from path/language |
| Permission rejection | `permission.hook("evaluate")` returning deny/ask feedback | 0.6 | reason text becomes the statement |
| Tool failure/retry | `tool.hook("execute.after")` status=error, then a different tool succeeds | 0.4 | avoids "always use tool X" overfitting |
| Test result | shell hook on test commands: pass after a change | 0.5 | supports the approach, not the exact code |
| Manual `/taste learn` | command | 1.0 | user-authored, immediately enforced |

Only explicit preferences and manual learnings can create a **new** key.
Corrections and failures can only reinforce or contradict an existing key.
This prevents the profile from filling with invented rules — the failure mode
Command Code calls out in LLM-written taste.

### 2.3 Extraction is constrained

For explicit preferences we first try a deterministic pattern grammar:

```
(always|never|prefer|avoid|use|don't use|stop using) <object>
<object> (over|instead of) <object>
```

If that fails and `taste.llmExtract` is enabled, `ctx.generate.text` is called
with a JSON schema whose `category` is an enum and whose `statement` must be a
substring-backed claim. Invalid JSON, unknown categories, or statements with no
supporting quote are discarded. The LLM never sets confidence.

Default: **LLM extraction off**. Taste works with zero model calls.

### 2.4 Injection

On every `context` hook, the plugin builds a bounded block from `enforced`
learnings relevant to the session:

```xml
<taste scope="project" confidence="enforced">
  <rule category="typescript">Omit semicolons in TypeScript.</rule>
  <rule category="cli">Every command must support --json.</rule>
</taste>
```

Rules:

- only `enforced` entries, never `hint` or `conflict`
- max 600 tokens, ranked by `confidence × recency`
- project rules before global rules
- no secrets, paths or code snippets in the statement
- the block is injected as a system message, never as user text
- `/taste off` disables injection for the session; `/taste pause` for 1 hour
- **the polarity travels with the statement.** A learning's statement is
  the *subject* of the preference ("fabricate output") and its polarity
  says which way it points. Rendering the statement alone turns "Never
  fabricate output" into "fabricate output" — an instruction to do the
  thing the user forbade. A negative learning is rendered as a prohibition;
  a statement that is already one is not prefixed twice

### 2.5 Storage and commands

Durable state lives in xt-forge (`~/.xt-forge/taste.db`, SQLite) and is
mirrored to human-editable markdown:

```
~/.xt-forge/taste/global/<category>/taste.md
<project>/.xt-forge/taste/<category>/taste.md
```

Markdown format (lintable, diffable):

```markdown
---
category: typescript
confidence: 0.91
status: enforced
evidence: 7
updated: 2026-10-19T18:40:00Z
---
# TypeScript

- Omit semicolons in TypeScript. <!-- id: 9f2c… -->
```

Commands:

| Command | Behaviour |
|---|---|
| `/taste` | show enforced + hints for this project |
| `/taste review` | list conflicts and low-confidence hints with evidence |
| `/taste learn <statement>` | add a manual learning (weight 1.0) |
| `/taste forget <id>` | retire a learning |
| `/taste export [path]` | write markdown package |
| `/taste import <path>` | merge a package (conflicts flagged, never overwritten) |
| `/taste off` / `on` | toggle injection |
| `/taste why <id>` | show the signals behind a learning |

The same surface is exposed by xt-forge as `xtforge taste …` and six MCP
tools: `taste_learn`, `taste_search`, `taste_show`, `taste_review`,
`taste_export`, `taste_stats`.

### 2.6 Evaluation

Taste is only useful if it changes output without hurting correctness:

- 20 paired tasks, same model/prompt, taste on vs off.
- Measure: user correction rate, diff size, test pass rate, tokens.
- Ship only if correction rate drops ≥15% and test pass rate does not drop.
- A false-positive audit: every `enforced` rule must cite ≥3 signals.

---

## 3. Goal

### 3.1 State machine

```
idle ──/goal <objective>──▶ active
active ──completion marker──▶ verifying
verifying ──pass──▶ achieved
verifying ──fail──▶ active (gap appended)
active ──budget/stuck/denied──▶ paused
active ──/goal stop──▶ cleared
```

`paused` keeps the record; `/goal resume` re-enters `active` without resetting
the turn count. `/goal clear` deletes it.

### 3.2 Record

```ts
interface Goal {
  id: string
  sessionID: string
  objective: string
  state: "idle" | "active" | "verifying" | "achieved" | "paused"
  turn: number
  maxTurns: number            // default 100, clamp 1000
  tokenBudget?: number
  startedAt: number
  updatedAt: number
  criteria: string[]          // user-supplied, semicolon separated
  verifyCmd?: string          // optional, must be approved once
  digest: string              // compact state summary for fresh context
  evidence: Evidence[]
  failures: { gap: string; at: number }[]
  history: { turn: number; action: string; verdict?: string }[]
}
```

### 3.3 Completion protocol

The agent may only declare completion with a fenced marker:

```xml
<goal-done>
  <claim>All 42 tests pass and the migration is complete.</claim>
  <evidence>
    <item cmd="pytest -q" exit="0">42 passed</item>
    <item file="src/api.py" change="migrated 12 call sites"/>
  </evidence>
</goal-done>
```

The plugin then runs **independent checks** in order:

1. **Marker well-formed?** Missing evidence → reject with a specific gap.
2. **Evidence replay.** Re-run each `cmd` with a 120 s timeout, output capped
   at 8 KB, cwd fixed to the project. Exit code must match the claim.
   Commands run only if the user approved `verifyCmd` or the exact command
   appears in the goal's approved list.
3. **File checks.** Claimed files exist, are inside the workspace, and the
   recorded diff is non-empty where a change is claimed.
4. **Criteria.** Each user criterion gets a pass/fail note. A single fail
   rejects.
5. **Hack check.** Reject if evidence references paths outside the workspace,
   if tests were edited to pass, or if the same command was run against a
   different cwd.

On rejection the plugin appends the gap to `failures` and sends a
continuation packet. Three consecutive rejections with the same gap →
`paused · could not verify completion`.

### 3.4 Continuation packet

At session idle, if the goal is `active`:

```xml
<goal-control id="g-…" turn="7/100">
  <objective>…</objective>
  <done>…</done>
  <remaining>…</remaining>
  <last-verdict>…</last-verdict>
  <next>Continue from the filesystem and command output. Do not restate the plan.</next>
</goal-control>
```

The packet is **synthetic control data**, not a user request. It may not widen
permissions or override project instructions. If the agent is busy, the tick
waits; missed ticks do not pile up.

### 3.5 Budgets and stop conditions

| Condition | Behaviour |
|---|---|
| turn budget exhausted | `paused · out of turns` |
| token budget exceeded | `paused · token budget` |
| wall clock > 6 h | `paused · time budget` |
| same digest twice | inject a "change approach" note; third time pause |
| permission denied on a required action | pause and report |
| user `/goal stop` or `Esc` interrupt | cleared/finishing current step |
| verifier command rejected by policy | pause, ask for approval once |

Resume semantics follow Command Code: a restored goal is **idle**, never
auto-running. The user restarts it explicitly.

---

## 4. Loop

### 4.1 Grammar

```
/loop <interval> <task>
/loop <task> every <interval>
/loop <task>                # self-paced
/loop <interval>            # default loop.md task
/loop                       # default task, self-paced
/loops                      # list scheduled tasks
/loop-stop [id]             # cancel one or all
```

Intervals accept `s`, `m`, `h`, `d` and spelled-out units. Fixed intervals are
normalised to clean steps (1,2,3,4,5,6,10,12,15,20,30 minutes; 1,2,3,4,6,8,12
hours; daily; N days), matching the cron behaviour users expect, and the
confirmation states the normalised value.

### 4.2 Two modes

**Fixed** — a recurring timer per conversation. Deterministic jitter of up to
10% (capped 15 min) derived from the task id so many sessions do not fire
together. Seven-day lifetime.

**Self-paced** — one pending wakeup. Each iteration ends with exactly one of:

```xml
<loop-next delay="300" reason="CI still running"/>
<loop-done reason="deploy is green and smoke test passed"/>
```

Delay is clamped to 60–3600 s. A quiet iteration (no state change) increments
`quietStreak`; the next packet reports it and the prompt instructs the agent to
back off. A missing marker schedules one 20-minute safety check; a second
missing marker stops the loop.

### 4.3 Safety properties

- task text is fenced as `<loop-task>` **data**; it cannot override system or
  project instructions
- permissions are unchanged; each iteration goes through normal checks
- no self-paced loops from subagents or headless runs
- one self-paced loop per conversation; starting another replaces it
- max 50 scheduled tasks per conversation; 7-day lifetime for fixed loops
- cancellation is explicit (`/loop-stop`, `Esc`, session end) and queued
  iterations are re-checked before running
- a kill switch (`XT_NATIVE_LOOP=0`) disables all scheduling at launch

### 4.4 Default task

A bare `/loop` reads `<project>/.xt-forge/loop.md`, then
`~/.xt-forge/loop.md`, capped at 25 KB. Default content:

```markdown
Continue unfinished work from this conversation.
Check the current branch for review comments, failing checks and conflicts.
Fix only what is clearly in scope.
If nothing is pending, make one bounded quality pass on files already touched.
Do not start unrelated work or widen permissions.
```

The file is re-read each iteration, so edits apply without restarting.

### 4.5 Persistence and execution

- schedules are stored in `ctx.storage` under `loop/<sessionID>/<id>`
- a single `setTimeout` per task; no interval drift accumulation
- on server restart, tasks inside their lifetime are restored; a task that was
  mid-iteration becomes a 20-minute safety check
- the scheduler only fires between turns; a due event while busy waits once
- each iteration is a synthetic prompt, so it does not masquerade as user input

---

## 5. xt-forge bridge

The plugin remains thin; xt-forge owns durable state and cross-harness parity.

| Concern | Owner |
|---|---|
| schema, confidence math, markdown export | xt-forge `taste` core |
| goal state machine + verifier + budgets | xt-forge `goal` core |
| catalog + tool registry | xt-forge `repos` core |
| OpenCode hooks, commands, scheduling | plugin |
| CLI/MCP parity | xt-forge CLI + `adapters/mcp/server.py` |

Bridge rules:

1. Writes are **batched**: signals accumulate in `ctx.storage`, flushed on idle
   or every 20 signals, one `xtforge taste ingest --json` call.
2. Reads are cached for 60 s; `/taste` commands force a refresh.
3. The bridge prefers the native binary, falls back to
   `python3 -m xtforge.cli`, and never blocks a model call for more than 500 ms.
4. If xt-forge is unavailable, the plugin keeps working from its local cache
   and marks the profile `degraded` in `/taste` output.

New xt-forge surfaces required:

```
xtforge taste ingest|search|show|review|export|import|forget|stats|prune|repair
xtforge goal start|status|tick|verify|pause|resume|stop|log
xtforge loop parse|schedule|list|cancel      # pure helpers; scheduling stays in the harness
```

MCP additions: six `taste_*` tools, six `goal_*` tools (`goal_tick` and
`goal_verify` included), and read-only loop helpers.

---

## 6. Delivery plan

| Phase | Deliverable | Acceptance |
|---|---|---|
| T0 ✅ | xt-forge `taste` core (schema, learner, SQLite, markdown) | done 2026-10-19 — 38 tests: confidence monotonic, contradiction flagged, deterministic replay |
| T1 ✅ | `xtforge taste` CLI + 6 MCP tools | done — JSON parity between CLI and MCP; zero model calls |
| T2 ✅ | OpenCode plugin skeleton + `/taste` | done 2026-10-20 — plugin loads, `taste` registered, `/taste stats` reads the live store |
| T3 ✅ | signal capture (prompt, edits, permissions, tests) | prompt hook ingests explicit preferences; permission + tool-retry signals still pending |
| T4 ✅ | injection + A/B evaluation | injection **proven on the wire**: the block appears in the outgoing provider request. A/B measurement still pending |
| T5 ✅ | the plugin **ships** | done 2026-10-20 — source in `plugins/xt-native/`, `xtforge plugin install|status|uninstall` puts it on a machine, `xtforge sync` installs it too, the doctor reports drift. Acceptance: **10 scripted sessions → 6 expected learnings, 0 invented keys, 1 enforced rule injected**; the installed copy is byte-identical to the source |
| G0 ✅ | xt-forge `goal` machine + verifier | done 2026-10-20 — `<goal-done>` protocol with 5 checks; **5/5 fabricated claims rejected** (no evidence, lying exit code, missing file, workspace escape, unapproved command) |
| G1 ✅ | `/goal` command + continuation + budgets | done 2026-10-20 — `record / check / done / status / stop`; budget pause proven (`BUDGET_HIT` on tokens and rounds); auto-verification injects a verdict when an assistant claims done |
| L0 ✅ | loop parser + fixed scheduler | done 2026-10-20 — interval normalisation table (13 cases) passes; `/loop-stop` clears the timer |
| L1 ✅ | self-paced loop + quiet backoff | done — first omission gives one 20-minute safety check, the second stops ("refusing to guess"); quiet streak doubles the delay, capped at 4× |
| L2 ✅ | `loop.md`, persistence, kill switch | done — tasks survive a server boot and re-arm (mid-iteration becomes a safety check); `XT_NATIVE_LOOP=0` disables everything; 50-task and 7-day caps enforced |
| H0 ✅ | hardening | done 2026-10-20 — suite green; the MCP tool surface is now **pinned by name** in `tests/test_mcp_surface.py`, so no tool can be dropped or renamed without the change showing up in the same commit, and the 56-tool cap holds (51 today) |
| P0 ✅ | plugin shipped from the repo | 2026-10-20 — `plugins/xt-native/` is the canon; `xtforge plugin install` installs and registers it, `xtforge plugin status` reports drift, and the installed copy is stamped with the paths it needs instead of one hard-coded home |
| P1 ✅ | extraction precision | 2026-10-20 — a key needs a preference word ("always", "never", "prefer", "avoid", "please use", "use X not Y"). 19 of 23 live learnings were invented by the old rules; `taste prune` retires what the current rules would not invent |
| P2 ✅ | concurrent writes lose nothing | 2026-10-20 — absorbing a signal is a read-modify-write, and SQLite's deferred transaction did the read *outside* the write lock: two processes learning the same key both read the same row and both wrote it back, so a piece of evidence was lost. Four concurrent writers recorded **1** piece of evidence instead of 4, the rule never reached `enforced`, and it was never injected. The store now takes the write lock before the read (`BEGIN IMMEDIATE`) |
| P3 ✅ | the profile says what the user said | 2026-10-21 — three defects found by auditing a live profile, all of which made the profile lie. (1) A rule the user *avoided* was injected as an instruction to do it: the statement is the subject of the preference ("fabricate output") and the polarity says which way it points, but the block rendered the statement alone, so "Never fabricate output" reached the model as "fabricate output". The block now renders a negative learning as a prohibition. (2) One prompt was ingested once per location — the plugin is loaded per location, so the prompt hook fired two or three times and each copy counted as another piece of evidence, letting a rule stated *once* reach `enforced`. The prompt's id is now the deduplication key: one prompt, one signal. (3) `xtforge taste repair` collapses evidence the plugin recorded twice and recomputes the counters it inflated; a deliberate `manual` learning and a repetition in a later second are both kept |

---

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Taste encodes noise as preference | new keys only from explicit/manual signals; ≥3 evidence; contradiction visible |
| Taste drifts with the model | deterministic learner + evidence audit; no LLM confidence |
| Prompt injection through repo text or loop tasks | fence as data; never widen permissions; allowlists |
| Autonomous goal burns budget | hard turn/token/time caps; pause, never silently continue |
| Verifier runs unsafe commands | one-time approval, allowlist, timeout, cwd pin, output cap |
| Plugin API churn | pin OpenCode version, keep a thin adapter layer, test on upgrade |
| Scheduler survives incorrectly | persist with session id + lifetime; re-check before firing |
| Context bloat from tools/taste | budgets: 600 taste tokens, 6 new MCP tools per surface, rank before inject |

---

## 8. Approval questions

1. **Taste privacy** — may the plugin read session diffs and permission
   decisions locally to infer preferences? Default: yes, local-only, no LLM
   extraction. Alternative: explicit `/taste learn` only.
2. **Verifier commands** — should `/goal` be allowed to re-run test/lint
   commands automatically after a one-time approval, or require approval for
   every verification?
3. **Autonomy defaults** — accept 100 turns per goal, 7-day loops, 50 tasks per
   conversation, and a 6-hour wall clock? These are the proposed defaults.

---

## 9. Sources

- Command Code taste: <https://commandcode.ai/docs/taste>
- Command Code `/goal`: <https://commandcode.ai/docs/goal>
- Command Code `/loop`: <https://commandcode.ai/docs/loop>
- OpenCode V2 plugins: <https://opencode.ai/v2/docs/build/plugins>
- OpenCode V2 MCP servers: <https://opencode.ai/v2/docs/mcp-servers>
