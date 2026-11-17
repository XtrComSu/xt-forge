# Tool backlog: what gets built next

Status: **scope proposal** · supersedes the 12-round family list in
`plan-top-repos-learning.md` as the working plan
Source: `catalog/top-repos/tool-candidates.json` (4,810 repos, 250 ranked)

The earlier plan grouped work into 12 capability families and shipped six
rounds of foundation. This document is the concrete answer to "what other
features": **33 named tools across 6 tracks**, each with the repos it learns
from and the check that decides whether it is done.

Delivery order follows the instruction: **taste/goal/loop first**, catalog
breadth immediately after.

---

## Track D — Autonomy (first, because it was asked for first)

These are the three mechanics adapted from Command Code's public behaviour,
clean-room: xt-forge already owns `goal` (predates this work), so D3–D4 extend
it rather than replace it.

| # | tool | verbs | learn from | done when |
|---|---|---|---|---|
| D1 ✅ | **taste core** | `ingest search show review learn forget export stats` | Command Code taste docs | done — confidence is monotonic, contradictions are flagged not overwritten, deterministic replay |
| D2 ✅ | **taste in OpenCode** | `/taste`, `<taste>` injection | Command Code taste | done 2026-10-20 — plugin is source in `plugins/xt-native/`, shipped by `xtforge plugin install`; **10 scripted sessions → 6 expected learnings, 0 invented keys, 1 enforced rule injected** |
| D3 | **goal verifier** | `verify` + completion marker | Command Code `/goal` | 5/5 fabricated completion claims rejected |
| D4 | **goal budgets** | turn/token/time caps, stuck detection | SWE-agent (20k), OpenHands | budget pause works; restored goal is idle, never auto-running |
| D5 | **loop scheduler** | `/loop`, `/loops`, `/loop-stop` | healthchecks (10k), Temporal | fixed + self-paced, restart-safe, cancel leaves no timer |
| D6 | **loop safety** | `loop.md`, kill switch, fencing | Command Code `/loop` | 7-day cap, 50-task cap, task text cannot widen permissions |

---

## Track A — Security & red team

| # | tool | verbs | learn from | done when |
|---|---|---|---|---|
| A1 ✅ | **codec** | `hash encode decode roundtrip entropy inspect` | gchq/CyberChef (36k), hashcat | done — 20 fixtures round-trip, entropy within 0.01, `inspect` decodes JWT/PEM/UUID/semver/timestamps and flags credentials in URLs |
| A2 | **net** | `dns http tls whois` | mitmproxy (45k), projectdiscovery/httpx, subfinder | zero requests outside the allowlist; rate limit enforced |
| A3 ✅ | **recon** | `new note finding list report stats` | h4cker (29k), pwndbg (11k) | done — report regenerates byte-identical from the ledger; target is a label, never a path |
| A4 | **scan rules** | `rules list test` | projectdiscovery/nuclei (32k) | a rule pack loads and catches its seeded fixture |
| A5 | **scan advisories** | `advisories match` | aquasecurity/trivy, anchore/grype | offline DB version reported; no network call |
| A6 | **re pe** | `pe info sections imports` | lief-project/lief (8k) | sections + imports parsed on a fixture PE |
| A7 | **re macho** | `macho info` | lief | header fields correct on a fixture |
| A8 ✅ | **re pack** | `re pack` (entropy + string density + section entropy) | orhun/binsider (4k) | done — flags a packed fixture, passes a plain one; long-string density is the tell, not raw entropy |
| A9 | **re graph** | `graph imports` | JonathanSalwan/Triton (4k), BAP (2k) | import graph matches `nm -D` on N binaries |
| A10 | **fuzz** | `run corpus` | google/oss-fuzz (12k), honggfuzz (3k) | finds a seeded crash in a fixture parser, bounded runtime |

## Track B — Agent workflow

| # | tool | verbs | learn from | done when |
|---|---|---|---|---|
| B1 ✅ | **eval** | `record list show compare report` | promptfoo (26k), trycua/cua (30k) | done — the 3 bench scripts re-express into runs and agree on numbers; `compare` calls regressions by suite direction and exits non-zero |
| B2 | **git tools** | `diff preview apply worktree` | dandavison/delta (32k), lazygit (83k) | nothing touches the index without a confirm token |
| B3 | **docs** | `drift check render` | mkdocs-material, facebook/docusaurus | catches a seeded CLI/doc mismatch |
| B4 | **build** (growth) | `gates checkpoint resume` | conductor (32k), dapr (26k), Temporal | a stalled phase resumes from its checkpoint |
| B5 | **dataset** | `manifest dedupe provenance` | treeverse/dvc (8k) | manifest round-trips through export/import |
| B6 | **prompt** | `list lint render` | code2prompt (7k) | lint catches a missing template variable |
| B7 | **archive** | `pack unpack index` | yamadashy/repomix | packs a workspace to a token budget |
| B8 | **doctor** (growth) | `check explain fix` | textualize/rich (24k) | every failed check carries an actionable hint |

## Track C — Memory & context

| # | tool | verbs | learn from | done when |
|---|---|---|---|---|
| C1 | **mem consolidate** | `dedupe merge supersede` | mem0 (67k), cognee (32k) | N near-dupes collapse to 1 with provenance kept |
| C2 | **mem lifecycle** | `ttl purge review --auto` | EverMind-AI/EverOS (13k) | expired records purge during calibrate |
| C3 | **mem graph** | `links --depth path` | Understand-Anything (87k), codegraph (74k) | 2-hop path query returns a stable edge list |
| C4 | **mem embed** (growth) | `embed probe backend` | faiss (41k), qdrant (35k) | a local model behind `XT_EMBED_CMD` lifts recall over hashing |
| C5 | **context symbols** | `route context --symbols` | ast-grep (16k), graphify (129k) | beats query-only packing on the 20-task fixture |
| C6 | **mem capture** (growth) | `capture --session` | (xt-forge own) | session logs stage candidates without duplicates |

## Track E — Device & edge

| # | tool | verbs | learn from | done when |
|---|---|---|---|---|
| E1 | **phone** (growth) | `battery thermal network` | termux/termux-app | probes degrade to hints on non-Termux hosts |
| E2 | **model** | `list probe quant` | ggml-org/llama.cpp | reports installed artifacts; never downloads |
| E3 | **disk guard** | `check require` | preflight disk check | refuses snapshotting under the free-space threshold |

---

## How a tool ships

Unchanged from the plan, and non-negotiable:

1. one page spec first (`xtforge repos plan`) — mechanic, caller, guard, tests
2. CLI `--json` before MCP; MCP promotion requires retiring or merging another
   tool (cap: 56 in `0.4.0`)
3. stdlib-only unless a dependency is approved and capability-probed
4. a benchmark that exits non-zero on regression, and a number in the changelog
5. read-only unless a write path goes through `route.guard` with a confirm token

## Suggested sequence

| phase | tools | why this order |
|---|---|---|
| 1 | D1–D6 | the request; also unblocks better tool use in every later round |
| 2 | A1, A3, A8, B1 | highest daily value for security work: codec, recon ledger, packing triage, one eval recorder |
| 3 | C1, C3, C5 | memory is the force multiplier for everything else |
| 4 | A2, A4, A5, A6, A10 | offensive breadth |
| 5 | B2, B3, B4, B6, B7, B8 | workflow polish |
| 6 | E1–E3, C4, A7, A9, B5 | edge cases and growth |

Track D first is the instruction. Phase 2 immediately after is the fastest way
to turn the catalog into capability you can feel.
