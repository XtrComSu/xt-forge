# Skills harvest

Status: **shipped 2026-10-20** · library lives in `~/.config/opencode/skills/`

OpenCode advertises every skill with a `description` on **every model step**,
so a skill library is a context-budget decision as much as a capability one.
This harvest is curated for that reason: 818 upstream skills would cost ~25k
tokens per step before the agent reads a single line of work.

## What is in the library

| group | count | advertised | source |
|---|---:|---:|---|
| **xt-forge skills** | 7 | 7 | original, written for this toolkit |
| **software skills** | 21 | 21 | original, one per job |
| **process skills** | 8 | 8 | original, distilled from mattpocock/skills (MIT) |
| **AI/ML skills** | 7 | 7 | original, written for distillation work |
| **security skills** | 24 | 12 | mukul975/Anthropic-Cybersecurity-Skills (Apache-2.0) |
| total | **67** | **55** | |

## The rule: one skill per job

Five skills for one job is worse than none — the model spends the turn
choosing instead of working. So the library is a list of **jobs**, and each
job has exactly one skill. The generators enforce it, including against
skills already installed by a different generator:

```sh
python3 scripts/build_software_skills.py --dry-run
#   21 software skills · unique jobs: 21
python3 scripts/build_engineering_skills.py --dry-run
#   15 skills · unique jobs across the whole library: 67
```

A duplicate id, or two skills claiming the same job, aborts the build. The
current library reports **67 unique jobs, 0 collisions**.

## Software skills (original, 21)

**Frontend** — the interface, the framework, the phone, the desktop:

| id | job |
|---|---|
| `frontend-ui` | build an interface (markup, CSS, interaction, a11y) |
| `frontend-framework` | work in React/Vue/Svelte/Angular |
| `frontend-mobile` | ship to phones (RN, Flutter, PWA) |
| `frontend-desktop` | ship a desktop app (Electron, Tauri) |

**Backend** — one per mainstream language, because the language is the tool
and the service is the job:

| id | stack | id | stack |
|---|---|---|---|
| `backend-node` | Express, Fastify, NestJS | `backend-rust` | Axum, Actix, Tokio |
| `backend-python` | FastAPI, Django, Flask | `backend-java` | Spring, Micronaut, Quarkus |
| `backend-go` | stdlib, Gin, Echo | `backend-php` | Laravel, Symfony |
| `backend-ruby` | Rails, Sinatra | `backend-dotnet` | ASP.NET Core |

**Platform** — the jobs every service needs:

| id | job |
|---|---|
| `api-design` | define the contract (REST/GraphQL/gRPC) |
| `data-and-databases` | model and store data (schema, migrations, SQL, NoSQL) |
| `auth` | identify users and permit actions |
| `background-jobs` | do work asynchronously |
| `testing` | verify it works (unit → e2e) |
| `deployment` | ship it (containers, CI/CD, TLS, rollback) |
| `observability` | know what it is doing (logs, metrics, traces) |
| `performance` | make it fast (measure → profile → fix) |
| `realtime` | push updates live (WS, SSE, polling) |

### Process skills (original, 8)

Distilled from the engineering discipline in
[mattpocock/skills](https://github.com/mattpocock/skills) (MIT) and decoupled
from that project's tooling — the methodology survives, the references to
their issue tracker and glossary do not.

| id | job |
|---|---|
| `process-research` | investigate before building (spikes, evidence, decisions) |
| `process-spec` | turn an idea into a spec |
| `process-plan` | break a spec into risk-ordered tasks |
| `process-implement` | build to a spec, keep the diff reviewable |
| `process-tdd` | red-green-refactor as a workflow |
| `process-diagnose` | hard bugs: reproduce, narrow, explain, fix |
| `process-review` | review on two axes: standards and spec |
| `process-ship` | the PR, the review conversation, the retro |

## AI/ML skills (original, 7)

Written for the work this toolkit actually supports — distillation and
fine-tuning under real hardware limits.

| id | job |
|---|---|
| `ml-training` | train or fine-tune: method, memory math, checkpoints |
| `ml-distillation` | **make a smaller model smarter** — what to distil, which signal, how to judge the student |
| `ml-datasets` | curate, dedupe, decontaminate, format |
| `ml-eval` | measure honestly: benchmarks, regression gates, contamination |
| `ml-inference` | quantize and serve: KV cache, batching, local runtimes |
| `ml-systems` | fit the hardware: VRAM, throughput, disk guards |
| `ml-agents` | design agents: tools, memory, loops, verification |

`ml-distillation` is the centrepiece: preference data over response
distillation over logit transfer, the capacity mismatch to expect from a small
student, and how to detect the failure where the student nails the format but
loses the reasoning.

## Adjacent skills, clearly separated

| pair | boundary |
|---|---|
| `testing` vs `xt-forge-verification` | test **strategy** vs **claims and benchmarks** |
| `process-tdd` vs `testing` | the **workflow** (red-green) vs the **strategy** (what to test) |
| `process-review` vs `xt-forge-verification` | reviewing **code** vs proving **results** |
| `process-diagnose` vs `performance` | finding a **defect** vs removing a **bottleneck** |
| `process-ship` vs `deployment` | shipping a **change** (PR) vs shipping a **system** (infra) |
| `ml-eval` vs `xt-forge-verification` | evaluating a **model** vs evaluating any **claim** |
| `ml-agents` vs `xt-forge-autonomy` | designing **an** agent vs using **our** taste/goal/loop |
| `ml-datasets` vs `data-and-databases` | **training** data vs **application** data |
| `frontend-ui` vs `frontend-framework` | markup/CSS/vanilla vs component state & routing |
| `api-design` vs `backend-*` | the contract vs its implementation |
| `data-and-databases` vs `backend-*` | the data layer vs the service layer |
| `deployment` vs `observability` | shipping vs watching |

## xt-forge skills (original)

| id | teaches |
|---|---|
| `xt-forge-memory` | hybrid recall, typed links, the review queue |
| `xt-forge-security` | scan / codec / re — and never printing a recovered secret |
| `xt-forge-recon` | the findings ledger and reproducible reports |
| `xt-forge-autonomy` | taste, verified goal completion, loop grammar |
| `xt-forge-catalog` | querying 4,810 repos for what to borrow |
| `xt-forge-context` | query-aware packing, ranked grep, code structure |
| `xt-forge-verification` | evidence-based claims and the measurement discipline |

## Harvested security skills (Apache-2.0)

**Advertised (12)** — high daily value, chosen to pair with xt-forge surfaces:

| skill | pairs with |
|---|---|
| `analyzing-linux-elf-malware` | `xtforge re info/sections/pack` |
| `analyzing-cobalt-strike-beacon-configuration` | `codec inspect`, `re strings` |
| `conducting-external-reconnaissance-with-osint` | `xtforge recon` |
| `abusing-dpapi-for-credential-access` | `scan secrets` |
| `conducting-pass-the-ticket-attack` | red team |
| `analyzing-linux-kernel-rootkits` | `re pack`, forensics |
| `analyzing-golang-malware-with-ghidra` | reverse engineering |
| `analyzing-macro-malware-in-office-documents` | malware analysis |
| `analyzing-malware-persistence-with-autoruns` | forensics |
| `analyzing-command-and-control-communication` | threat hunting |
| `analyzing-linux-system-artifacts` | forensics |
| `executing-red-team-exercise` | engagement meta |

**Load-on-demand (12)** — available by id (`@skill-id`), hidden from the
model's list so the advertised set stays affordable: shadow-credential abuse,
DCSync persistence, BloodHound recon, Havoc C2, C2 redirectors, PetitPotam
coercion, malleable C2 profiles, bootkits/rootkits, Android malware with
apktool, malicious PDFs, Cuckoo sandboxing, heap-spray exploitation.

## Provenance and licence

- **source**: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills>
- **commit**: `54a798831d2266a3ca61ce68a7acb80b81160d57`
- **licence**: Apache-2.0 — each copied directory keeps its own `LICENSE`
- **upstream clone**: `~/.local/share/opencode/skills-src/anthropic-cybersecurity`
  (60 MB, 818 skills — kept so anything can be pulled in later)
- **harvester**: `scripts/harvest_skills.py` (dry-run supported)

### Modified files

Apache-2.0 requires prominent notice of changes. Of the 24 copied skills:

- **12 are byte-identical** to upstream
- **12 differ in one place**: the `SKILL.md` frontmatter gained
  `metadata.opencode/autoinvoke: false` so the skill loads on demand instead
  of being advertised. The body is unmodified.

Every copied directory carries a `HARVEST.md` recording the source URL, the
commit, the licence and exactly what changed.

## Why not all 818?

| option | cost per model step | verdict |
|---|---:|---|
| all 818 security skills | ~25,000 tokens | rejected — eats the context before work starts |
| 24 curated security | ~2,600 tokens | too much for what it adds |
| **12 advertised + 12 on demand** | ~1,200 tokens | shipped |

## Total advertised budget

| group | skills | description cost |
|---|---:|---:|
| xt-forge | 7 | ~700 tokens |
| software | 21 | ~557 tokens |
| process | 8 | ~220 tokens |
| AI/ML | 7 | ~190 tokens |
| security (harvested) | 12 | ~1,200 tokens |
| **advertised** | **55** | **~2,451 tokens per step** |
| load-on-demand | 12 | 0 until used |

Descriptions are length-budgeted on purpose: the software skills average 106
characters. When adding one, shorten another or expect the cost to compound.

The remaining 794 security skills stay in the clone. Pulling one in later is a
copy, not a re-harvest.

## Managing the library

```sh
ls ~/.config/opencode/skills                  # what is installed
cat ~/.config/opencode/skills/<id>/HARVEST.md # where it came from
python3 scripts/harvest_skills.py --dry-run   # re-check the selection
```

To hide a skill without deleting it, add to its `SKILL.md`:

```yaml
metadata:
  opencode/autoinvoke: false
```

To pull in more from the clone, add the id to `ADVERTISED` or `QUIET` in
`scripts/harvest_skills.py` and re-run it.

## Rules

- skills are instructions, not dependencies: nothing here runs code on load
- never copy a skill without its licence file and a harvest record
- the advertised list is budgeted; adding one means removing one
