# XT-Forge 0.3.3 — release candidate

**Status: prepared for review. Not published.** No external publication has been
performed; that requires explicit authorization.

Built artifacts (verified by installation, see §4):

```
xt_forge-0.3.3-py3-none-any.whl
xt_forge-0.3.3.tar.gz
```

---

## 1. What changed in this release

| Area | Change | Verified |
|---|---|---|
| **Knowledge records** | `xtforge knowledge` — put/get/search/verify/revise/link/deprecate with lifecycle status, history, scope | yes |
| **Status integrity** | An agent cannot self-promote to `verified`; verification needs a method and, for promotion, an executed check | yes |
| **Confidence follows evidence** | A contradicted record drops to ≤0.05; it stops being recommended | yes |
| **Design library** | `xtforge design` over 4 curated entries (3 patterns + 1 anti-pattern) with declared state coverage | yes |
| **Design brief skill** | `xt-design-brief` — 8 questions, retrieval, state check, verification | written |
| **Dedup identity** | Records scoped by `target`/`project` no longer merge across scopes | yes |
| **Schema v2** | Additive migration on a live 195-row database, zero rows rewritten | yes |
| **Paths** | Design library and error-memory resolved relatively; no `/home/<user>` in shipped source | yes |
| **Version** | Installed copy reads package metadata instead of reporting 0.0.0 | yes |

---

## 2. Capability table

Honest separation. "Implemented" means the command exists and a test exercises
it. "Evaluated" means behaviour was measured. Nothing here is evaluated with a
live model.

| Capability | Command | Status | Evidence |
|---|---|---|---|
| Durable memory (scoped, typed) | `xtforge mem` | implemented | pre-existing |
| **Knowledge lifecycle** | `xtforge knowledge` | implemented | 30/30 `test_knowledge.py` |
| **Verified promotion gate** | `knowledge verify` | implemented | negative control fails 2 |
| Cross-store recall | `xtforge recall` | implemented | 24/24 |
| **Artifact verification** | `xtforge artifact` | implemented | 40/40 |
| Declared vs executed checks | `artifact check --declared` | implemented | negative control fails 3 |
| Dedup across scopes | (internal) | implemented | 18/18 |
| **Design library** | `xtforge design` | implemented | 3 patterns, 1 anti-pattern |
| Design brief workflow | skill `xt-design-brief` | **written, not exercised** | — |
| Guidance at DSH hooks | `dsh-guidance` | implemented | 24/24 fixtures |
| Model behaviour improvement | — | **unverified** | no authorized route |
| XER / PDF / PPTX | — | out of scope | — |

---

## 3. Install and quick start

```sh
# from the wheel
python3 -m venv ~/.venvs/xt
~/.venvs/xt/bin/pip install xt_forge-0.3.3-py3-none-any.whl
~/.venvs/xt/bin/xtforge version

# or from the sdist
python3 -m venv ~/.venvs/xt
~/.venvs/xt/bin/pip install xt_forge-0.3.3.tar.gz
```

No third-party runtime dependency. Python ≥ 3.11.

**State location** defaults to `~/.xt-forge`. Override with `XT_HOME`:

```sh
XT_HOME=/tmp/sandbox xtforge knowledge put --kind fact --title t --body b
```

### Quick start

```sh
# 1. record something you learned
xtforge knowledge put --kind problem \
  --title "tsc fails without --path" \
  --body "the compiler needs an explicit --path in this repo" \
  --project p1 --target build --author me

# 2. prove it (this is what promotes it to verified)
xtforge knowledge verify <id> --method "reran with --path" \
  --result pass --checker "tsc@1" --exit-status 0

# 3. find it again, scoped
xtforge knowledge search "tsc --path" --project p1

# 4. verify a produced file
xtforge artifact record report.csv --producer builder
xtforge artifact check report.csv --check csv-parses \
  --result pass --checker "csv@1" --exit-status 0
xtforge artifact require report.csv --requires csv-parses
xtforge artifact verify report.csv      # exit 0 only when required checks passed

# 5. search the design library
xtforge design search "dense results"
xtforge design check editor            # exit 1 if a required state is missing
```

---

## 4. Reproducible build and install evidence

```sh
uv build --out-dir /tmp/xtbuild .        # wheel + sdist
python3 -m venv /tmp/clean
uv pip install --python /tmp/clean/bin/python \
   /tmp/xtbuild/xt_forge-0.3.3-py3-none-any.whl
XT_HOME=/tmp/clean-home /tmp/clean/bin/xtforge version
```

Observed in a clean venv, from the wheel only:

| Check | Result |
|---|---|
| `version` | `xt-forge 0.3.3` **[V]** |
| `design search editor` | 1 match, resolves its own library **[V]** |
| `knowledge put` | id returned **[V]** |
| `knowledge verify` (executed) | `status=verified` **[V]** |
| `artifact record/check/require/verify` | `verified`, exit 0 **[V]** |
| `recall "clean probe"` | found in `mem` **[V]** |
| separate `XT_HOME` | 1 row in its DB, host DB untouched (199 rows) **[V]** |

---

## 5. Schema, migration, backup

- Schema version **2**. `_ensure_columns()` adds 8 nullable columns if absent;
  SQLite has no `ADD COLUMN IF NOT EXISTS`, so it inspects `PRAGMA table_info`.
- **Additive only.** A v1 database keeps every row; existing records read as
  `status: observed` with `statusInferred: true` rather than being relabelled
  `verified`.
- Verified on the live 195-row database: all rows intact, version bumped **[V]**.

### Backup and restore

```sh
# backup (WAL-safe: use the SQLite backup API, not cp of a live db)
python3 - <<'PY'
import sqlite3
src = sqlite3.connect("/home/<user>/.xt-forge/mem.db")
dst = sqlite3.connect("/tmp/mem-backup.db")
src.backup(dst); dst.close(); src.close()
PY

# restore
cp /tmp/mem-backup.db "$XT_HOME/mem.db"
```

### Rollback of this release

| Change | Revert |
|---|---|
| Schema v2 columns | leave them; v1 code ignores unknown nullable columns |
| `knowledge`, `design` modules | delete `xtforge/core/mem/knowledge.py`, `xtforge/cli/{knowledge,design}_cmd.py`, and their `_add_*` calls |
| Version fallback | restore `xtforge/version.py.bak-*` |
| Prompt launcher discovery | restore `xtforge/core/prompts.py` from git |

Timestamped `.bak-*` files exist for every edited file; they are excluded from
the build.

---

## 6. Compatibility

| Item | Support |
|---|---|
| Python | ≥ 3.11 (uses `tomllib`-free path; verified on 3.12 and 3.14) |
| OS | Linux (POSIX paths, WAL SQLite) |
| SQLite | bundled with Python; FTS5 used when available, trigram fallback otherwise |
| MCP | stdio JSON-RPC 2.0 |
| Node | not required for the core; the DSH guidance plugin is separate |
| Existing databases | v1 auto-upgrades in place, additive |

---

## 7. Release blockers

Honest list. Each of these prevents describing the release as complete.

| # | Blocker | Why it blocks | Resolution |
|---|---|---|---|
| B1 | **Design brief skill never exercised** | written but no agent has run it; claim would be untested | run one real UI task through it, or mark experimental |
| B2 | **No live-model evaluation** | guidance/knowledge effect on model behaviour unmeasured | needs an authorized provider route |
| ~~B3~~ | ~~No LICENSE file~~ | **resolved** — `LICENSE` added, ships in sdist | — |
| B4 | **Native binary not built** | `native/xtforge-rs` exists but the release is Python-only | document the Python path as authoritative or ship the binary |
| B5 | **`design` entry count is small** | 3 patterns is a seed, not a library | state it; growing it is not a release blocker but should be documented |
| ~~B6~~ | ~~`tests/` not in the sdist~~ | **not a blocker** — verified 23 test files are included | — |
| ~~B7~~ | ~~No CHANGELOG entry~~ | **resolved** — 0.3.3 entry added | — |

### Explicitly out of scope

Themes and Qoder are excluded from this assignment. XER/P6, PDF and PPTX
workflows are not part of this release.

---

## 8. What was not done

- The design library has **3 patterns**, not the breadth the brief describes
  (dashboards, settings, workspaces, typography/spacing/colour guidance,
  templates per stack). It is a working seed with a real index and state checks,
  not a catalogue.
- **Design proposals** (item 5) are not a separate workflow: an agent can record
  a `design` knowledge entry with `status: proposed`, which satisfies the
  evidence rule, but there is no review queue or versioned pattern registry.
- **Automatic incident aggregation** (item 2) is not built. Dedup exists and
  works; aggregation of duplicate incidents into one record is not implemented.
- **Outcome feedback** (item 6) is not built: whether retrieved guidance was
  used and helped is not tracked.
- **Preflight, task kits, problem bundles, artifact lineage, knowledge health**
  (item 6) are not built.
