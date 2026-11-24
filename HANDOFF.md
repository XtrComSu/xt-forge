# Handoff — xt-forge breadth, CVE tooling, production review

Written at session end. Everything below is labelled by how it is known:

- **verified** — a command was run and its output is what is reported
- **recorded** — found in a log, doc, or commit message
- **planned** — not yet true

Repo: `/home/xtrcom/projects/xt-forge`, HEAD `e01cd9d`. Tree has two untracked paths: this file and
`docs/assets/session-captures/` (the README evidence images — see §2 item 2). Neither is committed.

---

## 1. What was completed

### The three partial breadth rows — all closed

**verified**: `python3 scripts/rea_breadth.py`

```
REA tools                263
capabilities compared    101
  covered                91
  partial                3
  missing                0
  out-of-lane (excluded) 7
  REA tools mapped       263/263
in-lane coverage         91/94 = 96.8%
```

The percentage did not move, and that is the honest outcome — see §5. What moved is that three
rows' worth of "we cannot do this" turned out to be wrong, and the work is now implemented.

| Row | What it claimed | What was true |
|---|---|---|
| **il2cpp** | type/method records unreachable | stride derivable from the file; `e9943ef` |
| **NTFS journal** | no transaction records | `RCRD` paging + `RESTART_AREA`; `929914f` |
| **web-runtime** | 4 tools blocked by platform | 3 of 4 implementable; `75a990f` |

The pattern was consistent across all three: a note saying "not implemented" recorded as though it
said "not implementable". Each was verified with a live probe before being called blocked.

**Fixing web-runtime exposed a bug in shipped code.** `launch_and_inspect` launched the browser on
the target URL and attached immediately, so the first `Runtime.evaluate` ran against the blank
pre-navigation document. `document.title` came back `''` and anything a page installs at parse time
read as absent. This affected **every** `re cdp` aspect, not just WebMCP. The identical race had
already been found and fixed for network capture six months earlier — it was fixed there and not in
the shared launch path, so it came back. Measured: title `''` → `'WebMCP demo'`,
`typeof document.modelContext` `undefined` → `object`.

### Dependency + CVE discovery and application — new capability

Four verbs, `aee4843` plus follow-ups. Not in REA at all; folded into the existing
`inspect_elf_dependencies` row rather than padding the denominator with a new one (§5).

- `re deps` — inventories a tree or compiled artifact at exact versions across Go, npm, PyPI,
  crates.io, Maven, NuGet, Packagist, RubyGems, pub, Hex. Parses 13 manifest formats plus a Go
  binary's own buildinfo. A range rather than a pin is reported `resolved: false` and **never
  queried** — a vulnerability is a property of a version.
- `re vulns` — matches pinned versions against OSV and decides from each advisory's own `affected`
  ranges, so a version above a `fixed` event is not reported even though OSV still lists the
  package.
- `re remediate` — plans bumps, applies with `--write`, confirms each by re-parsing.
- `re cve-info` — one advisory in full.

**verified** end to end on a two-package Go tree: 8 distinct vulnerabilities (HIGH=4, MODERATE=2,
UNKNOWN=2) → both bumped → re-scan drops to 6 with gin fully clean → `.xtbak` written.

### Production review — the real bugs found and fixed

Counted by fix, not by symptom; several of these are one mistake appearing in more than one place,
and those are grouped rather than split to make the number look larger. Every one is in code written
during this session, and every one is mutation-checked — the fix was reverted and the test watched
going red. This is the section worth reading first if you pick this up.

**Electron fuses — three ways the reader reported safety it had not established** (`d1bade7`).
All three are the same error: an uninterpreted fuse rendering as a clean one. That is the worst
failure mode a security reader has, because the output is not incomplete, it is a conclusion.

1. Unknown state bytes vanished from the summary. Nine `0xff` bytes decoded to nine entries each
   carrying `hardening: None` and a note saying the state was unrecognised — then appeared in none
   of `exposed`, `hardened` or `undetermined`. The filter asked for `state == "inherit"`. **Nine
   unknowns read as nine clean fuses.**
2. The renderer printed `"no exposure found on this wire"` over the top of them. Fixing the data
   left the sentence — the closing line a reader skims. Same error in prose.
3. A wire version other than 1 was decoded with version-1 names, putting a real name on a
   possibly-wrong slot.

Also: an `assert` in library code (vanishes under `python -O`), and a dropped `return` that made
`re fuses <non-Electron binary>` print **nothing and exit 0** — the real case being the 463 MB
Chromium in the Playwright cache, correctly identified as not-Electron and silently so.

**`remediate` could write an edit it had not verified** (`4d68b8f`). Order was rewrite →
`write_text` → re-parse. Six lines separated the write from the check meant to gate it. Measured on
a Gemfile.lock carrying `# NOTE: gin was pinned at 1.6.0`:

```
on-disk after:  # NOTE: gin was pinned at 1.9.0 for a reason
                  gin (1.6.0)                      <- the real pin, untouched
ok: False   applied: 0   files_changed: ['Gemfile.lock']
```

Comment rewritten, dependency not bumped, file modified, no failure message. Confirmation now runs
first; a file with any unconfirmed edit is not written at all.

**`_rewrite_locked` matched versions and names as bare substrings** (same commit). `if name in line
and old in line`, then `line.index(old)` — wrong in all three parts, silently:

| Input | Edit | Produced |
|---|---|---|
| `other (11.0.0)` | `other` 1.0→1.2 | `other (11.2.0)` — fabricated version |
| `rack-cors (1.0.5)` | `rack-cors` 1.0→1.2 | `rack-cors (1.2.5)` — fabricated version |
| `gin-gonic (1.6.0)` | `gin` 1.6.0→1.9.0 | `gin-gonic (1.9.0)` — wrong package |
| `# NOTE: gin was pinned at 1.6.0` | `gin` 1.6.0→1.9.0 | comment rewritten |

Names and versions now require delimiters; comment lines are excluded (`<!--` included, because
pom.xml has no positional rewriter and reaches this function).

**`plan()` accepted swapped arguments** (same commit). `dependencies` and `findings` are both lists
of dicts carrying name/version/ecosystem, so every key matched, the call reached `choose_target`
with an empty advisory list, and reported *"no advisory in this set names a fixed version newer
than the installed one"* — a confident statement about advisories for a failure caused entirely by
argument order. A finding is the only one of the two carrying `vulnerabilities`.

**`range_contains` returned `"fixed": last_affected`** (same commit). Different events, different
semantics: the `last_affected` version **is** affected, the `fixed` version is not. Unread at the
time, which is how it stayed wrong.

**The archive/nib decoders refused bytes** (`e01cd9d`). `inspect_electron_fuses` accepted a path or
the bytes themselves; these two accepted only a path, and passing bytes was treated as a *filename*:

```
not a regular file: b'<?xml version="1.0"…#'
```

a missing-file diagnosis handed to someone who never passed a filename. `path` also echoed the whole
multi-kilobyte blob into every report.

### Stress testing

**verified**:

- **650 fuzzed inputs** across the fuse, il2cpp and NTFS readers — no crashes, none over one second.
- **200 random byte strings** into the nib decoder — 0 raises. Plus deliberately broken archives
  (no `$objects`, `$objects` not a list, `$top` past the table, an object that is a string, a
  self-reference, missing `$classname`, empty input): all return `ok: false` with a diagnostic.
- **256 MB image** read in 0.18s (budget respected).
- **Concurrency** (`5f553b8`): serial scan of 10 packages = median 16.35s → 12 in flight = 2.34s
  (7.0x), 16 = 1.61s (10.2x). Identical counts, ids and order.

`querybatch` was measured and **rejected** despite an unused `OSV_BATCH` constant that looks like an
oversight: it returns only `{id, modified}` — no ranges — so deciding anything needs a second round
trip per advisory, and it does not filter by version server-side (72 advisory links vs 46 matching
vulnerabilities for the same 10 packages). Two-phase measured 16.0s vs 6.7s for the direct serial
calls it was meant to replace. The constant stays; the docstring now says why `scan` ignores it.

### Differential testing against outside oracles

Not self-referential tests — real ones:

- **Version ordering vs `node-semver`**: 15/15 valid cases agree. The 3 disagreements are inputs
  node-semver *rejects* (`1.0`, `1.2.3.4`, `rc2`) which are accepted leniently because OSV data
  contains them.
- **`range_contains`**: 33/33 cases plus an exact monotonicity sweep. Correct on two- and
  three-branch advisories, `last_affected`, `limit`, `fixed: 0`, open-ended.
- **Go buildinfo** verified against `go version -m` on a binary built on this host.
- **Chromium** is correctly reported as not-Electron.

**1740 test functions across 144 files. Full suite: 1738 tests, 24 skips, OK.**

---

## 2. What is left

### Immediate

1. **`scripts/render_terminal_png.py` is untracked.** Review it and commit, or discard. It renders
   captured terminal output as PNG with a real monospace font, colouring by content (so `HIGH` is
   red, `[ok]` green) rather than by line position.

2. **11 README images are rendered and preserved, but not yet referenced by the README.** They live
   in `docs/assets/session-captures/` (22 files, 636K — 11 PNGs plus the source text each was
   rendered from), copied out of tmpfs so they cannot be lost. **The directory is untracked** — it
   needs a `git add` to survive a fresh clone:

   ```
   01-deps.png  02-vulns.png  03-remediate-dry.png  04-remediate-write.png
   05-diff.png  06-vulns-after.png  07-fuses.png  08-nib.png
   09-webmcp.png  10-cdp.png  11-ntfs.png
   ```

   Each is real CLI output, prefixed with the command that produced it. Move them into `docs/assets/`
   proper (or keep the subdirectory) once referenced, and decide whether the `.txt` source files
   should stay — they are the audit trail for the images, which is worth more than it sounds: it is
   the difference between "this is a screenshot" and "this is a screenshot you can re-derive".

3. **README rewrite not started.** Current README is 332 lines and was read in full; no edits made.
   It is accurate on the MCP gateway, skills and benchmarks, and **says nothing** about
   dependency/CVE tooling, Electron fuses, WebMCP, nib, il2cpp or NTFS — the entire body of work in
   this session is undocumented.

### Deliberately not done, with reasons

4. **il2cpp and NTFS images are not in the set.** I built synthetic images for both and neither
   exercised the real parser — the il2cpp header offsets were wrong and the NTFS boot sector did not
   populate. Rather than ship a screenshot that looks like a demo but proves nothing, the NTFS
   capture was rebuilt from the test suite's **verified** fixture (`tests/test_re_ntfs.py`,
   `LogRecordTest`) and is genuine: 5 records, 3 transactions, padding correctly skipped. The
   il2cpp one was dropped entirely and should only be added from a real `global-metadata.dat`,
   which does not exist on this host.

5. **GIFs not made.** `ffmpeg` is available; `asciinema`, `agg`, `vhs`, `termtosvg` are not. A GIF
   would have to be assembled from PNG frames, which is a slideshow, not a demo — worse than the
   static images. 15 existing GIFs are already in `docs/assets/` and should be reused by reference.

6. **No README command was verified.** Every command currently in the README was written by a
   previous session. Before publishing, run each one.

### Carried over from the parent objective

7. **Unprobed covered rows (4)**: Kernel cache, Build VM (out-of-lane), Flutter/Dart, Debugger
   session control. These are marked `covered` in the breadth matrix **with no probe behind them** —
   a verdict resting on a naming coincidence. The same class of error this session spent its time
   disproving.

8. **Agentic 9-tier eval not re-run on 0.4.7.** The 93.3% in the README is a **0.4.6 floor**.

9. **Windows and macOS have never executed anything.** `install.ps1` assertions are text-only —
   never run on Windows. Stated honestly in the README already; do not quietly drop that caveat.

---

## 3. How to reproduce the captures

```sh
# The demo project the evidence images came from
mkdir -p /tmp/demo
cat > /tmp/demo/go.mod <<'EOF'
module example.com/demo

go 1.21

require (
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/text v0.3.0
	github.com/google/uuid v1.3.0
)
EOF

./bin/xtforge re deps /tmp/demo
./bin/xtforge re vulns /tmp/demo                       # 8 vulns
cp /tmp/demo/go.mod /tmp/demo/go.mod.orig
./bin/xtforge re remediate /tmp/demo --write           # gin 1.6.0->1.7.7, text 0.3.0->0.3.3
diff /tmp/demo/go.mod.orig /tmp/demo/go.mod
./bin/xtforge re vulns /tmp/demo                       # 6 vulns, gin clean
```

Fuses and nib images came from structure-built fixtures; the exact byte layout is in
`tests/test_re_electron.py` and `tests/test_re_nib.py`. WebMCP needs a local page that registers
`document.modelContext` — `tests/test_re_cdp_webmcp.py` has one.

---

## 4. Environment facts worth not rediscovering

- Shell launcher outside a tool call:
  `/home/xtrcom/.dsh/agy-accounts/acc_1793715748066_0taiw/bin/xtforge <cmd> --json`
- UI verbs need 4–5 edits: `scan_cmd.py` dispatch + renderer branch, `cli/__init__.py` argparse
  `choices`, `adapters/mcp_server.py` TOOL enum, `core/re/guidance.py` `KNOWN_VERBS`.
- **Renderer hazard**: renderer branches are one long `elif verb == …` chain inside `cmd_re`. A
  second `elif` for the same verb is silently unreachable.
- **`_page_targets` returns a dict on error, a list on success.** Code that assumes a list crashes
  on failure instead of reporting it.
- **`launched_browser` yields a dict, not a port** — `{"port", "binary", "profile"}`.
- `plistlib` on this Python cannot serialize `plistlib.UID`; encode as `{"CF$UID": n}` instead.
- Chromium 141.0.7390.37 at `~/.cache/ms-playwright/chromium-1194/chrome-linux/chrome`, 463 MB, has
  **no `WebMCP` domain** in `/json/protocol` — verified, not assumed.
- **No Electron binary exists anywhere on this host.** A filesystem search for the fence-post
  sentinel finds none. The fuse reader's positive path rests on the documented format
  (`@electron/fuses`), and the tests say so.
- No `mkntfs`/mount capability, so a real Windows `$LogFile` cannot be produced here. The NTFS row
  stays `partial` for exactly that reason.
- No `global-metadata.dat` anywhere on this host.
- Disk is tmpfs ~3.8G and easily exhausted; truncate large logs.

---

## 5. Readings on the breadth metric

The number did not move this session, and that is worth understanding before trying to move it.

**"Out-of-lane" is self-chosen**, so it is where an inflated number can hide. A row marked out of
lane is excluded from the denominator, which raises the percentage without any work. There are 7
such rows. Any future claim of increased breadth should be checked against whether the denominator
changed.

**Do not add a row for a capability REA lacks.** The dependency/CVE work is genuinely new — REA has
nothing comparable — and adding it as a new row would have padded the denominator with a free win
and moved the percentage for no reason. It was folded into the existing
`inspect_elf_dependencies` row instead (`0502c79`), which is where it honestly belongs: REA's tool
names `DT_NEEDED` entries and stops, and a name is not a version.

**A verdict with no probe rests on a naming coincidence.** 88 of 91 covered rows have probes and all
88 pass. The 4 listed in §2 item 7 do not have one yet.

**The fixtures matter more than the probes.** A probe that passes because the tool rejects an
invalid fixture proves nothing, and a fixture that cannot exercise the feature makes a passing
probe vacuous. Both happened during this session.

---

## 6. If you only read one thing

The bugs in §1 are all the same bug wearing different clothes: **a tool reporting a conclusion it
had not established.** Nine unknown fuses rendering as nine clean ones. An unverified edit written
to disk. A version matched inside a longer version. A diagnosis about advisories for an argument-order
error. Every one passed its test suite before being found, and every one was found by a probe that
asked what the output actually meant rather than whether the function returned.

The method that found them: build an input the code should refuse, check that it refuses *for the
right reason*, then revert the fix and watch the test fail. A test that cannot fail is worse than no
test, because it reads as coverage.
