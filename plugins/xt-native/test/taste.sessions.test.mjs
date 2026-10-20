/**
 * The D2 acceptance test: ten scripted sessions, the expected learnings, and
 * nothing else.
 *
 * `docs/TOOL-BACKLOG.md` puts the bar for "taste in OpenCode" at *10
 * scripted sessions -> expected learnings, zero invented keys*. The other
 * plugin tests prove the plumbing; this one proves the learning contract
 * against the real xt-forge CLI and a real store:
 *
 *   - the six expected learnings exist, with the expected category and polarity
 *   - no other key was invented (near-miss prompts must stay silent)
 *   - only the rule with three consistent signals reaches the session
 *
 * Run: node --test plugins/xt-native/test/
 */
import { test } from "node:test"
import assert from "node:assert/strict"
import {
  chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { makeHarness } from "./harness.mjs"

/**
 * Ten prompts, in order. The first three are one preference phrased three
 * ways; the last two are near-misses that must not become learnings.
 */
const SESSIONS = [
  "Always add a --json flag to every command.",
  "Always add a --json flag to every command, always.",
  "Always use ruff for linting Python.",
  "Always prefer ruff for linting Python.",
  "Please use ruff for linting Python.",
  "Never hardcode absolute paths.",
  "Use tabs not spaces for indentation.",
  "Never commit secrets or access tokens.",
  "I think the parser should probably handle tabs.",
  "The build takes about 30 seconds on this machine.",
]

/** (category, key, polarity) — the complete set of allowed learnings. */
const EXPECTED = new Set([
  "cli|add json flag every command|1",
  "python|ruff linting python|1",
  "architecture|hardcode absolute paths|-1",
  "architecture|tabs|1",
  "architecture|spaces indentation|-1",
  "security|commit secrets access tokens|-1",
])

/** The rule that reaches `enforced`, and therefore the injected block. */
const ENFORCED = "python|ruff linting python"
const ENFORCED_BLOCK =
  '<taste source="xt-forge" enforcement="enforced only">\n' +
  '  <rule category="python" confidence="0.88">use ruff for linting Python</rule>\n' +
  "</taste>"

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** How many `taste ingest` calls the plugin has finished. */
function ingests(log) {
  if (!existsSync(log)) return 0
  return readFileSync(log, "utf-8")
    .split("\n")
    .filter((line) => line.includes("taste ingest")).length
}

/**
 * A wrapper around the real interpreter that logs every call *after* it
 * finishes. The plugin ingests in the background, so "the signal landed" is
 * only observable from the other side of that call.
 */
function writeWrapper(dir, log) {
  const real = process.env.XT_PYTHON ?? "python3"
  const path = join(dir, "python-wrapper.sh")
  writeFileSync(path, [
    "#!/bin/sh",
    `"${real}" "$@"`,
    "code=$?",
    `echo "$@" >> "${log}"`,
    "exit $code",
    "",
  ].join("\n"))
  chmodSync(path, 0o755)
  return path
}

test("ten scripted sessions: expected learnings, zero invented keys", async () => {
  const dir = mkdtempSync(join(tmpdir(), "xt-native-sessions-"))
  const log = join(dir, "calls.log")
  const wrapper = writeWrapper(dir, log)
  const store = join(dir, "xt-home")
  const blocks = []
  let signals = 0

  try {
    for (const [index, prompt] of SESSIONS.entries()) {
      const harness = await makeHarness({ xtHome: store, keepHome: true,
                                         python: wrapper })
      const before = await harness.cli(["taste", "stats"])
      signals = before.payload?.signals ?? 0

      await harness.hook("prompt", { prompt: { text: prompt } })

      // Wait for the background ingest to finish. A prompt that expresses no
      // preference still makes the call, so the call count is the signal.
      const deadline = Date.now() + 30000
      while (ingests(log) < index + 1 && Date.now() < deadline) {
        await sleep(25)
      }
      assert.equal(ingests(log), index + 1,
                   `the ingest for session ${index} never finished`)

      const event = { system: [], messages: [] }
      await harness.hook("context", event)
      const block = harness.systemParts(event).find((t) => t.includes("<taste"))
      blocks.push(block ?? "")
      harness.cleanup()
    }

    // 1. the expected learnings exist, and only they exist
    const harness = await makeHarness({ xtHome: store, keepHome: true,
                                       python: wrapper })
    const found = await harness.cli(["taste", "search", "--limit", "100"])
    const keys = (found.payload ?? []).map(
      (row) => `${row.category}|${row.key}|${row.polarity}`)
    assert.deepEqual(new Set(keys), EXPECTED)
    assert.equal(found.payload.length, EXPECTED.size)

    // 2. the near-miss prompts invented nothing
    const stats = await harness.cli(["taste", "stats"])
    assert.equal(stats.payload.signals, 9,
                 "two of the ten prompts express no preference")

    // 3. only the enforced rule reaches the session, and only once it is
    const enforced = (found.payload ?? []).filter((r) => r.status === "enforced")
    assert.equal(enforced.length, 1)
    assert.equal(`${enforced[0].category}|${enforced[0].key}`, ENFORCED)
    assert.equal(enforced[0].evidence, 3)

    for (const [index, block] of blocks.entries()) {
      if (index < 4) {
        assert.equal(block, "", `session ${index} injected a hint`)
      } else {
        assert.equal(block, ENFORCED_BLOCK)
      }
    }
    harness.cleanup()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
