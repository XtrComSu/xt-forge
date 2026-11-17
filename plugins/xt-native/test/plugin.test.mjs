/**
 * Plugin contract tests.
 *
 * The plugin is the shipped part of taste, so it gets the same treatment as
 * the core: a real module, loaded for real, driven through a mock OpenCode
 * context, against an isolated store.
 *
 *   node --test plugins/xt-native/test/
 */
import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { makeHarness } from "./harness.mjs"

/** Three phrasings of one rule: they merge into one enforced learning. */
const JSON_RULE = [
  "Always use --json for command output.",
  "Use --json for command output.",
  "Always prefer --json for command output.",
]

/** Learn the same rule until it reaches `enforced`. */
async function learnEnforced(harness) {
  for (const statement of JSON_RULE) {
    await harness.command("taste", `learn ${statement}`)
  }
}

test("registers every command", async () => {
  const harness = await makeHarness()
  try {
    for (const name of ["taste", "goal", "loop", "loops", "loop-stop", "xtf"]) {
      assert.ok(harness.commands.has(name), `missing command: ${name}`)
      assert.ok(harness.commands.get(name).description.length > 0)
    }
    const metaOut = await harness.command("xtf", "--meta")
    assert.match(metaOut, /xt-forge --meta/)
  } finally {
    harness.cleanup()
  }
})

test("learn writes a learning and stats reads it back", async () => {
  const harness = await makeHarness()
  try {
    const out = await harness.command("taste", "learn Always omit semicolons")
    assert.match(out, /\[taste\] learned/)
    const stats = await harness.command("taste", "stats")
    assert.match(stats, /"total": 1/)
  } finally {
    harness.cleanup()
  }
})

test("why shows the evidence log", async () => {
  const harness = await makeHarness()
  try {
    const learned = await harness.command("taste", "learn Always omit semicolons")
    const id = JSON.parse(learned.slice(learned.indexOf("{"))).id
    const why = await harness.command("taste", `why ${id}`)
    assert.match(why, /evidence_log/)
  } finally {
    harness.cleanup()
  }
})

test("forget retires a learning", async () => {
  const harness = await makeHarness()
  try {
    const learned = await harness.command("taste", "learn Always omit semicolons")
    const id = JSON.parse(learned.slice(learned.indexOf("{"))).id
    await harness.command("taste", `forget ${id}`)
    const shown = await harness.command("taste", `why ${id}`)
    assert.match(shown, /"status": "retired"/)
  } finally {
    harness.cleanup()
  }
})

test("the prompt hook records an explicit preference", async () => {
  const harness = await makeHarness()
  try {
    await harness.hook("prompt", {
      prompt: { text: "Always use --json for command output." },
    })
    // The hook ingests in the background, so wait for the signal to land
    // instead of racing it.
    const landed = await harness.waitFor(async () => {
      const stats = await harness.cli(["taste", "stats"])
      return (stats.payload?.signals ?? 0) >= 1
    })
    assert.ok(landed, "the preference was never recorded")
    const stats = await harness.cli(["taste", "stats"])
    assert.equal(stats.payload.total, 1)
    assert.equal(stats.payload.signals, 1)
  } finally {
    harness.cleanup()
  }
})

test("one prompt is ingested once, however many times the hook fires", async () => {
  // The plugin is loaded once per location, so the same session can have the
  // prompt hook registered more than once. Every registration used to ingest
  // the prompt again, which inflated the evidence count: a rule the user
  // stated once reached `enforced` and was then injected into every session.
  // The store makes the ingest idempotent on the prompt's id, because the
  // plugin's module state is not shared between its loads.
  const harness = await makeHarness()
  try {
    const event = {
      messageID: "msg_dup_1",
      prompt: { text: "Always use --json for command output." },
    }
    await harness.hook("prompt", event)
    await harness.hook("prompt", event)
    await harness.hook("prompt", event)
    const landed = await harness.waitFor(async () => {
      const stats = await harness.cli(["taste", "stats"])
      return (stats.payload?.signals ?? 0) >= 1
    })
    assert.ok(landed, "the preference was never recorded")
    // Give any duplicate ingest a chance to land before counting.
    await new Promise((r) => setTimeout(r, 400))
    const stats = await harness.cli(["taste", "stats"])
    assert.equal(stats.payload.signals, 1,
                 "the same prompt was ingested more than once")
    assert.equal(stats.payload.total, 1)
  } finally {
    harness.cleanup()
  }
})

test("a different prompt is a different piece of evidence", async () => {
  // The dedup key is the prompt id, not the text: two distinct prompts that
  // happen to read alike are still two statements.
  const harness = await makeHarness()
  try {
    const text = "Always use --json for command output."
    await harness.hook("prompt", { messageID: "msg_a", prompt: { text } })
    await harness.hook("prompt", { messageID: "msg_b", prompt: { text } })
    const landed = await harness.waitFor(async () => {
      const stats = await harness.cli(["taste", "stats"])
      return (stats.payload?.signals ?? 0) >= 2
    })
    assert.ok(landed, "the second prompt was never recorded")
    const stats = await harness.cli(["taste", "stats"])
    assert.equal(stats.payload.signals, 2)
  } finally {
    harness.cleanup()
  }
})

test("the context hook injects the enforced block", async () => {
  const harness = await makeHarness()
  try {
    await learnEnforced(harness)
    const event = { system: [], messages: [] }
    await harness.hook("context", event)
    const block = harness.systemParts(event).find((t) => t.includes("<taste"))
    assert.ok(block, "no taste block injected")
    assert.match(block, /enforcement="enforced only"/)
    assert.equal((block.match(/<rule /g) ?? []).length, 1)
  } finally {
    harness.cleanup()
  }
})

test("nothing is injected when no rule is enforced", async () => {
  const harness = await makeHarness()
  try {
    await harness.command("taste", "learn Always omit semicolons")
    const event = { system: [], messages: [] }
    await harness.hook("context", event)
    const block = harness.systemParts(event).find((t) => t.includes("<taste"))
    assert.equal(block, undefined)
  } finally {
    harness.cleanup()
  }
})

test("taste off disables injection and survives a restart", async () => {
  const harness = await makeHarness()
  try {
    await learnEnforced(harness)
    await harness.command("taste", "off")
    const off = { system: [], messages: [] }
    await harness.hook("context", off)
    assert.equal(harness.systemParts(off).find((t) => t.includes("<taste")),
                 undefined)
    assert.equal(harness.storage.get("taste.enabled"), false)

    await harness.command("taste", "on")
    const on = { system: [], messages: [] }
    await harness.hook("context", on)
    assert.ok(harness.systemParts(on).find((t) => t.includes("<taste")))
  } finally {
    harness.cleanup()
  }
})

test("two plugin loads still ingest one prompt once", async () => {
  // The plugin is loaded once per location, so two loads can both see the
  // same prompt. The set of seen prompts is per load, so the store is what
  // has to recognise a prompt it already holds — the store is the one thing
  // every load writes through.
  const home = mkdtempSync(join(tmpdir(), "xt-native-shared-"))
  const first = await makeHarness({ xtHome: home })
  const second = await makeHarness({ xtHome: home })
  try {
    const event = {
      messageID: "msg_shared_1",
      prompt: { text: "Always use --json for command output." },
    }
    await first.hook("prompt", event)
    await second.hook("prompt", event)
    const landed = await first.waitFor(async () => {
      const stats = await first.cli(["taste", "stats"])
      return (stats.payload?.signals ?? 0) >= 1
    })
    assert.ok(landed, "the preference was never recorded")
    // Give any duplicate ingest a chance to land before counting.
    await new Promise((r) => setTimeout(r, 400))
    const stats = await first.cli(["taste", "stats"])
    assert.equal(stats.payload.signals, 1,
                 "the same prompt was ingested twice across two loads")
    assert.equal(stats.payload.total, 1)
  } finally {
    second.cleanup()
    first.cleanup()
    rmSync(home, { recursive: true, force: true })
  }
})

test("a fabricated goal-done claim is rejected in the same request", async () => {
  const harness = await makeHarness()
  try {
    const event = {
      system: [],
      messages: [{
        role: "assistant",
        text: "<goal-done><claim>all done</claim><evidence></evidence></goal-done>",
      }],
    }
    await harness.hook("context", event)
    const verdict = harness.systemParts(event)
      .find((t) => t.includes("<goal-verification"))
    assert.ok(verdict, "no verification verdict injected")
    assert.match(verdict, /verdict="(reject|insufficient_evidence)"/)
    assert.doesNotMatch(verdict, /verdict="pass"/)
  } finally {
    harness.cleanup()
  }
})

test("a claim with the approved command passes", async () => {
  const harness = await makeHarness()
  try {
    await harness.command("goal", "ship the taste plugin")
    await harness.command("goal", "check echo suite green")
    const event = {
      system: [],
      messages: [{
        role: "assistant",
        text: "<goal-done><claim>suite is green</claim><evidence>" +
              "<item cmd=\"echo suite green\" exit=\"0\">suite green</item>" +
              "</evidence></goal-done>",
      }],
    }
    await harness.hook("context", event)
    const verdict = harness.systemParts(event)
      .find((t) => t.includes("<goal-verification"))
    assert.ok(verdict, "no verification verdict injected")
    assert.match(verdict, /verdict="pass"/)
  } finally {
    harness.cleanup()
  }
})

test("a loop marker does not break the session", async () => {
  const harness = await makeHarness()
  try {
    const event = {
      system: [],
      messages: [{
        role: "assistant",
        text: '<loop-next delay="300" reason="CI still running"/>',
      }],
    }
    await harness.hook("context", event)
    assert.ok(true)
  } finally {
    harness.cleanup()
  }
})

test("loop schedules, lists and cancels a task", async () => {
  const harness = await makeHarness()
  try {
    const out = await harness.command("loop", "every 30m check the CI")
    assert.match(out, /\[loop\]/)
    const tasks = harness.storage.get("loop.tasks")
    assert.equal(tasks.length, 1)
    assert.equal(tasks[0].mode, "fixed")

    const listed = await harness.command("loops")
    assert.match(listed, /\[loop\] 1 scheduled/)

    const stopped = await harness.command("loop-stop")
    assert.match(stopped, /cancelled 1/)
    assert.equal((harness.storage.get("loop.tasks") ?? []).length, 0)
  } finally {
    harness.cleanup()
  }
})

test("a broken xt-forge degrades instead of breaking the session", async () => {
  const harness = await makeHarness({ python: "/nonexistent/python3" })
  try {
    const out = await harness.command("taste", "stats")
    assert.match(out, /degraded/)

    const event = { system: [], messages: [] }
    await harness.hook("context", event)
    assert.equal(harness.systemParts(event).find((t) => t.includes("<taste")),
                 undefined)
  } finally {
    harness.cleanup()
  }
})
