/**
 * Session ownership of the goal record.
 *
 * The bug this pins: the plugin kept the active goal under one global
 * storage key, so two sessions in the same opencode instance overwrote each
 * other's objective *and* their approved check. The loser then saw its own
 * completion claim rejected with "evidence command is not approved" — for a
 * command it had never chosen, because a sibling session had taken the slot.
 *
 * The script drives the **real** plugin file (the canon that `xtforge sync`
 * installs) with a fake OpenCode context and reports what happened, as JSON.
 * The unittest next to it asserts on the report.
 *
 * Contract: write a JSON report to stdout, nothing else.
 *
 *   node tests/plugin/goal_scope.mjs
 */
import { execFile } from "node:child_process"
import { fileURLToPath, pathToFileURL } from "node:url"
import { dirname, resolve } from "node:path"

const HERE = dirname(fileURLToPath(import.meta.url))
// The canon is wherever `xtforge.core.plugin.manager` says it is; the caller
// passes it in so this script cannot drift from the shipped source.
const PLUGIN = resolve(process.env.XT_PLUGIN_PATH ??
                       resolve(HERE, "..", "..", "plugins", "xt-native",
                               "index.ts"))
const ROOT = process.env.XT_FORGE_ROOT ?? resolve(HERE, "..", "..")
const PYTHON = process.env.XT_PYTHON ?? "/usr/bin/python3"
const ENV = { ...process.env, PYTHONPATH: ROOT }

/** A completion claim whose only evidence is one command. */
function marker(cmd, claim) {
  return `<goal-done>
  <claim>${claim}</claim>
  <evidence>
    <item cmd="${cmd}" exit="0">${cmd}</item>
  </evidence>
</goal-done>`
}

/** A fake OpenCode plugin context: enough surface for the plugin to work. */
function fakeContext(hooks, commands, storage) {
  return {
    storage: {
      get: async (key) => storage.get(key),
      set: async (key, value) => { storage.set(key, value) },
    },
    command: {
      transform: async (fn) => {
        fn({ add: (definition) => commands.set(definition.name, definition) })
      },
      list: async () => [...commands.values()],
    },
    session: {
      hook: async (name, fn) => { hooks.set(name, fn) },
      synthetic: async () => {},
      prompt: async () => {},
    },
    location: { directory: ROOT },
  }
}

/** Run the context hook and return the verdict it injected. */
async function verdict(hooks, sessionID, messages) {
  const system = []
  await hooks.get("context")({ sessionID, messages, system })
  const text = system.map((part) => part?.text ?? "").join("\n")
  return /verdict="([^"]+)"/.exec(text)?.[1] ?? null
}

/** Set the approved check of one session, the way `/goal check` does. */
async function check(commands, sessionID, cmd) {
  const goal = commands.get("goal")
  if (!goal) throw new Error("the plugin registered no /goal command")
  await goal.execute({ sessionID, prompt: { text: `check ${cmd}` } })
}

async function main() {
  const hooks = new Map()
  const commands = new Map()
  const storage = new Map()

  const url = pathToFileURL(PLUGIN).href + "?scope=goal"
  const mod = await import(url)
  await mod.default.setup(fakeContext(hooks, commands, storage))

  // Two sessions, two goals, two approved checks.
  await check(commands, "ses_a", "echo ses-a-approved")
  await check(commands, "ses_b", "echo ses-b-approved")

  const report = {
    plugin: PLUGIN,
    aVerifyCmd: storage.get("goal.current:ses_a")?.verifyCmd ?? null,
    bVerifyCmd: storage.get("goal.current:ses_b")?.verifyCmd ?? null,
    aApproved: storage.get("goal.current:ses_a")?.approvedCmds ?? null,
  }

  // Session A claims completion with its own approved command.
  report.aVerdict = await verdict(hooks, "ses_a", [
    { role: "assistant", text: marker("echo ses-a-approved", "session A ran its check") },
  ])

  // Session C never recorded a goal: it must inherit no approved command.
  report.cVerdict = await verdict(hooks, "ses_c", [
    { role: "assistant", text: marker("echo ses-a-approved", "session C ran a check") },
  ])

  // A command that is on nobody's list is not proof.
  report.unapprovedVerdict = await verdict(hooks, "ses_a", [
    { role: "assistant", text: marker("echo three", "session A ran an unapproved check") },
  ])

  // The global mirror still exists for `/goal status` in a fresh session.
  report.mirrorVerifyCmd = storage.get("goal.current")?.verifyCmd ?? null

  process.stdout.write(JSON.stringify(report, null, 2) + "\n")
}

main().catch((error) => {
  console.error(String(error?.stack ?? error))
  process.exit(1)
})
