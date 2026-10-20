/**
 * Test harness for the xt-native plugin.
 *
 * The plugin is a plain TypeScript module with a default export that takes an
 * OpenCode context. To test it without OpenCode we build a mock context that
 * records what the plugin registers and lets the test fire it.
 *
 * The plugin reads `XT_HOME` and `XT_FORGE_ROOT` at import time, so the
 * environment is set before the module is loaded and every import is given a
 * cache-busting query so two harnesses never share module state.
 */
import { execFile } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
export const PLUGIN_PATH = join(HERE, "..", "index.ts")
export const REPO_ROOT = join(HERE, "..", "..", "..")

let importCounter = 0

/**
 * Build a harness around a fresh plugin instance.
 *
 * `xtHome` isolates the taste store: the plugin passes XT_HOME to the
 * xt-forge CLI, so a temp directory means the test never touches the real
 * profile.
 */
export async function makeHarness({ xtHome, keepHome = false, python } = {}) {
  const home = xtHome ?? mkdtempSync(join(tmpdir(), "xt-native-"))
  const previous = {
    XT_HOME: process.env.XT_HOME,
    XT_FORGE_ROOT: process.env.XT_FORGE_ROOT,
    XT_PYTHON: process.env.XT_PYTHON,
  }
  process.env.XT_HOME = home
  process.env.XT_FORGE_ROOT = REPO_ROOT
  // A bogus interpreter is how the degradation test makes xt-forge
  // unavailable on purpose.
  if (python) process.env.XT_PYTHON = python

  const url = `${pathToFileURL(PLUGIN_PATH).href}?v=${++importCounter}`
  const mod = await import(url)
  const plugin = mod.default

  const storage = new Map()
  const commands = new Map()
  const hooks = new Map()
  const synthetic = []
  const prompts = []
  const sessionID = "ses_test"

  const ctx = {
    storage: {
      get: async (key) => storage.get(key),
      set: async (key, value) => { storage.set(key, value) },
      scan: async () => [...storage.entries()],
    },
    command: {
      transform: async (fn) => {
        fn({
          add: (command) => { commands.set(command.name, command) },
        })
      },
      list: async () => [...commands.values()],
    },
    session: {
      hook: async (name, fn) => { hooks.set(name, fn) },
      synthetic: async ({ sessionID: sid, text }) => {
        synthetic.push({ sessionID: sid, text })
      },
      prompt: async ({ sessionID: sid, text, delivery }) => {
        prompts.push({ sessionID: sid, text, delivery })
      },
    },
    location: { directory: REPO_ROOT },
  }

  await plugin.setup(ctx)

  const harness = {
    plugin,
    ctx,
    storage,
    commands,
    hooks,
    synthetic,
    prompts,
    sessionID,
    xtHome: home,

    /** Run a registered command and return the text it sent to the session. */
    async command(name, text = "") {
      const cmd = commands.get(name)
      if (!cmd) throw new Error(`command not registered: ${name}`)
      const before = synthetic.length
      await cmd.execute({ sessionID, prompt: { text } })
      return synthetic.length > before ? synthetic[synthetic.length - 1].text : ""
    },

    /** Fire a session hook with the given event payload. */
    async hook(name, event = {}) {
      const fn = hooks.get(name)
      if (!fn) throw new Error(`hook not registered: ${name}`)
      return fn({ sessionID, ...event })
    },

    /** The system parts the plugin pushed during the last context hook. */
    systemParts(event = {}) {
      const parts = Array.isArray(event.system) ? event.system : []
      return parts
        .map((p) => (typeof p?.text === "string" ? p.text : ""))
        .filter(Boolean)
    },

    /** Run the xt-forge CLI against this harness's isolated XT_HOME. */
    cli(args) {
      return new Promise((resolve) => {
        execFile(
          process.env.XT_PYTHON ?? "python3",
          ["-m", "xtforge.cli", ...args, "--json"],
          {
            cwd: REPO_ROOT,
            env: { ...process.env, XT_HOME: home, PYTHONPATH: REPO_ROOT },
            timeout: 30000,
            maxBuffer: 8 << 20,
          },
          (error, stdout, stderr) => {
            let payload = null
            try { payload = JSON.parse(stdout) } catch { /* not json */ }
            resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr, payload })
          },
        )
      })
    },

    /**
     * Wait for a condition to hold.
     *
     * The prompt hook ingests in the background — a missing CLI must never
     * delay a prompt — so a test that reads the store straight after firing
     * the hook is racing. Poll instead of guessing.
     */
    async waitFor(check, { timeout = 10000, step = 25 } = {}) {
      const started = Date.now()
      while (Date.now() - started < timeout) {
        if (await check()) return true
        await new Promise((r) => setTimeout(r, step))
      }
      return false
    },

    /** Restore the environment and delete the temp store. */
    cleanup() {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
      if (!keepHome) rmSync(home, { recursive: true, force: true })
    },
  }

  return harness
}
