#!/usr/bin/env node
/**
 * Zero-dependency launcher & cross-platform setup entrypoint for `npx xt-forge`.
 * Works on Windows, Linux, and macOS.
 *
 * Examples:
 *   npx xt-forge --meta               Launch sub-1KB MCP gateway (stdio)
 *   npx xt-forge init                 Install CLI on PATH, copy XTF-* skills, configure harnesses
 *   npx xt-forge skills               List the 3-tier XTF-* skill catalog
 *   npx xt-forge prompt-install       Print agent self-install prompts (Windows/Linux/macOS)
 *   npx xt-forge <noun> <verb> ...    Forward directly to native Rust/Go/Python workbench
 */
import { spawnSync } from "node:child_process"
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs"
import { homedir } from "node:os"
import { delimiter, dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, "..")
const IS_WIN = process.platform === "win32"
const IS_MAC = process.platform === "darwin"
const HOME = IS_WIN ? process.env.USERPROFILE || homedir() : process.env.HOME || homedir()

function resolveRunner() {
  const rsName = IS_WIN ? "xtforge-native.exe" : "xtforge-native"
  const rsBin = join(ROOT, "native", "xtforge-rs", "target", "release", rsName)
  if (process.env.XT_FORCE_PYTHON !== "1" && existsSync(rsBin)) {
    return { cmd: rsBin, prefixArgs: [], engine: "rust+go", needsShell: false }
  }
  const wrapper = join(ROOT, "bin", IS_WIN ? "xtforge.cmd" : "xtforge")
  if (existsSync(wrapper)) {
    return { cmd: wrapper, prefixArgs: [], engine: "cli", needsShell: IS_WIN }
  }
  const py = process.env.XT_PYTHON || (IS_WIN ? "python" : "python3")
  return { cmd: py, prefixArgs: ["-m", "xtforge.cli"], engine: "python", needsShell: false }
}

function copyDir(src, dst) {
  if (!existsSync(src)) return 0
  mkdirSync(dst, { recursive: true })
  let count = 0
  for (const tier of ["simple", "complex", "advanced"]) {
    const tierDir = join(src, tier)
    if (!existsSync(tierDir)) continue
    for (const skillName of readdirSync(tierDir)) {
      const skillSrc = join(tierDir, skillName)
      const skillFile = join(skillSrc, "SKILL.md")
      if (!existsSync(skillFile)) continue
      const skillDst = join(dst, skillName)
      cpSync(skillSrc, skillDst, { recursive: true, force: true })
      count += 1
    }
  }
  return count
}

function installShim(targetDir, name, sourcePath) {
  mkdirSync(targetDir, { recursive: true })
  if (IS_WIN) {
    const dest = join(targetDir, `${name}.cmd`)
    writeFileSync(dest, `@echo off\r\n"${sourcePath}" %*\r\n`, "ascii")
    return dest
  }
  const dest = join(targetDir, name)
  try {
    unlinkSync(dest)
  } catch {
    // ignore if missing
  }
  symlinkSync(sourcePath, dest)
  return dest
}

function cmdSkills() {
  const indexPath = join(ROOT, "skills", "index.json")
  if (!existsSync(indexPath)) {
    console.error("skills/index.json not found in package")
    process.exit(1)
  }
  const idx = JSON.parse(readFileSync(indexPath, "utf8"))
  console.log(`XT-Forge Skills Library (${idx.skills.length} workflow skills across 3 tiers)\n`)
  for (const tier of ["simple", "complex", "advanced"]) {
    const items = idx.skills.filter((s) => s.tier === tier)
    console.log(`[${tier.toUpperCase()}] (${items.length})`)
    for (const s of items) {
      console.log(`  ${s.name.padEnd(20)} ${s.summary}`)
    }
    console.log("")
  }
  console.log("Install all skills locally via: xt-forge init (or npx xt-forge init)")
}

function cmdPromptInstall() {
  const promptPath = join(ROOT, "prompts", "install.md")
  if (!existsSync(promptPath)) {
    console.error("prompts/install.md not found in package")
    process.exit(1)
  }
  process.stdout.write(readFileSync(promptPath, "utf8"))
}

function cmdInit(argv) {
  const args = new Set(argv)
  const localBin = join(HOME, ".local", "bin")
  const launcher = join(ROOT, "bin", IS_WIN ? "xtforge.cmd" : "xtforge")
  if (!IS_WIN) {
    try {
      chmodSync(launcher, 0o755)
    } catch {
      // ignore if packaged read-only
    }
  }

  const binPath = installShim(localBin, "xt-forge", launcher)
  const aliasPath = installShim(localBin, "xtforge", launcher)
  const shortAlias = installShim(localBin, "xtf", launcher)

  const skillsSrc = join(ROOT, "skills")
  const skillTargets = [
    join(HOME, ".agents", "skills"),
    join(HOME, ".dsh", "skills"),
    join(HOME, ".config", "opencode", "skills"),
    join(HOME, ".claude", "skills"),
  ]
  const installedCounts = {}
  for (const dst of skillTargets) {
    installedCounts[dst] = copyDir(skillsSrc, dst)
  }

  const dshCmdDir = join(HOME, ".dsh", "commands")
  mkdirSync(dshCmdDir, { recursive: true })
  writeFileSync(
    join(dshCmdDir, "xtf.md"),
    "---\ndescription: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve, /xtf code graph)\n---\n" +
      "Execute `xt-forge $ARGUMENTS` cleanly. If `$ARGUMENTS` is `--meta`, configure or inspect the sub-1KB MCP gateway (`xt-forge --meta`).\n",
  )

  const claudeCmdDir = join(HOME, ".claude", "commands")
  mkdirSync(claudeCmdDir, { recursive: true })
  writeFileSync(
    join(claudeCmdDir, "xtf.md"),
    "---\ndescription: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve)\n---\n" +
      "Run `xt-forge $ARGUMENTS` and present crisp findings.\n",
  )

  const ocPluginDst = join(HOME, ".config", "opencode", "plugins", "xt-native")
  if (existsSync(ocPluginDst)) {
    const runner = resolveRunner()
    spawnSync(runner.cmd, [...runner.prefixArgs, "plugin", "install"], {
      stdio: "ignore",
      shell: runner.needsShell,
    })
  }

  console.log("XT-Forge initialized successfully:\n")
  console.log(`  Platform         : ${process.platform} (${process.arch})`)
  console.log(`  Commands on PATH : ${binPath}, ${aliasPath}, ${shortAlias}`)
  console.log(`  Gateway command  : xt-forge --meta`)
  console.log(`  Slash commands   : /xtf (~/.dsh/commands/xtf.md, ~/.claude/commands/xtf.md)`)
  console.log(`  Skills installed : ${installedCounts[join(HOME, ".agents", "skills")]} XTF-* workflow skills synced to:`)
  for (const [dir, n] of Object.entries(installedCounts)) {
    console.log(`    - ${dir} (${n} skills)`)
  }
  const pathEnv = (process.env.PATH || "").split(delimiter)
  if (!pathEnv.includes(localBin)) {
    if (IS_WIN) {
      console.log(`\n  Add ${localBin} to User PATH cleanly in PowerShell:\n    setx PATH "$env:USERPROFILE\\.local\\bin;$env:PATH"`)
    } else if (IS_MAC) {
      console.log(`\n  Add ${localBin} to PATH in ~/.zshrc:\n    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc`)
    } else {
      console.log(`\n  Add ${localBin} to PATH in ~/.bashrc:\n    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc`)
    }
  }
  if (!args.has("--quiet")) {
    console.log("\n  Quick check:\n    xt-forge doctor\n    xt-forge --meta\n")
  }
}

const rawArgs = process.argv.slice(2)
if (rawArgs[0] === "init") {
  cmdInit(rawArgs.slice(1))
  process.exit(0)
}
if (rawArgs[0] === "skills" && rawArgs.length === 1) {
  cmdSkills()
  process.exit(0)
}
if (rawArgs[0] === "prompt-install" || (rawArgs[0] === "prompt" && rawArgs[1] === "install")) {
  cmdPromptInstall()
  process.exit(0)
}

const { cmd, prefixArgs, needsShell } = resolveRunner()
const finalArgs = [...prefixArgs, ...rawArgs]
const childEnv = { ...process.env }
if (!childEnv.XT_HOME) {
  childEnv.XT_HOME = join(HOME, ".xt-forge")
}
if (!childEnv.PYTHONPATH) {
  childEnv.PYTHONPATH = ROOT
} else if (!childEnv.PYTHONPATH.split(delimiter).includes(ROOT)) {
  childEnv.PYTHONPATH = `${ROOT}${delimiter}${childEnv.PYTHONPATH}`
}
const child = spawnSync(cmd, finalArgs, {
  cwd: rawArgs[0] === "--meta" || rawArgs[0] === "mcp" ? ROOT : process.cwd(),
  env: childEnv,
  stdio: "inherit",
  shell: needsShell,
})
process.exit(child.status ?? 1)
