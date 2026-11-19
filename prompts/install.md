# Agent Self-Install Prompts for xt-forge

Give any coding agent (Claude Code, Codex CLI, OpenCode, DSH, Cursor, Windsurf, or a custom autonomous loop) one of the prompts below so it can install, compile native Rust/Go engines when available, sync all 24 `XTF-*` skills, wire `--meta` MCP, and verify its own setup without manual guidance.

---

## 1. Universal Autonomous Install Prompt (Windows, Linux, macOS)

Copy and paste this prompt directly to your agent:

> Install and configure `xt-forge` (`https://github.com/XtrComSu/xt-forge`) for this machine and current agent harness, then verify everything works end-to-end:
>
> 1. Detect the operating system (`uname -s` on Linux/macOS, `$env:OS` / PowerShell on Windows) and whether `node`, `cargo`, `go`, `git`, and `python3`/`python` are available.
> 2. Pick the cleanest install path:
>    - If Node.js is available and package install works, run `npx xt-forge@latest init`; otherwise:
>    - On **Linux or macOS**: clone `https://github.com/XtrComSu/xt-forge.git` (into `~/.xt-forge-src` if not already inside the repo) and run `./install.sh` (or `curl -fsSL https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.sh | bash`).
>    - On **Windows (PowerShell)**: clone `https://github.com/XtrComSu/xt-forge.git` and run `.\install.ps1` (or `irm https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.ps1 | iex`).
> 3. Confirm `xt-forge`, `xtf`, and `/xtf` slash commands plus the 24 `XTF-*` skills are installed (ensure `~/.local/bin` or `%USERPROFILE%\.local\bin` is on `PATH`).
> 4. If an MCP client config exists for the active harness (`.mcp.json`, `~/.claude.json`, `~/.config/opencode/opencode.json`, `~/.codex/config.toml`, or `~/.dsh/settings.json`), add or suggest the sub-1KB MCP server entry running `xt-forge --meta` (`0.90 KB` initial schema overhead).
> 5. Run this verification gate before finishing and report the exact observed outputs:
>    - `xt-forge version --json`
>    - `xt-forge doctor --json`
>    - Verify stdio MCP gateway `tools/list` via `xt-forge --meta` returns `xt_discover`, `xt_schema`, `xt_call`, and `xt_batch`.
>    - On OpenCode, also run `xt-forge plugin install` if `~/.config/opencode` exists.

---

## 2. Minimal MCP-Only Prompt (Fastest Setup, Node.js Required)

> Set up `xt-forge` via `npx` so we get global CLI commands, 24 `XTF-*` skills, `/xtf` slash integration, and the sub-1KB MCP gateway:
>
> 1. Run `npx xt-forge@latest init` (on Windows PowerShell make sure `%USERPROFILE%\.local\bin` is on User `PATH`; on macOS/Linux add `~/.local/bin` to `PATH` if needed).
> 2. Register `xt-forge` as an MCP server with command `npx` and args `["-y", "xt-forge", "--meta"]` (or command `xt-forge` and args `["--meta"]`).
> 3. Run `xt-forge version --json` and `xt-forge skills` and confirm all 24 `XTF-*` skills are synced cleanly.

---

## 3. Native Source + Python Wheel Install (Linux / macOS / Windows)

> Build `xt-forge` from source with full Rust (`xtforge-native`) and Go (`xtforge-hub`) native speedups:
>
> 1. Clone `https://github.com/XtrComSu/xt-forge.git` and `cd xt-forge`.
> 2. Run `./install.sh` (Linux/macOS) or `.\install.ps1` (Windows). Optionally run `pip install .` / `uv tool install .` if you only need the zero-dependency Python CLI.
> 3. Verify native dispatch works with `xt-forge intel sources --json` (`"engine": "go"` when Go hub is built) and `xt-forge scan secrets . --json` (`"engine": "rust"` when Rust binary is built).
> 4. Keep `XT_FORCE_PYTHON=1` available anytime as an instant fallback.

---

## Quick Verification Checklist for Agents

Agents can validate any installation in one command:

```sh
# Linux / macOS
xt-forge version --json && printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n' | xt-forge --meta
```

```powershell
# Windows (PowerShell)
xt-forge version --json
'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | xt-forge --meta
```
