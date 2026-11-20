---
name: XTF-IDABridge
description: Bridge live IDA Pro, idalib, headless idat64, .i64/.idb metadata, and Borer/Ghidra fallback through one MCP and CLI surface.
---

# XTF-IDABridge (Complex Tier)

**Quick start:** `xt-forge re ida status --json` | `python3 -m xtforge.adapters.ida_mcp`

Use IDA Pro tools seamlessly across live `ida-pro-mcp` HTTP sessions, headless `idat64`/`idalib`, `.i64`/`.idb` databases, and automatic offline `borer` + `ghidra` + SHA-256 overlay fallbacks.

## When to use
- Inspecting `.i64` / `.idb` databases and locating their companion binaries.
- Running `ida_decompile`, `ida_disasm`, `ida_functions`, `ida_xrefs`, `ida_structs`, or `ida_batch` (`idat64 -A -S...`) with zero-setup fallback when no IDA GUI is open.

## Workflow
1. Check available RE backends:
   ```sh
   xt-forge re ida status --json
   ```
2. Inspect `.i64`/`.idb` metadata or decompile/list functions:
   ```sh
   xt-forge re ida info path/to/target.i64 --json
   xt-forge re ida decompile path/to/binary --symbol 0x401200 --json
   ```
3. Or via `--meta` (`xt_call`):
   ```json
   {"name": "re_ida", "arguments": {"subcommand": "decompile", "path": "path/to/binary", "symbol": "0x401200"}}
   ```

## Guardrails
- Never fail solely because `idat64` or `ida-pro-mcp` is offline; `xt-forge` automatically falls back to `borer` + `ghidra` + persistent SHA-256 overlays.
- Keep binary patch writes gated behind explicit confirmation tokens.
