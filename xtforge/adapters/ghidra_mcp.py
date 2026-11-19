"""Ghidra & REA-Replacement MCP Server (`python3 -m xtforge.adapters.ghidra_mcp`).

Provides a 32-tool stdio MCP server compatible with LaurieWired/GhidraMCP,
pyghidra-mcp, and REA (`rea-agents`) binary analysis workflows.

Tiered Multi-Engine Execution:
1. Live Ghidra GUI HTTP Bridge (`GHIDRA_MCP_URL`, default `http://127.0.0.1:8080/`)
   when Ghidra CodeBrowser is running with GhidraMCP plugin enabled.
2. Headless Ghidra (`analyzeHeadless` via `GHIDRA_INSTALL_DIR` / `GHIDRA_HOME` / PATH)
   with automatic `JAVA_HOME` detection and SHA-256 project caching.
3. Instant Native Decompiler & Binary Engine (`borer` + `xt-forge` ELF/PE/Mach-O +
   `.rodata` string & reciprocal-division math annotator + persistent SHA-256
   `$XT_HOME/re_overlay.db` for function/variable/data renames, C prototypes,
   and decompiler/disassembly comments).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..atomicio import atomic_write_json, read_json
from ..core.re import analysis as re_analysis
from ..core.re import annotate as re_annotate
from ..core.re import capa as re_capa
from ..core.re import diff as re_diff
from ..core.re import elf as re_elf
from ..core.re import native as re_native
from ..core.re import pe as re_pe
from ..core.re import rtti as re_rtti
from ..core.re import runtimes as re_runtimes
from ..core.re import sober_re
from ..version import xt_home


def _session_cache_path() -> Path:
    return xt_home() / "cache" / "ghidra-session.json"


def _var_overlay_path() -> Path:
    return xt_home() / "cache" / "ghidra-var-overlay.json"


def _load_var_overlay() -> dict[str, Any]:
    data = read_json(_var_overlay_path())
    return data if isinstance(data, dict) else {}


def _save_var_overlay(data: dict[str, Any]) -> None:
    atomic_write_json(_var_overlay_path(), data)


def _find_borer() -> str | None:
    env_cmd = os.environ.get("BORER_CMD", "").strip()
    if env_cmd and os.path.isfile(env_cmd):
        return env_cmd
    found = shutil.which("borer")
    if found:
        return found
    home = Path.home()
    for cand in (home / ".local" / "bin" / "borer", home / ".cargo" / "bin" / "borer"):
        if cand.is_file():
            return str(cand)
    return None


def _find_analyze_headless() -> str | None:
    for env_key in ("GHIDRA_HEADLESS", "GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        val = os.environ.get(env_key, "").strip()
        if not val:
            continue
        p = Path(val)
        if p.is_file():
            return str(p)
        cand = p / "support" / "analyzeHeadless"
        if cand.is_file():
            return str(cand)
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    home = Path.home()
    search_roots = [Path("/opt"), Path("/usr/share"), home / "tools", home / ".cache" / "rea-tools"]
    for root in search_roots:
        if not root.is_dir():
            continue
        for match in sorted(root.glob("ghidra*/support/analyzeHeadless"), reverse=True):
            if match.is_file():
                return str(match)
    return None


def _find_java_home() -> str | None:
    jh = os.environ.get("JAVA_HOME", "").strip()
    if jh and Path(jh).is_dir():
        return jh
    home = Path.home()
    for match in sorted((home / "tools").glob("jdk-*"), reverse=True) if (home / "tools").is_dir() else []:
        if (match / "bin" / "java").is_file():
            return str(match)
    return None


def _ghidra_http_url() -> str:
    return os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8080").rstrip("/")


def _probe_ghidra_http() -> bool:
    if os.environ.get("XT_GHIDRA_HTTP", "0") != "1" and not os.environ.get("GHIDRA_MCP_URL"):
        return False
    try:
        req = urllib.request.Request(f"{_ghidra_http_url()}/methods?offset=0&limit=1", method="GET")
        with urllib.request.urlopen(req, timeout=0.6) as resp:
            return resp.status == 200
    except Exception:
        return False


def _http_get(endpoint: str, params: dict[str, Any] | None = None) -> str | None:
    if not _probe_ghidra_http():
        return None
    qs = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{_ghidra_http_url()}/{endpoint.lstrip('/')}{qs}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _http_post(endpoint: str, data: dict[str, Any] | str) -> str | None:
    if not _probe_ghidra_http():
        return None
    url = f"{_ghidra_http_url()}/{endpoint.lstrip('/')}"
    body = data.encode("utf-8") if isinstance(data, str) else urllib.parse.urlencode(data).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=body, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


class GhidraSessionState:
    """Persistent binary analysis state for the Ghidra MCP server."""

    def __init__(self) -> None:
        self.active_binary: str = ""
        self.current_function: str = "main"
        self.borer_bin: str | None = _find_borer()
        self.headless_bin: str | None = _find_analyze_headless()
        self.java_home: str | None = _find_java_home()
        cached = read_json(_session_cache_path())
        if isinstance(cached, dict):
            p = str(cached.get("path", "")).strip()
            if p and os.path.isfile(p):
                self.active_binary = p

    def set_binary(self, path: str) -> str:
        p = str(Path(path).expanduser().resolve())
        if not os.path.isfile(p):
            raise FileNotFoundError(f"binary not found: {path}")
        self.active_binary = p
        atomic_write_json(_session_cache_path(), {"path": p})
        return p

    def resolve_binary(self, args: dict[str, Any]) -> str:
        raw = str(args.get("path") or args.get("binary") or "").strip()
        if raw:
            return self.set_binary(raw)
        if self.active_binary and os.path.isfile(self.active_binary):
            return self.active_binary
        cached = read_json(_session_cache_path())
        if isinstance(cached, dict):
            p = str(cached.get("path", "")).strip()
            if p and os.path.isfile(p):
                self.active_binary = p
                return p
        raise ValueError("no binary loaded; pass 'path' or call load_binary first")

    def run_borer_cli(self, *borer_args: str, timeout: int = 30) -> str | None:
        if not self.borer_bin:
            return None
        try:
            proc = subprocess.run(
                [self.borer_bin, *borer_args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass
        return None


STATE = GhidraSessionState()


def _parse_addr_int(raw: str | int | None) -> int:
    if raw is None:
        return 0
    if isinstance(raw, int):
        return raw
    s = str(raw).strip().lower()
    if s.startswith("sub_"):
        s = "0x" + s[4:]
    try:
        return int(s, 16) if s.startswith("0x") else int(s, 16 if all(c in "0123456789abcdef" for c in s) and s else 10)
    except ValueError:
        return 0


def _apply_overlay_to_pseudocode(bin_path: str, target: str, code: str, raw_target: str = "") -> tuple[str, dict[str, Any]]:
    """Apply function renames, variable renames, C prototypes, and comments from re_overlay.db."""
    ov = re_annotate.overlay_map_for_binary(bin_path)
    _, sha, _, _ = re_annotate.binary_sha256(bin_path)
    var_db = _load_var_overlay().get(sha, {})
    protos = var_db.get("prototypes", {})
    var_renames = var_db.get("variables", {})
    decompiler_comments = var_db.get("decompiler_comments", {})

    updated = code
    applied: dict[str, Any] = {"renames": {}, "variables": {}, "comments": [], "prototype": None}

    candidate_keys: set[str] = set()
    for t in (target, raw_target):
        if not t:
            continue
        candidate_keys.add(t)
        bare = t.removeprefix("0x").removeprefix("sub_")
        candidate_keys.add(bare)
        candidate_keys.add(f"0x{bare}")
        candidate_keys.add(f"sub_{bare}")
        ai = _parse_addr_int(t)
        if ai > 0:
            hx = hex(ai).lower()
            candidate_keys.add(hx)
            candidate_keys.add(f"sub_{hx.removeprefix('0x')}")

    # 1. Apply function renames across the pseudocode
    for orig_name, new_name in ov.get("renames_by_orig", {}).items():
        if orig_name and new_name and orig_name in updated:
            updated = re.sub(rf"\b{re.escape(orig_name)}\b", new_name, updated)
            applied["renames"][orig_name] = new_name
            candidate_keys.add(new_name)
    for rva_hex, new_name in ov.get("renames_by_rva", {}).items():
        sub_name = f"sub_{rva_hex.removeprefix('0x')}"
        if sub_name in updated:
            updated = re.sub(rf"\b{re.escape(sub_name)}\b", new_name, updated)
            applied["renames"][sub_name] = new_name
            candidate_keys.add(new_name)

    # 2. Apply variable renames for this function
    for fn_key, mapping in var_renames.items():
        if fn_key in candidate_keys or fn_key in applied["renames"].values():
            if isinstance(mapping, dict):
                for old_v, new_v in mapping.items():
                    updated = re.sub(rf"\b{re.escape(old_v)}\b", new_v, updated)
                    applied["variables"][old_v] = new_v

    # 3. Apply prototype override if set
    for proto_key, proto_val in protos.items():
        if proto_key in candidate_keys or proto_key in applied["renames"].values():
            applied["prototype"] = proto_val
            if "// signature:" in updated:
                updated = re.sub(r"// signature:.*", f"// signature: {proto_val}", updated, count=1)
            else:
                updated = f"// signature: {proto_val}\n" + updated

    # 4. Prepend decompiler & overlay comments
    comments: list[str] = []
    seen_comments: set[str] = set()
    for t in (raw_target, target):
        if not t:
            continue
        addr_int = _parse_addr_int(t)
        if addr_int > 0:
            hx = hex(addr_int).lower()
            c_txt = decompiler_comments.get(hx) or ov.get("comments_by_rva", {}).get(hx)
            if c_txt and c_txt not in seen_comments:
                seen_comments.add(c_txt)
                comments.append(f"// [comment @ {hx}] {c_txt}")
        if t in decompiler_comments and decompiler_comments[t] not in seen_comments:
            seen_comments.add(decompiler_comments[t])
            comments.append(f"// [comment @ {t}] {decompiler_comments[t]}")
    if comments:
        applied["comments"] = comments
        updated = "\n".join(comments) + "\n" + updated

    return updated, applied


def _resolve_target_symbol_from_overlay(bin_path: str, requested: str) -> str:
    """If the user asks to decompile a renamed function ('ls_entrypoint'), map it back to original symbol/RVA."""
    ov = re_annotate.overlay_map_for_binary(bin_path)
    for orig_name, new_name in ov.get("renames_by_orig", {}).items():
        if new_name == requested and orig_name:
            return orig_name
    for rva_hex, new_name in ov.get("renames_by_rva", {}).items():
        if new_name == requested:
            return rva_hex
    return requested


def _extract_functions(bin_path: str, flt: str = "", offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
    ov = re_annotate.overlay_map_for_binary(bin_path)
    rows: list[dict[str, Any]] = []
    borer_out = STATE.run_borer_cli("functions", bin_path, flt or "", str(offset), str(min(limit, 300)))
    if borer_out:
        for line in borer_out.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("entry"):
                continue
            parts = line.split()
            if len(parts) >= 7 and parts[0].startswith("0x"):
                addr = parts[0].lower()
                orig_name = parts[-1]
                display_name = ov["renames_by_orig"].get(orig_name) or ov["renames_by_rva"].get(addr) or orig_name
                rows.append({
                    "address": addr,
                    "size": int(parts[1]) if parts[1].isdigit() else parts[1],
                    "blocks": int(parts[2]) if parts[2].isdigit() else parts[2],
                    "instructions": int(parts[3]) if parts[3].isdigit() else parts[3],
                    "callers": int(parts[4]) if parts[4].isdigit() else parts[4],
                    "callees": int(parts[5]) if parts[5].isdigit() else parts[5],
                    "name": display_name,
                    "original_name": orig_name,
                })
    if not rows:
        syms = re_elf.symbols(bin_path, limit=max(limit + offset, 200))
        for s in syms.get("symbols", []):
            if s.get("type") in ("FUNC", "GLOBAL", "LOCAL", "WEAK") or s.get("name"):
                orig_name = s.get("name", "")
                addr_raw = s.get("address") or s.get("value") or "0x0"
                addr = hex(addr_raw) if isinstance(addr_raw, int) else str(addr_raw)
                display_name = ov["renames_by_orig"].get(orig_name) or ov["renames_by_rva"].get(addr.lower()) or orig_name
                if flt and flt.lower() not in display_name.lower() and flt.lower() not in orig_name.lower():
                    continue
                rows.append({
                    "address": addr,
                    "size": s.get("size", 0),
                    "name": display_name,
                    "original_name": orig_name,
                })
        rows = rows[offset:offset + limit]
    return rows


def _decompile_target(bin_path: str, target: str) -> dict[str, Any]:
    STATE.current_function = target
    http_res = _http_post("decompile", target) or _http_get("decompile_function", {"name": target})
    if http_res and http_res.strip():
        code, applied = _apply_overlay_to_pseudocode(bin_path, target, http_res)
        return {
            "ok": True,
            "engine": "ghidra_gui_http",
            "path": bin_path,
            "target": target,
            "pseudocode": code,
            "overlay": applied,
        }

    raw_target = _resolve_target_symbol_from_overlay(bin_path, target)
    borer_code = STATE.run_borer_cli("decompile", bin_path, raw_target, "full", "0", "300")
    # Also gather annotated objdump notes (.rodata strings & reciprocal division math)
    disasm_notes: list[str] = []
    rodata_hits: list[str] = []
    try:
        fn_map = re_diff._disassemble_functions(Path(bin_path))
        rodata_map = re_diff._extract_rodata_strings(Path(bin_path))
        fn_lines = fn_map.get(raw_target) or fn_map.get(target) or []
        if fn_lines:
            annotated = re_diff._annotate_disasm_with_strings(fn_lines, rodata_map)
            for ln in annotated:
                if "; str:" in ln:
                    rodata_hits.append(ln.split("; str:", 1)[1].strip())
            for c in re_diff._extract_strength_reduced_divs(fn_lines):
                if c.get("approx_divisor"):
                    disasm_notes.append(
                        f"imul {c['magic_hex']} + shift {c['shift']} => signed division by ~{c['approx_divisor']} ({c['approx_percent']}%)"
                    )
    except Exception:
        pass

    if borer_code:
        code, applied = _apply_overlay_to_pseudocode(bin_path, target, borer_code, raw_target=raw_target)
        if disasm_notes:
            code = "// [math-notes] " + " | ".join(disasm_notes) + "\n" + code
        return {
            "ok": True,
            "engine": "ghidra_borer_lifter",
            "path": bin_path,
            "target": target,
            "resolved_target": raw_target,
            "pseudocode": code,
            "math_notes": disasm_notes,
            "rodata_strings": rodata_hits,
            "overlay": applied,
        }

    # Fallback to xt-forge runtime decompile / annotated objdump
    fallback = re_native.disasm(bin_path, symbol=raw_target)
    raw_text = fallback.get("disassembly") or fallback.get("output") or ""
    code, applied = _apply_overlay_to_pseudocode(bin_path, target, raw_text)
    return {
        "ok": bool(raw_text),
        "engine": "xtforge_annotated_disasm",
        "path": bin_path,
        "target": target,
        "pseudocode": code,
        "math_notes": disasm_notes,
        "rodata_strings": rodata_hits,
        "overlay": applied,
    }


TOOLS: list[dict[str, Any]] = [
    {
        "name": "load_binary",
        "description": "Load an ELF, PE, or Mach-O binary into the active Ghidra MCP session and return format, architecture, entry point, and section summary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or workspace path to the binary."},
                "project": {"type": "string", "description": "Optional Ghidra project name."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "open_binary",
        "description": "Open a binary for analysis (REA & GhidraMCP compatible) and return overview metadata, mitigations, and section entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to binary file."}},
            "required": ["path"],
        },
    },
    {
        "name": "binary_overview",
        "description": "Inspect architecture, sections, Shannon entropy, exploit mitigations (checksec), and behavioral capabilities (capa).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Optional binary path (uses active session binary if omitted)."}},
        },
    },
    {
        "name": "decompile_function",
        "description": "Decompile a function by name or hex address into structured C pseudocode with applied renames, prototypes, comments, .rodata strings, and reciprocal math notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Function symbol name or hex address (e.g. 'main' or '0x5620')."},
                "address": {"type": "string", "description": "Function entry address (e.g. '0x5620')."},
                "path": {"type": "string", "description": "Optional path to binary (auto-loads if provided)."},
            },
        },
    },
    {
        "name": "decompile_function_by_name",
        "description": "Decompile a function by symbol name (GhidraMCP compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Function name to decompile."},
                "path": {"type": "string", "description": "Optional binary path."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "decompile_function_by_address",
        "description": "Decompile a function at the given hex address (GhidraMCP compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Hex address (e.g. '0x5620')."},
                "path": {"type": "string", "description": "Optional binary path."},
            },
            "required": ["address"],
        },
    },
    {
        "name": "procedure_pseudo_code",
        "description": "Recover decompiled C pseudocode for a procedure (REA-compatible alias for decompile_function).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Procedure name or address."},
                "address": {"type": "string", "description": "Procedure hex address."},
                "path": {"type": "string", "description": "Optional binary path."},
            },
        },
    },
    {
        "name": "disassemble_function",
        "description": "Disassemble a function by name or address with basic-block labels, resolved .rodata string literals, and reciprocal division math annotations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Function name or address."},
                "address": {"type": "string", "description": "Function hex address."},
                "path": {"type": "string", "description": "Optional binary path."},
            },
        },
    },
    {
        "name": "procedure_disassembly",
        "description": "Disassemble a procedure with inline string and constant annotations (REA-compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "address": {"type": "string"},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_functions",
        "description": "List discovered functions with entry address, size, basic block count, callers, callees, and applied overlay renames.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "filter": {"type": "string", "description": "Optional case-insensitive name filter."},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_methods",
        "description": "List all methods/functions in the program with pagination (GhidraMCP compatible).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "filter": {"type": "string"},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "search_functions_by_name",
        "description": "Search functions by case-insensitive substring across both original and renamed symbols.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Substring to search for."},
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "path": {"type": "string"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_function_by_address",
        "description": "Get function boundaries, callers, callees, string references, and overlay metadata at an address or symbol.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address or name."},
                "path": {"type": "string"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "get_current_function",
        "description": "Return metadata and decompilation for the most recently inspected function in the active session.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
        },
    },
    {
        "name": "list_imports",
        "description": "List imported functions and shared library dependencies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "filter": {"type": "string"},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_exports",
        "description": "List exported functions and symbols.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "filter": {"type": "string"},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_segments",
        "description": "List memory segments and sections with virtual addresses, file offsets, permissions, and Shannon entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
        },
    },
    {
        "name": "list_strings",
        "description": "List printable ASCII and UTF-16LE strings with virtual addresses and optional substring filter.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 200},
                "filter": {"type": "string"},
                "min_length": {"type": "integer", "default": 5},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_classes",
        "description": "Recover C++ RTTI classes, vtables, and struct field layouts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_namespaces",
        "description": "List recovered C++/Rust/.NET namespaces and class roles.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "list_data_items",
        "description": "List defined global data symbols and renamed data items.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
                "filter": {"type": "string"},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "xrefs_to",
        "description": "Find cross-references TO a target address or symbol name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Target hex address or symbol name."},
                "name": {"type": "string", "description": "Target symbol name."},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "xrefs_from",
        "description": "Find cross-references FROM a function or address (callees and referenced strings/globals).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Source function address or symbol name."},
                "name": {"type": "string"},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "get_call_graph",
        "description": "Reconstruct function call graph (callers, callees, and basic-block CFG edges).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Function name or address."},
                "address": {"type": "string"},
                "callers": {"type": "boolean", "default": False},
                "path": {"type": "string"},
            },
        },
    },
    {
        "name": "rename_function",
        "description": "Rename a function persistently in the SHA-256 binary overlay (and live Ghidra bridge if connected).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "old_name": {"type": "string", "description": "Current function name (e.g. 'sub_5620')."},
                "new_name": {"type": "string", "description": "New function name (e.g. 'parse_packet_header')."},
                "address": {"type": "string", "description": "Optional function hex address."},
                "path": {"type": "string"},
            },
            "required": ["new_name"],
        },
    },
    {
        "name": "rename_function_by_address",
        "description": "Rename a function by its hex address persistently.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "function_address": {"type": "string", "description": "Hex address of function."},
                "new_name": {"type": "string", "description": "New function name."},
                "path": {"type": "string"},
            },
            "required": ["function_address", "new_name"],
        },
    },
    {
        "name": "rename_variable",
        "description": "Rename a local or parameter variable inside a function persistently across decompilations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name or address."},
                "old_name": {"type": "string", "description": "Existing variable identifier (e.g. 'a1' or 'local_18')."},
                "new_name": {"type": "string", "description": "New variable identifier (e.g. 'ctx_ptr')."},
                "path": {"type": "string"},
            },
            "required": ["function_name", "old_name", "new_name"],
        },
    },
    {
        "name": "rename_data",
        "description": "Rename a global data label at the specified hex address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Hex address of data item."},
                "new_name": {"type": "string", "description": "New symbol name."},
                "path": {"type": "string"},
            },
            "required": ["address", "new_name"],
        },
    },
    {
        "name": "set_decompiler_comment",
        "description": "Attach a persistent decompiler comment to a function or address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function name or hex address."},
                "comment": {"type": "string", "description": "Decompiler comment text."},
                "path": {"type": "string"},
            },
            "required": ["address", "comment"],
        },
    },
    {
        "name": "set_disassembly_comment",
        "description": "Attach a persistent disassembly EOL comment at an instruction address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Instruction hex address."},
                "comment": {"type": "string", "description": "Disassembly comment text."},
                "path": {"type": "string"},
            },
            "required": ["address", "comment"],
        },
    },
    {
        "name": "set_function_prototype",
        "description": "Set a persistent C function prototype/signature at an address or function name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "function_address": {"type": "string", "description": "Function hex address or name."},
                "prototype": {"type": "string", "description": "Full C function signature (e.g. 'int verify_token(const char *buf, size_t len)')."},
                "path": {"type": "string"},
            },
            "required": ["function_address", "prototype"],
        },
    },
    {
        "name": "engine_status",
        "description": "Report active Ghidra GUI HTTP bridge, Ghidra analyzeHeadless, Borer lifter, and SHA-256 overlay DB status.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "diff_binaries",
        "description": "Normalized structural binary diff between two ELF/PE/Mach-O binaries with .rodata string literal resolution and reciprocal division math diffing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "old_path": {"type": "string", "description": "Baseline binary path."},
                "new_path": {"type": "string", "description": "Modified binary path."},
            },
            "required": ["old_path", "new_path"],
        },
    },
    {
        "name": "unpack_asar",
        "description": "Inspect or filter files inside an Electron .asar archive without unpacking to disk (REA replacement).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to .asar archive."},
                "grep": {"type": "string", "description": "Optional filename substring filter."},
                "limit": {"type": "integer", "default": 200},
            },
            "required": ["path"],
        },
    },
    {
        "name": "inspect_apk",
        "description": "Inspect Android APK manifest, permissions, DEX bytecode entries, and native JNI .so libraries (REA replacement).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to .apk file."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "inspect_netcap",
        "description": "Triage HAR or Fiddler SAZ network captures with secret-header masking (REA replacement).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to .har or .saz file."},
                "reveal": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["path"],
        },
    },
    {
        "name": "analyze_javascript_application",
        "description": "Statically analyze a JavaScript/TypeScript/Electron bundle or .asar archive for IPC channels, API endpoints, routes, and embedded secrets (REA replacement).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to JS/TS file, directory, or .asar bundle."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "inspect_analysis_settings",
        "description": "Inspect active Ghidra + Borer + xt-forge RE engine capabilities, session state, and overlay paths (REA replacement).",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "inspect_elf_deep",
        "description": "Inspect sectionless ELFs (e_shnum=0 via PT_LOAD + PT_DYNAMIC without false 'packed' diagnosis) and Android Bionic ELFs (SHT_ANDROID_RELA APS2 packed relocations, safe post-.bss VMA, and 4-byte Bionic pthread_mutex_t ABI warnings).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to ELF binary (e.g. libloader.so or libroblox.so)."},
            },
        },
    },
    {
        "name": "resolve_string_anchors",
        "description": "Streaming RIP-relative lea string-anchor resolver for 100+ MB stripped ELFs: maps diagnostic strings to string VA, RIP-relative lea instruction sites, enclosing function entry prologue VA, and detects string-xref alias collisions without Ghidra OOM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to ELF binary."},
                "queries": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Exact or substring diagnostic literals to resolve.",
                },
                "max_sites_per_string": {"type": "integer", "default": 16},
            },
            "required": ["queries"],
        },
    },
    {
        "name": "slice_disasm_window",
        "description": "O(1) windowed disassembly (objdump --start-address/--stop-address) around a target virtual address with inline RIP-relative .rodata string resolution and power-of-two MiB constant decoding. Never runs whole-binary disassembly on 100+ MB binaries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to binary."},
                "address": {"type": "string", "description": "Center virtual address in hex (e.g. '0x36085e4')."},
                "before_bytes": {"type": "integer", "default": 64},
                "after_bytes": {"type": "integer", "default": 256},
            },
            "required": ["address"],
        },
    },
    {
        "name": "probe_live_process",
        "description": "Safe live process memory probe: tests process_vm_readv directly (even when /proc/pid/mem is EACCES and ptrace is EPERM), discovers /memfd: (deleted) ELF mappings, and parses smaps RSS to prevent 118 GB sparse-page zero-fill OOM kills.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target Linux process ID."},
            },
            "required": ["pid"],
        },
    },
    {
        "name": "inspect_rbxm_container",
        "description": "Inspect Roblox .rbxm/.rbxl binary model containers: parses INST/PROP/SIGN/HASH/SSTR chunks, flags chunks covered by SIGN Ed25519 records vs unsigned Luau Source bytecode, and locates 27-byte tagged Color3 constant triples.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to .rbxm or .rbxl container."},
            },
            "required": ["path"],
        },
    },
]


def _dispatch_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name in ("engine_status", "inspect_analysis_settings"):
        return {
            "ok": True,
            "server": "ghidra",
            "replaces": ["rea-agents", "LaurieWired/GhidraMCP", "pyghidra-mcp"],
            "active_binary": STATE.active_binary,
            "current_function": STATE.current_function,
            "tool_count": len(TOOLS),
            "backends": {
                "ghidra_gui_http": {"url": _ghidra_http_url(), "reachable": _probe_ghidra_http()},
                "ghidra_headless": {"binary": STATE.headless_bin, "java_home": STATE.java_home},
                "borer_lifter": {"binary": STATE.borer_bin, "available": bool(STATE.borer_bin)},
                "overlay_db": str(re_annotate.overlay_db_path()),
            },
        }

    if name == "diff_binaries":
        old_p = str(args.get("old_path") or args.get("a") or "").strip()
        new_p = str(args.get("new_path") or args.get("b") or "").strip()
        if not old_p or not new_p:
            return {"ok": False, "error": "diff_binaries requires old_path and new_path"}
        return re_diff.diff_binaries(old_p, new_p)

    if name == "unpack_asar":
        p = str(args.get("path") or "").strip()
        return re_runtimes.inspect_asar(p, grep=str(args.get("grep") or ""), limit=int(args.get("limit") or 200))

    if name == "inspect_apk":
        p = str(args.get("path") or "").strip()
        return re_runtimes.inspect_apk(p)

    if name == "inspect_netcap":
        p = str(args.get("path") or "").strip()
        return re_runtimes.inspect_netcap(p, reveal=bool(args.get("reveal", False)), limit=int(args.get("limit") or 100))

    if name == "analyze_javascript_application":
        p = Path(str(args.get("path") or "").strip()).expanduser().resolve()
        if not p.exists():
            return {"ok": False, "error": f"path not found: {p}"}
        if p.suffix.lower() == ".asar":
            return re_runtimes.inspect_asar(p, limit=250)
        files = [p] if p.is_file() else sorted(list(p.rglob("*.js")) + list(p.rglob("*.ts")))[:60]
        urls: set[str] = set()
        ipc_channels: set[str] = set()
        routes: set[str] = set()
        for f in files:
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for m in re.findall(r"https?://[^\s\"'`<>]+", txt):
                urls.add(m[:140])
            for m in re.findall(r"ipc(?:Main|Renderer)\.(?:handle|on|invoke|send)\(\s*['\"]([^'\"]+)['\"]", txt):
                ipc_channels.add(m)
            for m in re.findall(r"\.(?:get|post|put|delete|patch)\(\s*['\"](/[^'\"]*)['\"]", txt):
                routes.add(m)
        return {
            "ok": True,
            "path": str(p),
            "files_scanned": len(files),
            "urls": sorted(urls)[:80],
            "ipc_channels": sorted(ipc_channels)[:80],
            "routes": sorted(routes)[:80],
        }

    if name in ("load_binary", "open_binary", "binary_overview"):
        bin_path = STATE.resolve_binary(args)
        info = re_elf.info(bin_path)
        secs = re_elf.sections(bin_path)
        sec_mit = re_capa.checksec(bin_path)
        capa_res = re_capa.capa(bin_path)
        ov = re_annotate.overlay_map_for_binary(bin_path)
        deep_elf = sober_re.inspect_elf_deep(bin_path)
        return {
            "ok": True,
            "path": bin_path,
            "info": info,
            "sections": secs.get("sections", [])[:30],
            "checksec": sec_mit.get("mitigations", sec_mit),
            "capabilities": capa_res.get("capabilities", []),
            "overlay_annotations": ov.get("count", 0),
            "deep_elf": {
                "section_header_stripped_not_packed": deep_elf.get("section_header_stripped_not_packed", False),
                "is_android_bionic": deep_elf.get("is_android_bionic", False),
                "has_android_aps2_rela": deep_elf.get("has_android_aps2_rela", False),
                "safe_post_bss_vaddr": deep_elf.get("safe_post_bss_vaddr"),
                "warnings": deep_elf.get("warnings", []),
            } if deep_elf.get("ok") else {},
        }

    if name == "inspect_elf_deep":
        bin_path = STATE.resolve_binary(args)
        return sober_re.inspect_elf_deep(bin_path)

    if name == "resolve_string_anchors":
        bin_path = STATE.resolve_binary(args)
        raw_q = args.get("queries") or args.get("anchors") or []
        if isinstance(raw_q, str):
            raw_q = [raw_q]
        return sober_re.resolve_string_anchors(
            bin_path,
            [str(q) for q in raw_q if str(q).strip()],
        )

    if name == "slice_disasm_window":
        bin_path = STATE.resolve_binary(args)
        addr = str(args.get("address") or STATE.current_function or "0x0").strip()
        return sober_re.slice_disasm_window(
            bin_path,
            addr,
            before_bytes=int(args.get("before_bytes") if args.get("before_bytes") is not None else 64),
            after_bytes=int(args.get("after_bytes") if args.get("after_bytes") is not None else 256),
        )

    if name == "probe_live_process":
        pid = int(args.get("pid") or 0)
        if pid <= 0:
            return {"ok": False, "error": "probe_live_process requires positive integer pid"}
        return sober_re.probe_live_process(pid)

    if name == "inspect_rbxm_container":
        p = str(args.get("path") or "").strip()
        if not p:
            return {"ok": False, "error": "inspect_rbxm_container requires path"}
        return sober_re.inspect_rbxm_container(p)

    if name in ("decompile_function", "decompile_function_by_name", "decompile_function_by_address", "procedure_pseudo_code"):
        bin_path = STATE.resolve_binary(args)
        target = str(args.get("name") or args.get("address") or STATE.current_function or "main").strip()
        return _decompile_target(bin_path, target)

    if name in ("disassemble_function", "procedure_disassembly"):
        bin_path = STATE.resolve_binary(args)
        target = str(args.get("name") or args.get("address") or STATE.current_function or "main").strip()
        raw_target = _resolve_target_symbol_from_overlay(bin_path, target)
        borer_dis = STATE.run_borer_cli("disasmfn", bin_path, raw_target)
        if not borer_dis:
            res = re_native.disasm(bin_path, symbol=raw_target)
            borer_dis = res.get("disassembly") or res.get("output") or ""
        code, applied = _apply_overlay_to_pseudocode(bin_path, target, borer_dis, raw_target=raw_target)
        return {
            "ok": bool(code),
            "path": bin_path,
            "target": target,
            "disassembly": code,
            "overlay": applied,
        }

    if name in ("list_functions", "list_methods"):
        bin_path = STATE.resolve_binary(args)
        offset = int(args.get("offset") or 0)
        limit = int(args.get("limit") or 100)
        flt = str(args.get("filter") or "").strip()
        funcs = _extract_functions(bin_path, flt=flt, offset=offset, limit=limit)
        return {"ok": True, "path": bin_path, "count": len(funcs), "functions": funcs}

    if name == "search_functions_by_name":
        bin_path = STATE.resolve_binary(args)
        q = str(args.get("query") or "").strip()
        offset = int(args.get("offset") or 0)
        limit = int(args.get("limit") or 100)
        funcs = _extract_functions(bin_path, flt=q, offset=offset, limit=limit)
        return {"ok": True, "path": bin_path, "query": q, "count": len(funcs), "functions": funcs}

    if name in ("get_function_by_address", "get_current_function"):
        bin_path = STATE.resolve_binary(args)
        target = str(args.get("address") or args.get("name") or STATE.current_function or "main").strip()
        raw_target = _resolve_target_symbol_from_overlay(bin_path, target)
        summary = STATE.run_borer_cli("summary", bin_path, raw_target)
        fstrings = STATE.run_borer_cli("fstrings", bin_path, raw_target)
        ov = re_annotate.overlay_map_for_binary(bin_path)
        return {
            "ok": True,
            "path": bin_path,
            "target": target,
            "resolved_target": raw_target,
            "summary": summary or "",
            "strings": (fstrings or "").splitlines()[:50],
            "renamed_to": ov["renames_by_orig"].get(raw_target) or ov["renames_by_rva"].get(raw_target.lower()),
        }

    if name in ("list_imports", "list_exports", "list_data_items"):
        bin_path = STATE.resolve_binary(args)
        flt = str(args.get("filter") or "").strip()
        offset = int(args.get("offset") or 0)
        limit = int(args.get("limit") or 100)
        borer_out = STATE.run_borer_cli("symbols", bin_path, flt, str(offset), str(min(limit, 500)))
        items: list[dict[str, Any]] = []
        want_kind = "import" if name == "list_imports" else ("export" if name == "list_exports" else "data")
        if borer_out:
            for ln in borer_out.splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                parts = ln.split(None, 2)
                if len(parts) >= 3:
                    kind, addr, sym_name = parts[0].lower(), parts[1], parts[2]
                    if want_kind in kind or (name == "list_data_items" and kind in ("data", "local", "export")):
                        items.append({"kind": kind, "address": addr, "name": sym_name})
        if not items:
            raw_syms = re_elf.symbols(bin_path, limit=max(limit + offset, 200)).get("symbols", [])
            for s in raw_syms:
                if flt and flt.lower() not in str(s.get("name", "")).lower():
                    continue
                items.append(s)
            items = items[offset:offset + limit]
        return {"ok": True, "path": bin_path, "kind": want_kind, "count": len(items), "items": items}

    if name == "list_segments":
        bin_path = STATE.resolve_binary(args)
        secs = re_elf.sections(bin_path)
        return {"ok": True, "path": bin_path, "segments": secs.get("sections", [])}

    if name == "list_strings":
        bin_path = STATE.resolve_binary(args)
        flt = str(args.get("filter") or "").strip()
        offset = int(args.get("offset") or 0)
        limit = int(args.get("limit") or 200)
        min_len = int(args.get("min_length") or 5)
        strs = re_elf.strings(bin_path, min_len=min_len, limit=limit + offset)
        all_s = strs.get("strings", [])
        if flt:
            all_s = [s for s in all_s if flt.lower() in str(s).lower()]
        sliced = all_s[offset:offset + limit]
        return {"ok": True, "path": bin_path, "count": len(sliced), "strings": sliced}

    if name in ("list_classes", "list_namespaces"):
        bin_path = STATE.resolve_binary(args)
        rtti_res = re_rtti.extract_rtti(bin_path)
        map_out = STATE.run_borer_cli("map", bin_path) or ""
        return {
            "ok": True,
            "path": bin_path,
            "classes": rtti_res.get("classes", []),
            "vtables": rtti_res.get("vtables", []),
            "namespaces": map_out.splitlines()[:100] if map_out else [],
        }

    if name in ("xrefs_to", "xrefs_from", "get_call_graph"):
        bin_path = STATE.resolve_binary(args)
        target = str(args.get("address") or args.get("name") or STATE.current_function or "main").strip()
        raw_target = _resolve_target_symbol_from_overlay(bin_path, target)
        if name == "xrefs_to":
            xr = re_analysis.find_xrefs(bin_path, raw_target)
            return {"ok": True, "path": bin_path, "target": target, "xrefs_to": xr.get("xrefs", [])}
        cfg = re_analysis.build_cfg(bin_path, symbol=raw_target)
        summary = STATE.run_borer_cli("summary", bin_path, raw_target) or ""
        return {
            "ok": True,
            "path": bin_path,
            "target": target,
            "summary": summary,
            "cfg": cfg,
        }

    if name in ("rename_function", "rename_function_by_address", "rename_data"):
        bin_path = STATE.resolve_binary(args)
        old_name = str(args.get("old_name") or "").strip()
        addr_raw = str(args.get("function_address") or args.get("address") or "").strip()
        new_name = str(args.get("new_name") or "").strip()
        if not addr_raw and old_name.startswith(("0x", "sub_")):
            addr_raw = "0x" + old_name.removeprefix("0x").removeprefix("sub_")
        rva_int = _parse_addr_int(addr_raw)
        if _probe_ghidra_http():
            if addr_raw:
                _http_post("renameFunctionByAddress", {"function_address": addr_raw, "new_name": new_name})
            elif old_name:
                _http_post("renameFunction", {"oldName": old_name, "newName": new_name})
        res = re_annotate.annotate(
            action="rename",
            binary=bin_path,
            rva=rva_int,
            name=new_name,
            orig=old_name or (hex(rva_int) if rva_int else ""),
        )
        return {**res, "tool": name, "old_name": old_name, "new_name": new_name}

    if name == "rename_variable":
        bin_path = STATE.resolve_binary(args)
        fn_name = str(args.get("function_name") or STATE.current_function or "main").strip()
        old_v = str(args.get("old_name") or "").strip()
        new_v = str(args.get("new_name") or "").strip()
        _, sha, _, _ = re_annotate.binary_sha256(bin_path)
        db = _load_var_overlay()
        entry = db.setdefault(sha, {})
        fn_vars = entry.setdefault("variables", {}).setdefault(fn_name, {})
        fn_vars[old_v] = new_v
        _save_var_overlay(db)
        return {
            "ok": True,
            "action": "rename_variable",
            "sha256": sha,
            "function_name": fn_name,
            "old_name": old_v,
            "new_name": new_v,
        }

    if name in ("set_decompiler_comment", "set_disassembly_comment"):
        bin_path = STATE.resolve_binary(args)
        addr_raw = str(args.get("address") or STATE.current_function or "0x0").strip()
        comment = str(args.get("comment") or "").strip()
        rva_int = _parse_addr_int(addr_raw)
        _, sha, _, _ = re_annotate.binary_sha256(bin_path)
        db = _load_var_overlay()
        entry = db.setdefault(sha, {})
        c_map = entry.setdefault("decompiler_comments", {})
        c_map[hex(rva_int).lower() if rva_int else addr_raw] = comment
        _save_var_overlay(db)
        res = re_annotate.annotate(action="comment", binary=bin_path, rva=rva_int, comment=comment)
        return {**res, "tool": name, "address": addr_raw, "comment": comment}

    if name == "set_function_prototype":
        bin_path = STATE.resolve_binary(args)
        fn_addr = str(args.get("function_address") or args.get("name") or STATE.current_function).strip()
        proto = str(args.get("prototype") or "").strip()
        rva_int = _parse_addr_int(fn_addr)
        _, sha, _, _ = re_annotate.binary_sha256(bin_path)
        db = _load_var_overlay()
        entry = db.setdefault(sha, {})
        p_map = entry.setdefault("prototypes", {})
        p_map[hex(rva_int).lower() if rva_int else fn_addr] = proto
        _save_var_overlay(db)
        res = re_annotate.annotate(action="type", binary=bin_path, rva=rva_int, type_decl=proto)
        return {**res, "tool": name, "function_address": fn_addr, "prototype": proto}

    return {"ok": False, "error": f"unknown Ghidra MCP tool: {name}"}


_handle_tool = _dispatch_tool


def serve_stdio() -> int:
    """Run the stdio JSON-RPC 2.0 loop for xtforge.adapters.ghidra_mcp."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        mid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "xtforge-ghidra-mcp", "version": "0.4.5"},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method in ("notifications/initialized", "notifications/cancelled"):
            continue
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            tname = str(params.get("name") or "")
            targs = params.get("arguments") or {}
            try:
                payload = _dispatch_tool(tname, targs if isinstance(targs, dict) else {})
                is_err = not bool(payload.get("ok", True))
                res = {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "isError": is_err,
                }
            except Exception as exc:
                res = {
                    "content": [{"type": "text", "text": json.dumps({"ok": False, "error": str(exc)})}],
                    "isError": True,
                }
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
            sys.stdout.flush()
        elif mid is not None:
            sys.stdout.write(
                json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}) + "\n"
            )
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve_stdio())
