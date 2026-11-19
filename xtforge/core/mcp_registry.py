"""MCP Tool Registry & On-Demand Dispatcher.

Enables zero-bloat discovery and execution of external stdio MCP servers
(including REA, Craft Anything, cad3d/OpenSCAD, photoeditor, glmocr, searchd,
and user-defined servers in $XT_HOME/mcp_upstreams.json) with full MCP
initialize + notifications/initialized handshakes and cached catalogs.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ..atomicio import atomic_write_json, read_json
from ..version import xt_home

_SHARE_ROOT = Path.home() / ".local" / "share"

EXTERNAL_SERVERS: dict[str, dict[str, Any]] = {
    "rea": {
        "title": "REA — Reverse Engineering Agent MCP",
        "description": "229+ tools for native binaries, Electron/JS, .NET, websites, Frida, Ghidra, and Hopper.",
        "command": "rea-agents",
        "args": ["mcp"],
        "aliases": ["rea", "rea-agents", "re-mcp", "rea_mcp", "hopper", "ghidra", "ida", "reverse"],
        "tools": [
            {"name": "open_binary", "description": "Open a local binary, archive, Electron ASAR, or JS file for analysis."},
            {"name": "binary_overview", "description": "Inspect architecture, sections, symbols, and format metadata."},
            {"name": "procedure_pseudo_code", "description": "Recover decompiled pseudocode for a procedure."},
            {"name": "analyze_javascript_application", "description": "Inspect JS/Electron bundles, routes, and secrets statically."},
            {"name": "inspect_analysis_settings", "description": "Inspect editable REA runtime admission limits and timeouts."},
        ],
    },
    "craft-anything": {
        "title": "Craft Anything — Pure-Rust Clean-Room & Deep RE MCP",
        "description": "300+ tools across native ELF/PE/Mach-O, WebAssembly, Android, Apple, web capture, and rebuild workflows.",
        "command": "craft-anything-cli",
        "args": ["mcp", "--all-tools"],
        "aliases": ["craft", "craft-anything", "craftanything", "craft-anything-cli", "craft_anything", "cleanroom", "rebuild"],
        "tools": [
            {"name": "core_target_open", "description": "Open a binary, app bundle, archive, or website URL in Craft Anything."},
            {"name": "list_toolsets", "description": "List available specialty toolsets (native, android, apple, web, wasm...)."},
            {"name": "enable_toolset", "description": "Enable a Craft Anything toolset dynamically when --all-tools is off."},
            {"name": "core_investigation_show", "description": "Inspect active project brief, evidence, findings, and unknowns."},
            {"name": "core_evidence_browse", "description": "Page through retained evidence records without blowing context budgets."},
        ],
    },
    "borer": {
        "title": "Borer — Pure-Rust Decompiler, Emulator & Certified Binary Analysis MCP",
        "description": "34 MCP tools + 111 borer:// resources for certified x86/x64/arm64/RISC-V decompilation, function emulation, symbolic solve, devirtualization, unpacking, and protocol recovery.",
        "command": "borer",
        "args": [],
        "aliases": ["borer", "borer-mcp", "borer-cli", "borer_mcp", "certify", "emulate", "devirt", "taint"],
        "tools": [
            {"name": "load_binary", "description": "Load a PE, ELF, Mach-O, or raw memory dump as the active session binary."},
            {"name": "decompile", "description": "Decompile a function to pseudo-C with binary-vs-lift verification annotations."},
            {"name": "function_summary", "description": "One-call function triage: shape, loops, jump tables, callers, callees, strings, and constants."},
            {"name": "query", "description": "Read any borer:// resource (borer://triage, borer://emulate/<addr>, borer://solve/<spec>, borer://taint/<spec>, borer://devirt/<addr>, borer://unpack/<addr>, borer://capabilities, borer://antianalysis, borer://stackstrings)."},
            {"name": "class_layout", "description": "Infer C++ class fields, methods, and vftable layout from member accesses."},
            {"name": "find_crypto_constants", "description": "Find AES, SHA, MD5, CRC-32, ChaCha, Blowfish, FNV, Base64, and hashed API constants."},
        ],
    },
    "cad3d": {
        "title": "3D CAD & OpenSCAD Modeling",
        "description": "3D CAD modeling, OpenSCAD script compilation, CSG booleans, extrusion, mesh inspection, and STL/OBJ/GLB/3MF conversions.",
        "command": str(_SHARE_ROOT / "mcp-cad-env" / "bin" / "python"),
        "args": [str(_SHARE_ROOT / "cad3d" / "cad3d_mcp.py")],
        "aliases": ["opencad", "cad", "3d", "openscad", "stl", "obj", "mesh", "trimesh", "csg", "modeling", "cad3d"],
        "tools": [
            {"name": "cad_generate_scad", "description": "Generate and compile parametric OpenSCAD scripts into STL/OBJ/3MF 3D meshes."},
            {"name": "cad_create_primitive", "description": "Create 3D solid primitive (cube, cylinder, sphere, cone, torus)."},
            {"name": "cad_csg_boolean", "description": "Perform manifold CSG boolean operations (union, difference, intersection)."},
            {"name": "cad_extrude_2d", "description": "Extrude 2D polyline or SVG profile into a 3D solid."},
            {"name": "cad_inspect_mesh", "description": "Inspect mesh watertightness, volume, surface area, and bounding box."},
            {"name": "cad_convert_format", "description": "Convert between 3D formats (STL, OBJ, GLB, PLY, 3MF)."},
            {"name": "cad_render_preview", "description": "Render 2D isometric/orthographic preview PNG/SVG of a 3D mesh."},
        ],
    },
    "photoeditor": {
        "title": "Photo & Image Manipulation",
        "description": "Photo editing, color grading, adjustments, filters, cropping, resizing, annotations, watermark compositing, and background removal.",
        "command": str(_SHARE_ROOT / "mcp-cad-env" / "bin" / "python"),
        "args": [str(_SHARE_ROOT / "photoeditor" / "photoeditor_mcp.py")],
        "aliases": ["photo", "image", "picture", "filter", "crop", "resize", "watermark", "background_removal", "photoeditor", "png", "jpeg"],
        "tools": [
            {"name": "photo_adjust", "description": "Color, brightness, contrast, saturation, and sharpness adjustments."},
            {"name": "photo_filter", "description": "Filters: blur, sharpen, edge enhance, emboss, sepia, grayscale, invert."},
            {"name": "photo_transform", "description": "Transformations: crop, resize, rotate, flip, transpose."},
            {"name": "photo_composite", "description": "Layer compositing: alpha blending, watermarking, positioning."},
            {"name": "photo_annotate", "description": "Text overlays and geometric annotations on images."},
            {"name": "photo_convert", "description": "Convert image formats (PNG, JPEG, WebP, GIF, BMP, TIFF)."},
            {"name": "photo_analyze", "description": "Image dimensions, color palette, EXIF metadata, histogram."},
            {"name": "photo_remove_background", "description": "Color-key / chroma-key transparency background extraction."},
        ],
    },
    "glmocr": {
        "title": "Local Document & Image OCR",
        "description": "Local high-precision OCR on images and PDFs for small text, tables, and formulas.",
        "command": sys.executable,
        "args": [str(_SHARE_ROOT / "glmocr" / "glmocr_mcp.py")],
        "aliases": ["ocr", "text_recognition", "scan_image", "glmocr", "read_image", "pdf_ocr"],
        "tools": [
            {"name": "ocr", "description": "Extract text, markdown, and tables from image or PDF file."},
        ],
    },
    "searchd": {
        "title": "Local Web & Google Search",
        "description": "Google organic web search endpoint via local searchd daemon.",
        "command": sys.executable,
        "args": [str(_SHARE_ROOT / "searchd" / "searchd_mcp.py")],
        "aliases": ["web", "google", "searchd", "web_search"],
        "tools": [
            {"name": "search", "description": "Search the web with real Google organic results."},
        ],
    },
}


def canonical_upstream_name(name: str) -> str:
    low = name.strip().lower()
    if low in ("rea", "rea-agents", "re-mcp", "rea_mcp"):
        return "rea"
    if low in ("craft", "craft-anything", "craftanything", "craft-anything-cli", "craft_anything"):
        return "craft-anything"
    if low in ("borer", "borer-mcp", "borer-cli", "borer_mcp"):
        return "borer"
    return name.strip()


def borer_session_path() -> Path:
    return xt_home() / "cache" / "borer-session.json"


def save_borer_session(bin_path: str) -> None:
    p = str(bin_path).strip()
    if p:
        atomic_write_json(borer_session_path(), {"path": p, "updated_at": int(time.time())})


def load_borer_session() -> str:
    data = read_json(borer_session_path())
    if isinstance(data, dict):
        p = str(data.get("path", "")).strip()
        if p and os.path.isfile(p):
            return p
    return ""


def upstreams_path() -> Path:
    return xt_home() / "mcp_upstreams.json"


def catalog_cache_path(server: str) -> Path:
    safe = server.replace("/", "_").replace("\\", "_").replace(":", "_").replace(" ", "_")
    return xt_home() / "cache" / f"mcp-catalog-{safe}.json"


def load_upstreams() -> dict[str, dict[str, Any]]:
    data = read_json(upstreams_path())
    if isinstance(data, dict) and isinstance(data.get("upstreams"), dict):
        return dict(data["upstreams"])
    return {}


def save_upstream(name: str, command: list[str], source: str = "connect") -> None:
    canon = canonical_upstream_name(name)
    cur = load_upstreams()
    cur[canon] = {"name": canon, "command": command, "source": source}
    atomic_write_json(upstreams_path(), {"version": 1, "upstreams": cur})


def save_cached_catalog(server: str, tools: list[dict[str, Any]]) -> None:
    atomic_write_json(
        catalog_cache_path(canonical_upstream_name(server)),
        {"server": canonical_upstream_name(server), "fetched_at": int(time.time()), "tools": tools},
    )


def load_cached_catalog(server: str) -> list[dict[str, Any]]:
    data = read_json(catalog_cache_path(canonical_upstream_name(server)))
    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        return list(data["tools"])
    return []


def split_cmd(cmd_str: str) -> list[str]:
    return shlex.split(cmd_str, posix=(os.name != "nt"))


def resolve_upstream_cmd(server_name: str, explicit_cmd: str | None = None) -> tuple[str, list[str] | None, str | None]:
    """Resolve an external MCP stdio command from explicit_cmd, $XT_HOME/mcp_upstreams.json, or presets."""
    canon = canonical_upstream_name(server_name)
    if explicit_cmd:
        parts = split_cmd(explicit_cmd)
        if not parts:
            return canon, None, "empty command"
        return canon, parts, None

    saved = load_upstreams()
    if canon in saved and isinstance(saved[canon].get("command"), list) and saved[canon]["command"]:
        return canon, list(saved[canon]["command"]), None
    if server_name in saved and isinstance(saved[server_name].get("command"), list) and saved[server_name]["command"]:
        return server_name, list(saved[server_name]["command"]), None

    home = Path.home()
    if canon == "rea":
        env_cmd = os.environ.get("REA_CMD", "").strip()
        if env_cmd:
            parts = split_cmd(env_cmd)
            if os.environ.get("REA_ARGS", "").strip():
                parts.extend(split_cmd(os.environ["REA_ARGS"]))
            elif "mcp" not in parts and "--mcp" not in parts:
                parts.append("mcp")
            return canon, parts, None
        for exe in ("rea-agents", "rea"):
            found = shutil.which(exe)
            if found:
                return canon, [found, "mcp"], None
        cands = [
            home / ".local" / "share" / "rea" / "node_modules" / ".bin" / "rea-agents",
            home / ".local" / "share" / "rea" / "node_modules" / ".bin" / "rea",
        ]
        if os.name == "nt":
            cands = [
                home / ".local" / "share" / "rea" / "node_modules" / ".bin" / "rea-agents.cmd",
                home / "AppData" / "Local" / "rea" / "node_modules" / ".bin" / "rea-agents.cmd",
            ] + cands
        for c in cands:
            if c.is_file():
                return canon, [str(c), "mcp"], None
        npx = shutil.which("npx") or shutil.which("npx.cmd")
        if npx:
            return canon, [npx, "-y", "rea-agents@latest", "mcp"], None
        return canon, None, "rea executable not found (set REA_CMD or install rea-agents)"

    if canon == "craft-anything":
        def _craft_flags(base: list[str]) -> list[str]:
            out = list(base)
            if "mcp" not in out:
                out.append("mcp")
            if os.environ.get("XT_CRAFT_ALL_TOOLS") != "0" and "--all-tools" not in out:
                out.append("--all-tools")
            if os.environ.get("XT_CRAFT_DEEP") == "1" and "--deep" not in out:
                out.append("--deep")
            if os.environ.get("XT_CRAFT_ALLOW_RUN") == "1" and "--allow-run" not in out:
                out.append("--allow-run")
            proj = os.environ.get("XT_CRAFT_PROJECT", "").strip()
            if proj and "--project" not in out:
                out.extend(["--project", proj])
            return out

        env_cmd = os.environ.get("CRAFT_ANYTHING_CMD", "").strip()
        if env_cmd:
            return canon, _craft_flags(split_cmd(env_cmd)), None
        for exe in ("craft-anything-cli", "craft-anything"):
            found = shutil.which(exe)
            if found:
                return canon, _craft_flags([found]), None
        suffix = ".exe" if os.name == "nt" else ""
        for cand in (home / ".cargo" / "bin" / f"craft-anything-cli{suffix}",
                     home / ".local" / "bin" / f"craft-anything-cli{suffix}"):
            if cand.is_file():
                return canon, _craft_flags([str(cand)]), None
        return canon, None, "craft-anything-cli not found (set CRAFT_ANYTHING_CMD or install craft-anything-cli)"

    if canon == "borer":
        def _borer_flags(base: list[str]) -> list[str]:
            out = list(base)
            extra = os.environ.get("BORER_ARGS", "").strip()
            if extra:
                out.extend(split_cmd(extra))
            return out

        env_cmd = os.environ.get("BORER_CMD", "").strip()
        if env_cmd:
            return canon, _borer_flags(split_cmd(env_cmd)), None
        found = shutil.which("borer")
        if found:
            return canon, _borer_flags([found]), None
        suffix = ".exe" if os.name == "nt" else ""
        for cand in (home / ".cargo" / "bin" / f"borer{suffix}",
                     home / ".local" / "bin" / f"borer{suffix}"):
            if cand.is_file():
                return canon, _borer_flags([str(cand)]), None
        return canon, None, "borer executable not found (set BORER_CMD or install imjustprism/borer)"

    info = EXTERNAL_SERVERS.get(canon)
    if not info:
        for s_name, s_info in EXTERNAL_SERVERS.items():
            if canon.lower() in s_info.get("aliases", []):
                info = s_info
                canon = s_name
                break
    if info:
        return canon, [info["command"], *info["args"]], None
    return canon, None, f"unknown server '{server_name}'. Available: {sorted(set(EXTERNAL_SERVERS) | set(saved))}"


def known_upstreams() -> list[str]:
    seen: list[str] = []
    def _add(name: str) -> None:
        c = canonical_upstream_name(name)
        if c and c not in seen:
            seen.append(c)

    for k in load_upstreams():
        _add(k)
    env_raw = os.environ.get("XT_MCP_UPSTREAMS", "").strip()
    if env_raw:
        for part in env_raw.split(","):
            _add(part)
    cache_dir = xt_home() / "cache"
    if cache_dir.is_dir():
        for p in sorted(cache_dir.glob("mcp-catalog-*.json")):
            _add(p.name[len("mcp-catalog-"):-len(".json")])
    for preset in ("rea", "craft-anything", "borer"):
        _, argv, err = resolve_upstream_cmd(preset)
        if not err and argv and Path(argv[0]).name not in ("npx", "npx.cmd"):
            _add(preset)
    return seen


def _read_rpc_by_id(stdout, expected_id: int, deadline: float) -> tuple[dict[str, Any] | None, bool]:
    """Read newline-delimited JSON-RPC messages until expected_id matches."""
    list_changed = False
    while time.monotonic() < deadline:
        line = stdout.readline()
        if not line:
            return None, list_changed
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        if msg.get("id") is None:
            if msg.get("method") == "notifications/tools/list_changed":
                list_changed = True
            continue
        if msg.get("id") == expected_id:
            return msg, list_changed
    return None, list_changed


def close_subprocess(proc: subprocess.Popen[str] | None) -> None:
    """Terminate an MCP child process and close all attached stdio pipes."""
    if proc is None:
        return
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def search_tools(query: str, limit: int = 8) -> list[dict[str, Any]]:
    """Search external tools across cached catalogs, saved upstreams, and presets."""
    q = query.lower().strip()
    words = [w for w in q.split() if len(w) > 1]
    matches: list[dict[str, Any]] = []
    seen_servers: set[str] = set()

    for s_name in known_upstreams():
        cached = load_cached_catalog(s_name)
        if not cached:
            continue
        seen_servers.add(s_name)
        matching_tools = []
        s_boost = 2 if s_name in q or (s_name == "craft-anything" and "craft" in words) else 0
        for t in cached:
            hay = f"{s_name} {t.get('name', '')} {t.get('description', '')}".lower()
            if s_name == "borer" and t.get("name") == "query":
                hay += " triage taint emulate solve grep unpack devirt stackstrings capabilities antianalysis dynimports checks yara sig why layout patch flat vm hidden decoded"
            if not words or any(w in hay for w in words):
                matching_tools.append({
                    "name": t.get("name"),
                    "description": str(t.get("description", ""))[:140],
                })
        if matching_tools or s_boost > 0:
            matches.append({
                "server": s_name,
                "title": EXTERNAL_SERVERS.get(s_name, {}).get("title", f"Connected MCP: {s_name}"),
                "description": EXTERNAL_SERVERS.get(s_name, {}).get("description", "Cached live upstream MCP catalog"),
                "tools": (matching_tools or cached)[:15],
                "invocation": f"xtforge tool run {s_name} <tool_name> '{{\"arg\": \"val\"}}'",
            })

    for s_name, s_info in EXTERNAL_SERVERS.items():
        if s_name in seen_servers:
            continue
        score = 0
        matching_tools = []
        for alias in s_info.get("aliases", []):
            if alias in q or any(w == alias for w in words):
                score += 3
        if any(w in s_info.get("description", "").lower() for w in words):
            score += 1
        for t in s_info.get("tools", []):
            t_name = t["name"].lower()
            t_desc = t["description"].lower()
            if any(w in t_name or w in t_desc for w in words) or score > 0:
                matching_tools.append(t)
        if score > 0 or matching_tools:
            matches.append({
                "server": s_name,
                "title": s_info["title"],
                "description": s_info["description"],
                "tools": matching_tools or s_info.get("tools", []),
                "invocation": f"xtforge tool run {s_name} <tool_name> '{{\"arg\": \"val\"}}'",
            })

    return matches[:limit]


def execute_tool(server_name: str, tool_name: str, arguments: dict[str, Any] | None = None,
                 timeout: int = 60) -> dict[str, Any]:
    """Execute an external MCP tool over stdio JSON-RPC with a full MCP handshake."""
    canon, cmd, err = resolve_upstream_cmd(server_name)
    if err or not cmd:
        return {"ok": False, "error": err or f"unknown server '{server_name}'"}

    resolved_bin = shutil.which(cmd[0]) or cmd[0]
    if not os.path.exists(resolved_bin):
        return {"ok": False, "error": f"server executable not found: {cmd[0]}"}
    cmd = [resolved_bin, *cmd[1:]]

    proc_env = os.environ.copy()
    saved = load_upstreams()
    entry = saved.get(canonical_upstream_name(server_name)) or saved.get(server_name) or {}
    if isinstance(entry.get("env"), dict):
        for k, v in entry["env"].items():
            proc_env[str(k)] = str(v)
    deadline = time.monotonic() + max(timeout, 5)
    proc: subprocess.Popen[str] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=proc_env,
        )
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "xt-forge", "version": "0.4.4"}},
        }) + "\n")
        proc.stdin.flush()
        init_resp, _ = _read_rpc_by_id(proc.stdout, 1, deadline)
        if init_resp is None:
            return {"ok": False, "error": f"{canon} did not answer initialize"}
        if "error" in init_resp:
            return {"ok": False, "error": init_resp["error"]}

        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        call_args = dict(arguments or {})
        req_id = 2
        if canon == "borer":
            if tool_name == "query":
                raw_uri = str(call_args.get("uri", "")).strip()
                if raw_uri and "://" not in raw_uri:
                    call_args["uri"] = f"borer://{raw_uri.lstrip('/')}"
            if tool_name == "load_binary":
                if not call_args.get("path") and call_args.get("binary"):
                    call_args["path"] = str(call_args.pop("binary")).strip()
            elif tool_name not in ("load_project", "save_project", "reload"):
                target_bin = str(call_args.pop("path", "") or call_args.pop("binary", "") or "").strip()
                if not target_bin:
                    target_bin = load_borer_session()
                if target_bin:
                    proc.stdin.write(json.dumps({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "method": "tools/call",
                        "params": {"name": "load_binary", "arguments": {"path": target_bin}},
                    }) + "\n")
                    proc.stdin.flush()
                    load_resp, _ = _read_rpc_by_id(proc.stdout, req_id, deadline)
                    if load_resp and "error" not in load_resp:
                        save_borer_session(target_bin)
                    req_id += 1

        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": call_args},
        }) + "\n")
        proc.stdin.flush()

        call_resp, _ = _read_rpc_by_id(proc.stdout, req_id, deadline)
        if call_resp is None:
            stderr_tail = (proc.stderr.read() if proc.stderr else "")[:400]
            return {"ok": False, "error": f"no tools/call response from {canon}: {stderr_tail}"}
        if "error" in call_resp:
            return {"ok": False, "error": call_resp["error"]}
        if canon == "borer" and tool_name == "load_binary" and call_args.get("path"):
            save_borer_session(str(call_args["path"]))
        return {"ok": True, "server": canon, "result": call_resp.get("result", {})}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        close_subprocess(proc)
