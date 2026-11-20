"""IDA Pro & multi-disassembler integration for XT-Forge.

Supports:
  1. Live IDA Pro bridge (`ida-pro-mcp` HTTP/JSON-RPC at `XT_IDA_MCP_URL`, default
     `http://127.0.0.1:13337`).
  2. IDA 9.0+ headless `idalib` Python API (when installed).
  3. Headless `idat64` / `idat` batch execution (`-A -S<script>`).
  4. `.i64` / `.idb` database header & companion binary inspection.
  5. Seamless fallback to XT-Forge's `borer` + Ghidra + persistent SHA-256
     overlay engine (`xtforge.adapters.ghidra_mcp`) so all IDA tools work
     even when no local IDA Pro license is mounted.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..route import guard


def ida_mcp_url() -> str:
    return os.environ.get("XT_IDA_MCP_URL", "http://127.0.0.1:13337").rstrip("/")


def find_ida_binaries() -> dict[str, str | None]:
    """Locate `idat64`, `idat`, `ida64`, `ida`, and Binary Ninja / r2 / rizin."""
    roots = [
        Path.home() / "ida",
        Path.home() / "idapro",
        Path("/opt/ida"),
        Path("/opt/idapro"),
        Path("/usr/local/ida"),
    ]
    env_home = os.environ.get("IDA_HOME") or os.environ.get("IDADIR")
    if env_home:
        roots.insert(0, Path(env_home))

    found: dict[str, str | None] = {}
    for name in ("idat64", "idat", "ida64", "ida", "rizin", "r2"):
        hit = shutil.which(name)
        if not hit and name.startswith("ida"):
            for r in roots:
                cand = r / name
                if cand.is_file() and os.access(cand, os.X_OK):
                    hit = str(cand)
                    break
        found[name] = hit

    try:
        import idapro  # type: ignore  # noqa: F401
        found["idalib"] = "installed"
    except Exception:
        found["idalib"] = None

    try:
        import binaryninja  # type: ignore  # noqa: F401
        found["binaryninja"] = "installed"
    except Exception:
        found["binaryninja"] = shutil.which("binaryninja")
    return found


def probe_ida_http(timeout_s: float = 0.35) -> bool:
    """Check if an `ida-pro-mcp` HTTP/JSON-RPC bridge is listening."""
    base = ida_mcp_url()
    for path in ("/mcp", "/health", "/"):
        try:
            req = urllib.request.Request(f"{base}{path}", method="GET")
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if 200 <= resp.status < 500:
                    return True
        except Exception:
            continue
    return False


def call_ida_http(method: str, params: dict[str, Any] | None = None, *, timeout_s: float = 5.0) -> dict[str, Any] | None:
    """Invoke a JSON-RPC 2.0 method on a live `ida-pro-mcp` bridge."""
    url = f"{ida_mcp_url()}/mcp"
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": method, "arguments": params or {}},
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(data, dict) and "result" in data:
            return data["result"]
    except Exception:
        return None
    return None


def inspect_idb(path: str | Path) -> dict[str, Any]:
    """Inspect `.idb` / `.i64` database container metadata without running IDA."""
    canon = guard.read_guard(path)
    head = canon.read_bytes()[:64]
    magic = head[:4]
    is_idb = magic in (b"IDA0", b"IDA1", b"IDA2")
    bitness = 64 if canon.suffix.lower() == ".i64" or magic == b"IDA2" else 32
    companion = None
    for ext in ("", ".exe", ".dll", ".so", ".elf", ".bin"):
        cand = canon.with_suffix(ext)
        if cand != canon and cand.is_file():
            companion = str(cand)
            break
    return {
        "ok": is_idb,
        "path": str(canon),
        "magic": magic.decode("ascii", errors="replace"),
        "bitness": bitness,
        "size_bytes": canon.stat().st_size,
        "companion_binary": companion,
        "engine": "xtforge-idb-header",
    }


def _resolve_target_binary(path: str | Path) -> Path:
    canon = guard.read_guard(path)
    if canon.suffix.lower() in (".idb", ".i64"):
        info = inspect_idb(canon)
        if info.get("companion_binary"):
            return Path(info["companion_binary"])
    return canon


def _ghidra_fallback(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    from ...adapters.ghidra_mcp import _handle_tool
    res = _handle_tool(tool_name, arguments)
    if isinstance(res, dict) and "engine" in res:
        res["ida_fallback_engine"] = res["engine"]
    return res


def ida_status() -> dict[str, Any]:
    """Report available IDA Pro, Binary Ninja, Rizin/r2, Ghidra, and Borer backends."""
    bins = find_ida_binaries()
    live_http = probe_ida_http()
    from ...adapters.ghidra_mcp import STATE
    return {
        "ok": True,
        "ida_http_bridge": {"url": ida_mcp_url(), "reachable": live_http},
        "idalib": bins.get("idalib"),
        "idat64": bins.get("idat64"),
        "idat": bins.get("idat"),
        "ida64": bins.get("ida64"),
        "binaryninja": bins.get("binaryninja"),
        "rizin": bins.get("rizin"),
        "radare2": bins.get("r2"),
        "fallback_engines": {
            "borer": STATE.borer_bin,
            "ghidra_headless": STATE.headless_bin,
        },
        "engine": "ida-bridge+xtforge",
    }


def ida_functions(path: str | Path, *, filter_str: str = "", offset: int = 0, limit: int = 100) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("list_funcs", {"offset": offset, "count": limit, "filter": filter_str})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("list_functions", {
        "path": str(target_bin),
        "filter": filter_str,
        "offset": offset,
        "limit": limit,
    })


def ida_decompile(path: str | Path, target: str) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("decompile", {"addr": target})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "target": target, "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("decompile_function", {"path": str(target_bin), "name": target})


def ida_disasm(path: str | Path, target: str, *, count: int = 128) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("disassemble", {"addr": target, "count": count})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "target": target, "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("disassemble_function", {"path": str(target_bin), "name": target})


def ida_xrefs(path: str | Path, target: str) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("xrefs_to", {"addr": target})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "target": target, "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("xrefs_to", {"path": str(target_bin), "target": target})


def ida_strings(path: str | Path, *, filter_str: str = "", limit: int = 100) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("strings", {"filter": filter_str, "count": limit})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("list_strings", {"path": str(target_bin), "filter": filter_str, "limit": limit})


def ida_structs(path: str | Path) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("structs", {})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("rtti_classes", {"path": str(target_bin)})


def ida_rename(path: str | Path, target: str, new_name: str) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("rename_function", {"addr": target, "name": new_name})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("rename_function", {"path": str(target_bin), "old_name": target, "new_name": new_name})


def ida_set_type(path: str | Path, target: str, prototype: str) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("set_function_type", {"addr": target, "prototype": prototype})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("set_function_prototype", {
        "path": str(target_bin),
        "target": target,
        "prototype": prototype,
    })


def ida_comment(path: str | Path, address: str, comment: str) -> dict[str, Any]:
    if probe_ida_http():
        live = call_ida_http("set_comment", {"addr": address, "comment": comment})
        if live is not None:
            return {"ok": True, "engine": "ida-pro-mcp", "result": live}
    target_bin = _resolve_target_binary(path)
    return _ghidra_fallback("set_decompiler_comment", {
        "path": str(target_bin),
        "address": address,
        "comment": comment,
    })


def ida_batch(path: str | Path, script_path: str | Path, *, timeout_s: int = 120) -> dict[str, Any]:
    """Run an IDAPython batch script via `idat64` / `idat` (`-A -S<script>`)."""
    canon_bin = guard.read_guard(path)
    canon_script = guard.read_guard(script_path)
    bins = find_ida_binaries()
    idat = bins.get("idat64") or bins.get("idat")
    if not idat:
        return {
            "ok": False,
            "err": "idat64/idat not found on PATH or IDA_HOME",
            "hint": "Use `ida_decompile` / `ida_functions` / `ida_xrefs` for borer+ghidra fallback, or set IDA_HOME.",
        }
    with tempfile.NamedTemporaryFile(prefix="xt_ida_log_", suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [idat, "-A", f"-L{log_path}", f"-S{canon_script}", str(canon_bin)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:],
            "log": log_text[-4000:],
            "engine": Path(idat).name,
        }
    finally:
        log_path.unlink(missing_ok=True)
