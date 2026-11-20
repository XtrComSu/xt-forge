"""IDA Pro & Headless RE MCP Server (`python3 -m xtforge.adapters.ida_mcp`).

Replaces `ida-pro-mcp` with a standalone stdio JSON-RPC 2.0 MCP server that
bridges:
  1. Live IDA Pro (`ida-pro-mcp` HTTP bridge at `XT_IDA_MCP_URL`, default
     `http://127.0.0.1:13337`).
  2. Headless `idalib` / `idat64` / `idat` batch execution + `.i64`/`.idb`
     header inspection.
  3. Instant native fallback (`borer` + `ghidra` + `xt-forge` ELF/PE/Mach-O +
     persistent SHA-256 overlay) so all IDA tools work offline even without
     a local IDA Pro license.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ..core.re import ida as _ida
from .ghidra_mcp import _handle_tool as _ghidra_handle_tool

PROTOCOL_FALLBACK = "2025-06-18"


def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = required
    return out


_STR = {"type": "string"}
_INT = {"type": "integer"}

TOOLS: list[dict[str, Any]] = [
    {"name": "ida_status", "description": "Check live IDA Pro HTTP bridge, idalib, idat64, Binary Ninja, Rizin, Ghidra, and Borer availability.", "inputSchema": _schema({})},
    {"name": "ida_inspect_idb", "description": "Inspect .i64 / .idb database container metadata and locate companion binary.", "inputSchema": _schema({"path": _STR}, ["path"])},
    {"name": "ida_functions", "description": "List discovered functions from IDA Pro or Borer/Ghidra fallback.", "inputSchema": _schema({"path": _STR, "filter": _STR, "offset": _INT, "limit": _INT}, ["path"])},
    {"name": "ida_decompile", "description": "Decompile function pseudocode via IDA Pro Hex-Rays or Borer/Ghidra fallback with overlay renames.", "inputSchema": _schema({"path": _STR, "target": _STR}, ["path", "target"])},
    {"name": "ida_disasm", "description": "Disassemble function instructions via IDA Pro or Borer/Ghidra/objdump fallback.", "inputSchema": _schema({"path": _STR, "target": _STR, "count": _INT}, ["path", "target"])},
    {"name": "ida_xrefs", "description": "List cross-references (xrefs_to) for an address or symbol.", "inputSchema": _schema({"path": _STR, "target": _STR}, ["path", "target"])},
    {"name": "ida_strings", "description": "List extracted ASCII/UTF-16/XOR strings with optional filter.", "inputSchema": _schema({"path": _STR, "filter": _STR, "limit": _INT}, ["path"])},
    {"name": "ida_imports", "description": "List imported symbols/modules from the binary.", "inputSchema": _schema({"path": _STR, "offset": _INT, "limit": _INT}, ["path"])},
    {"name": "ida_exports", "description": "List exported symbols from the binary.", "inputSchema": _schema({"path": _STR, "offset": _INT, "limit": _INT}, ["path"])},
    {"name": "ida_structs", "description": "List structs, C++ RTTI classes, and vtable layouts.", "inputSchema": _schema({"path": _STR}, ["path"])},
    {"name": "ida_rename", "description": "Rename a function in live IDA Pro or persistent SHA-256 overlay.", "inputSchema": _schema({"path": _STR, "target": _STR, "new_name": _STR}, ["path", "target", "new_name"])},
    {"name": "ida_set_type", "description": "Set function prototype/signature in live IDA Pro or persistent SHA-256 overlay.", "inputSchema": _schema({"path": _STR, "target": _STR, "prototype": _STR}, ["path", "target", "prototype"])},
    {"name": "ida_comment", "description": "Add a decompiler/disassembly comment at an address.", "inputSchema": _schema({"path": _STR, "address": _STR, "comment": _STR}, ["path", "address", "comment"])},
    {"name": "ida_batch", "description": "Run an IDAPython batch script via idat64/idat (-A -S<script>).", "inputSchema": _schema({"path": _STR, "script_path": _STR, "timeout_s": _INT}, ["path", "script_path"])},
]


def _handle_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "ida_status":
        return _ida.ida_status()
    if name == "ida_inspect_idb":
        return _ida.inspect_idb(str(args.get("path", "")))
    if name == "ida_functions":
        return _ida.ida_functions(
            str(args.get("path", "")),
            filter_str=str(args.get("filter", "")),
            offset=int(args.get("offset", 0)),
            limit=int(args.get("limit", 100)),
        )
    if name == "ida_decompile":
        return _ida.ida_decompile(str(args.get("path", "")), str(args.get("target", "main")))
    if name == "ida_disasm":
        return _ida.ida_disasm(str(args.get("path", "")), str(args.get("target", "main")), count=int(args.get("count", 128)))
    if name == "ida_xrefs":
        return _ida.ida_xrefs(str(args.get("path", "")), str(args.get("target", "")))
    if name == "ida_strings":
        return _ida.ida_strings(str(args.get("path", "")), filter_str=str(args.get("filter", "")), limit=int(args.get("limit", 100)))
    if name == "ida_imports":
        return _ghidra_handle_tool("list_imports", args)
    if name == "ida_exports":
        return _ghidra_handle_tool("list_exports", args)
    if name == "ida_structs":
        return _ida.ida_structs(str(args.get("path", "")))
    if name == "ida_rename":
        return _ida.ida_rename(str(args.get("path", "")), str(args.get("target", "")), str(args.get("new_name", "")))
    if name == "ida_set_type":
        return _ida.ida_set_type(str(args.get("path", "")), str(args.get("target", "")), str(args.get("prototype", "")))
    if name == "ida_comment":
        return _ida.ida_comment(str(args.get("path", "")), str(args.get("address", "")), str(args.get("comment", "")))
    if name == "ida_batch":
        return _ida.ida_batch(str(args.get("path", "")), str(args.get("script_path", "")), timeout_s=int(args.get("timeout_s", 120)))
    return {"ok": False, "err": f"unknown tool: {name}"}


def _handle(message: dict[str, Any]) -> dict[str, Any] | None:
    msg_id = message.get("id")
    method = message.get("method", "")
    if method == "notifications/initialized" or msg_id is None:
        return None
    if method == "initialize":
        req_ver = (message.get("params") or {}).get("protocolVersion") or PROTOCOL_FALLBACK
        result: Any = {
            "protocolVersion": req_ver,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "xt-forge-ida-mcp", "version": "1.0.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = message.get("params") or {}
        tname = str(params.get("name", ""))
        targs = params.get("arguments") or {}
        try:
            payload = _handle_tool(tname, targs)
            is_err = not bool(payload.get("ok", True))
        except Exception as exc:
            payload = {"ok": False, "err": str(exc)}
            is_err = True
        result = {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2, default=str)}],
            "isError": is_err,
        }
    else:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main() -> int:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        reply = _handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
