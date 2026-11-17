"""`xtforge tool` — on-demand discovery and execution of external MCP tools.

Enables agents to discover and invoke specialized external tools (cad3d/OpenSCAD,
photoeditor, glmocr, searchd) on demand without cluttering the model prompt with
dozens of tool schemas on every turn.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ..core.mcp_registry import EXTERNAL_SERVERS, search_tools, execute_tool


def cmd_tool(args) -> int:
    verb = getattr(args, "tool_verb", None)
    is_json = getattr(args, "json", False)

    # 1. xtforge tool list
    if verb == "list":
        if is_json:
            print(json.dumps({"ok": True, "servers": EXTERNAL_SERVERS}, indent=2))
            return 0

        print("=== Registered External MCP Tool Capabilities ===\n")
        for s_name, s_info in EXTERNAL_SERVERS.items():
            print(f"📦 Server: {s_name} — {s_info.get('title')}")
            print(f"   Description: {s_info.get('description')}")
            print(f"   Aliases: {', '.join(s_info.get('aliases', []))}")
            print(f"   Available Tools ({len(s_info.get('tools', []))}):")
            for t in s_info.get("tools", []):
                print(f"     • {t['name']}: {t['description']}")
            print()
        return 0

    # 2. xtforge tool search <query>
    if verb == "search":
        query = (getattr(args, "query", None) or getattr(args, "server", None) or "").strip()
        if not query:
            msg = "tool search requires a query string, e.g.: xtforge tool search opencad"
            if is_json:
                print(json.dumps({"ok": False, "error": msg}))
            else:
                print(msg, file=sys.stderr)
            return 2

        hits = search_tools(query)
        if is_json:
            print(json.dumps({"ok": True, "query": query, "count": len(hits), "results": hits}, indent=2))
            return 0

        print(f"=== Tool Search Results for \"{query}\" ({len(hits)} servers match) ===\n")
        if not hits:
            print("No matching external tools found.")
            return 0

        for h in hits:
            print(f"🛠️  Server: {h['server']} ({h['title']})")
            print(f"   Description: {h['description']}")
            print(f"   Invocation: {h['invocation']}")
            print("   Matching Tools:")
            for t in h["tools"]:
                print(f"     • {t['name']}: {t['description']}")
            print()
        return 0

    # 3. xtforge tool run <server> <tool> [arguments]
    if verb == "run":
        server = (getattr(args, "server", None) or "").strip()
        tool_name = (getattr(args, "tool_name", None) or "").strip()
        args_raw = getattr(args, "arguments", None)
        args_file = getattr(args, "args_file", None)

        if not server or not tool_name:
            msg = "tool run requires server and tool name, e.g.: xtforge tool run cad3d cad_create_primitive '{\"primitive_type\": \"cube\", ...}'"
            if is_json:
                print(json.dumps({"ok": False, "error": msg}))
            else:
                print(msg, file=sys.stderr)
            return 2

        parsed_args: dict[str, Any] = {}
        if args_file:
            try:
                if args_file == "-":
                    text = sys.stdin.read()
                else:
                    with open(args_file, "r", encoding="utf-8") as fh:
                        text = fh.read()
                if text.strip():
                    parsed_args = json.loads(text)
            except Exception as exc:
                err = f"failed to parse arguments from file {args_file}: {exc}"
                if is_json:
                    print(json.dumps({"ok": False, "error": err}))
                else:
                    print(err, file=sys.stderr)
                return 1
        elif args_raw:
            try:
                parsed_args = json.loads(args_raw)
            except Exception as exc:
                err = f"failed to parse arguments JSON: {exc}"
                if is_json:
                    print(json.dumps({"ok": False, "error": err}))
                else:
                    print(err, file=sys.stderr)
                return 1

        timeout = int(getattr(args, "timeout", 60) or 60)
        res = execute_tool(server, tool_name, parsed_args, timeout=timeout)

        if is_json:
            print(json.dumps(res, indent=2))
        else:
            if not res.get("ok"):
                print(f"Error executing {server}/{tool_name}: {res.get('error')}", file=sys.stderr)
                return 1
            result_obj = res.get("result", {})
            # If standard MCP content array
            if isinstance(result_obj, dict) and "content" in result_obj:
                for item in result_obj.get("content", []):
                    if isinstance(item, dict) and "text" in item:
                        print(item["text"])
                    else:
                        print(item)
            else:
                print(json.dumps(result_obj, indent=2))
        return 0 if res.get("ok") else 1

    msg = f"unknown tool verb '{verb}'. Use: list, search, run"
    if is_json:
        print(json.dumps({"ok": False, "error": msg}))
    else:
        print(msg, file=sys.stderr)
    return 2
