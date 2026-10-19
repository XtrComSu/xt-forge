"""CLI handler for external tool detection."""
from __future__ import annotations

from .common import _out


def cmd_tools(args):
    from ..core.tools import registry

    verb = getattr(args, "tools_verb", "status")
    if verb != "status":
        raise ValueError(f"unknown tools verb: {verb}")

    res = registry.status()
    summary = res["summary"]
    lines = [f'{summary["total"]} tools: {summary["present"]} present, '
             f'{summary["missing"]} missing']
    for tool in res["tools"]:
        if tool["present"]:
            version = f'  {tool["version"]}' if tool["version"] else ""
            lines.append(f'[ok]   {tool["name"]:<8} {tool["path"]}{version}')
        else:
            lines.append(f'[miss] {tool["name"]:<8} {tool["install"]}')
    return _out(args, res, "\n".join(lines))
