"""MCP schema rug-pull & prompt-injection detector (`mcp_trust.json`) mirroring Go `internal/mcp/audit.go`."""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from ..atomicio import atomic_write_json, read_json
from ..version import xt_home

SCHEMA_RULES = (
    ("schema_ignore_prior", "critical", re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)", re.I)),
    ("schema_hidden_system", "critical", re.compile(r"(?:<\s*system\s*>|<\s*/?\s*important\s*>|\[SYSTEM\])", re.I)),
    ("schema_exfil", "critical", re.compile(r"(?:\.ssh/id_rsa|\.aws/credentials|\.env\b)", re.I)),
    ("schema_stealth", "high", re.compile(r"(?:do\s+not\s+(?:tell|inform)\s+the\s+user)", re.I)),
    ("schema_shell_pipe", "critical", re.compile(r"(?:curl|wget)[^|]*\|\s*(?:ba)?sh", re.I)),
)


def trust_path() -> Path:
    return xt_home() / "mcp_trust.json"


def schema_sha256(tools: list[dict[str, Any]]) -> str:
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_trust() -> dict[str, Any]:
    return read_json(trust_path()) or {"servers": {}}


def pin_trust(server: str, tools: list[dict[str, Any]], note: str = "") -> dict[str, Any]:
    digest = schema_sha256(tools)
    db = load_trust()
    servers = db.setdefault("servers", {})
    servers[server] = {
        "sha256": digest,
        "tool_count": len(tools),
        "pinned_at": int(time.time()),
        "note": note,
    }
    atomic_write_json(trust_path(), db)
    return {"ok": True, "server": server, "sha256": digest, "tool_count": len(tools), "engine": "python"}


def evaluate_tools(server: str, tools: list[dict[str, Any]], *,
                   trust_on_first: bool = False) -> dict[str, Any]:
    """Scan MCP tools list for injection patterns and check/pin schema SHA-256."""
    findings: list[dict[str, Any]] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        blob = json.dumps(tool, ensure_ascii=False)
        for rule, sev, pat in SCHEMA_RULES:
            m = pat.search(blob)
            if m:
                findings.append({
                    "rule": rule, "severity": sev,
                    "tool": name, "excerpt": m.group(0)[:80],
                })

    digest = schema_sha256(tools)
    db = load_trust()
    entry = (db.get("servers") or {}).get(server)
    rug_pull = False
    pinned_new = False
    if entry:
        if entry.get("sha256") != digest:
            rug_pull = True
            findings.append({
                "rule": "schema_rug_pull",
                "severity": "critical",
                "tool": server,
                "excerpt": f"expected={entry.get('sha256', '')[:12]} got={digest[:12]}",
            })
    elif trust_on_first:
        pin_trust(server, tools, note="auto-tof")
        pinned_new = True

    ok = not any(f["severity"] == "critical" for f in findings) and not rug_pull
    return {
        "ok": ok,
        "server": server,
        "sha256": digest,
        "tool_count": len(tools),
        "rug_pull": rug_pull,
        "pinned_on_first": pinned_new,
        "findings": findings,
        "engine": "python",
    }
