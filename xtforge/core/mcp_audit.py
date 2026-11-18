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


def _go_json_dumps(obj: Any) -> str:
    """Serialize compact sorted JSON matching Go encoding/json HTML escaping."""
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def tool_hash(tool: dict[str, Any]) -> str:
    """Hash one MCP tool definition consistently with Go audit.go toolHash."""
    payload = {
        "name": str(tool.get("name", "")),
        "description": str(tool.get("description", "")),
        "inputSchema": tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else None,
    }
    return hashlib.sha256(_go_json_dumps(payload).encode("utf-8")).hexdigest()


def catalog_hash(tool_hashes: dict[str, str]) -> str:
    """Hash a sorted map of tool hashes consistently with Go audit.go catalogHash."""
    h = hashlib.sha256()
    for name in sorted(tool_hashes):
        h.update(f"{name}={tool_hashes[name]}\n".encode("utf-8"))
    return h.hexdigest()


def schema_sha256(tools: list[dict[str, Any]]) -> str:
    return catalog_hash({str(t.get("name", "")): tool_hash(t) for t in tools})


def load_trust() -> dict[str, Any]:
    return read_json(trust_path()) or {"version": 1, "servers": {}}


def pin_trust(server: str, tools: list[dict[str, Any]], note: str = "") -> dict[str, Any]:
    hashes = {str(t.get("name", "")): tool_hash(t) for t in tools}
    digest = catalog_hash(hashes)
    db = load_trust()
    servers = db.setdefault("servers", {})
    now = int(time.time())
    prev = servers.get(server) or {}
    servers[server] = {
        "server": server,
        "schema_sha256": digest,
        "sha256": digest,
        "tool_hashes": hashes,
        "tool_count": len(tools),
        "first_seen": prev.get("first_seen") or now,
        "last_verified": now,
        "pinned_at": now,
        "note": note,
    }
    atomic_write_json(trust_path(), db)
    return {"ok": True, "server": server, "sha256": digest, "schema_sha256": digest, "tool_count": len(tools), "engine": "python"}


def evaluate_tools(server: str, tools: list[dict[str, Any]], *,
                   trust_on_first: bool = False) -> dict[str, Any]:
    """Scan MCP tools list for injection patterns and check/pin schema SHA-256."""
    findings: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    for tool in tools:
        name = str(tool.get("name", ""))
        hashes[name] = tool_hash(tool)
        blob = json.dumps(tool, ensure_ascii=False)
        for rule, sev, pat in SCHEMA_RULES:
            m = pat.search(blob)
            if m:
                findings.append({
                    "rule": rule, "severity": sev,
                    "tool": name, "excerpt": m.group(0)[:80],
                })

    digest = catalog_hash(hashes)
    db = load_trust()
    entry = (db.get("servers") or {}).get(server)
    rug_pull = False
    pinned_new = False
    if entry:
        pinned_digest = entry.get("schema_sha256") or entry.get("sha256") or ""
        if pinned_digest != digest:
            rug_pull = True
            findings.append({
                "rule": "schema_rug_pull",
                "severity": "critical",
                "tool": server,
                "excerpt": f"expected={pinned_digest[:12]} got={digest[:12]}",
            })
    elif trust_on_first:
        pin_trust(server, tools, note="auto-tof")
        pinned_new = True

    ok = not any(f["severity"] == "critical" for f in findings) and not rug_pull
    return {
        "ok": ok,
        "server": server,
        "sha256": digest,
        "schema_sha256": digest,
        "tool_count": len(tools),
        "rug_pull": rug_pull,
        "pinned_on_first": pinned_new,
        "findings": findings,
        "engine": "python",
    }
