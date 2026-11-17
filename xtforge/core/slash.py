"""Universal slash-command interpreter (F1/F3/F4): one grammar, every harness.

This is core logic (R7): the OpenCode plugin, the MCP adapter, and the CLI all
route through dispatch(). Zero LLM calls — flash ops are direct code.
"""
from __future__ import annotations

import json
from typing import Any

from .mem.flash import Flash
from .mem import search as memsearch
from .mem.scopes import GLOBAL
from .mem.store import Store
from .route.guard import issue_token
from ..version import db_path

FLASH_COMMANDS = "/m", "/mg", "/ml", "/mp", "/mx", "/mc", "/mw", "/mu"
ALL_COMMANDS = FLASH_COMMANDS + ("/xtf", "/goal", "/build", "/route", "/phone", "/help")


def is_slash(text: str) -> bool:
    txt = (text or "").strip()
    return txt.startswith("/") and txt.split()[0] in ALL_COMMANDS


def name(text: str) -> str:
    return (text or "").strip().split()[0]


def _split_kv(text: str) -> tuple[str | None, str]:
    if "=" in text and not text.startswith("#"):
        key, _, val = text.partition("=")
        key = key.strip()
        if key and " " not in key and not key.startswith("/"):
            return key, val.strip()
    return None, text.strip()


def _flash(base: Any = None) -> Flash:
    return Flash(base=base)


def _confirm_token(action: str, target: str) -> dict[str, Any]:
    return issue_token(action, target)


def dispatch_flash(text: str, flash: Flash, store: Store | None = None,
                   scope: str = GLOBAL) -> dict[str, Any]:
    cmd, _, body = text.strip().partition(" ")
    body = body.strip()
    cmd = cmd.lower()
    if cmd == "/m":
        if not body:
            return {"command": "/m", "ok": False, "err": "requires text",
                    "reply": "/m requires text: /m <note> [ #tag ]"}
        key, val = _split_kv(body)
        rec = flash.set(val, key=key, scope=scope, src="slash")
        return {"command": "/m", "ok": True, "entry": rec,
                "reply": f"[{rec['id']}] {rec['k']} = {rec['v'][:120]}"}
    if cmd == "/mg":
        rec = None
        if body:
            rec = flash.get(body, scope)
        if rec is None and body:
            hits = flash.find(body, scope, top=3)
            if hits:
                rec = hits[0]
        if rec is None:
            return {"command": "/mg", "ok": False, "err": "not found"}
        return {"command": "/mg", "ok": True, "entry": rec,
                "reply": f"{rec['k']} = {rec['v']}"}
    if cmd == "/ml":
        n = int(body) if body.isdigit() else 10
        recs = flash.list(scope, n=n)
        return {"command": "/ml", "ok": True, "entries": recs,
                "reply": "\n".join(f"{r['id']} {r['k']}: {r['v'][:80]}" for r in recs)
                         or "(empty)"}
    if cmd == "/mp":
        rec = flash.pin(body, scope) if body else None
        return {"command": "/mp", "ok": rec is not None,
                "entry": rec, "reply": f"pin={rec['pin']}" if rec else "not found"}
    if cmd == "/mx":
        if body == "--all":
            tok = _confirm_token("clear_scope", scope)
            return {"command": "/mx", "ok": True, "requires_confirm": True,
                    "reply": f"pass --confirm {tok['confirm_token']} to clear {scope}"}
        ok = flash.delete(body, scope)
        return {"command": "/mx", "ok": ok, "reply": "deleted" if ok else "not found"}
    if cmd == "/mc":
        stats = flash.compact(scope)
        return {"command": "/mc", "ok": True, "stats": stats,
                "reply": f"alive={stats['after']} merged={stats['dupes_merged']} "
                         f"expired={stats['expired']}"}
    if cmd == "/mw":
        wired = flash.wired(scope) if not body else \
            [r for r in [flash.get(body, scope)] if r]
        if store is not None and body and (not wired or body == "."):
            hits = memsearch.search(store, body, k=3, scopes=[GLOBAL])
            lines = [h["line"] for h in hits["results"]]
            return {"command": "/mw", "ok": True, "lines": lines,
                    "reply": "\n".join(lines) or "(nothing wired)"}
        lines = [f"[FLASH:{r['k']}] {r['v'][:300]}" for r in wired]
        return {"command": "/mw", "ok": True, "lines": lines, "entries": wired,
                "reply": "\n".join(lines) or "(nothing pinned; use /mp <key> first)"}
    if cmd == "/mu":
        if store is None:
            return {"command": "/mu", "ok": False, "err": "no universal store configured"}
        rec = flash.get(body, scope) if body else None
        if rec is None:
            hits = flash.find(body, scope, top=1)
            rec = hits[0] if hits else None
        if rec is None:
            return {"command": "/mu", "ok": False, "err": "flash entry not found"}
        target = store.put(scope=GLOBAL, kind="snippet", title=rec["k"],
                           body=rec["v"], tags=list(rec.get("tags") or []),
                           source=f"flash:{rec['id']}", confidence=0.9)
        return {"command": "/mu", "ok": True, "promoted": target,
                "reply": f"promoted {rec['k']} -> universal {target['id']}"}
    return {"command": cmd, "ok": False, "err": f"unknown flash command {cmd}"}


def dispatch(text: str, *, flash: Flash | None = None, store: Store | None = None,
             scope: str = GLOBAL) -> dict[str, Any]:
    """Route a slash command to its handler. Always returns a dict with a reply."""
    text = (text or "").strip()
    if not is_slash(text):
        return {"ok": False, "err": "not a slash command", "reply": None}
    cmd = name(text)
    if cmd == "/help":
        return {"command": "/help", "ok": True,
                "reply": " ".join(ALL_COMMANDS),
                "commands": list(ALL_COMMANDS)}
    if cmd == "/xtf":
        rest = text[len("/xtf"):].strip()
        if not rest or rest == "--help":
            return {
                "command": "/xtf",
                "ok": True,
                "reply": "usage: /xtf --meta | /xtf doctor | /xtf re <verb> <path> | /xtf intel cve <CVE> | /xtf code graph <sym> .",
            }
        if rest == "--meta":
            return {
                "command": "/xtf",
                "ok": True,
                "mode": "meta",
                "exec": "xt-forge --meta",
                "forward": "xt-forge --meta",
                "reply": "MCP gateway command: `xt-forge --meta` (4 meta-tools: xt_discover, xt_schema, xt_call, xt_batch). Add to your agent config or run directly over stdio.",
            }
        return {"command": "/xtf", "ok": True, "forward": f"xt-forge {rest}",
                "reply": "run: xt-forge " + rest}
    if cmd == "/goal":
        return {"command": "/goal", "ok": True, "forward": text,
                "reply": "hand the following to the goal engine verbatim: " + text}
    if cmd == "/build":
        return {"command": "/build", "ok": True, "forward": text,
                "reply": "hand the following to the build runner verbatim: " + text}
    if cmd == "/route":
        return {"command": "/route", "ok": True, "forward": text,
                "reply": "hand the following to route tools verbatim: " + text}
    if cmd == "/phone":
        return {"command": "/phone", "ok": True, "forward": text,
                "reply": "hand the following to phone tools verbatim: " + text}
    return dispatch_flash(text, flash or _flash(), store, scope)


# Used by runlog/adapter header: which path handled commands this session.
HARNESS_PATHS = {
    "direct": "hook interception, no model round trip",
    "shell_inject": "command markdown injects CLI output for echo",
}


def reply_text(res: dict[str, Any]) -> str:
    return str(res.get("reply") or res.get("err") or json.dumps(res, default=str))