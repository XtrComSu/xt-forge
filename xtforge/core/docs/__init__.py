"""Live library documentation via Context7.

Two MCP tools would cost two schemas on every model step. One CLI verb costs
nothing until it is called, so the capability lives here instead:

    xtforge docs search "FastAPI"
    xtforge docs show websites/fastapi_tiangolo --topic "Depends"

The API is public and read-only. Queries must not contain secrets: the text
is sent to a third-party service.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

BASE = "https://context7.com"
UA = "xt-forge/0.4 (+docs)"
TIMEOUT = 20
MAX_TOKENS = 4000


def _get(url: str, timeout: int = TIMEOUT) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers={
        "Accept": "application/json, text/plain",
        "User-Agent": UA,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        status = exc.code
    except (urllib.error.URLError, OSError) as exc:
        return 0, {"error": str(exc)}
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def search(query: str, limit: int = 8) -> dict[str, Any]:
    """Resolve a library name to Context7 project ids."""
    term = (query or "").strip()
    if not term:
        return {"ok": False, "err": "search needs a query", "results": []}
    status, payload = _get(f"{BASE}/api/search?query="
                           f"{urllib.parse.quote(term)}")
    if status != 200:
        return {"ok": False, "err": f"http {status}", "results": []}
    results = []
    for item in (payload.get("results") or [])[:limit]:
        settings = item.get("settings") or item
        results.append({
            "title": settings.get("title"),
            "project": settings.get("project") or item.get("project"),
            "description": settings.get("description"),
            "snippets": item.get("totalSnippets") or item.get("snippets"),
            "trust": (item.get("trustScore") or item.get("trust")),
        })
    return {"ok": True, "query": term, "results": results, "count": len(results)}


def show(project: str, topic: str | None = None, tokens: int = MAX_TOKENS,
         language: str | None = None) -> dict[str, Any]:
    """Fetch documentation for a project, optionally scoped to a topic."""
    slug = (project or "").strip().lstrip("/")
    if not slug:
        return {"ok": False, "err": "show needs a project id, e.g. "
                                    "websites/fastapi_tiangolo"}
    params = {"tokens": str(max(200, min(int(tokens), 8000)))}
    if topic:
        params["topic"] = topic
    if language:
        params["language"] = language
    status, payload = _get(f"{BASE}/api/v1/{urllib.parse.quote(slug, safe='/')}"
                           f"?{urllib.parse.urlencode(params)}")
    if status != 200:
        return {"ok": False, "err": f"http {status}", "project": slug}
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"ok": True, "project": slug, "topic": topic or "",
            "chars": len(text), "docs": text}


def resolve(query: str) -> dict[str, Any]:
    """Search, then return the best project id for `query`."""
    found = search(query, limit=5)
    if not found.get("results"):
        return {"ok": False, "err": "no library matched", "query": query}
    best = found["results"][0]
    return {"ok": True, "query": query, "project": best.get("project"),
            "title": best.get("title"), "alternatives": [
                {"project": r.get("project"), "title": r.get("title")}
                for r in found["results"][1:5]]}
