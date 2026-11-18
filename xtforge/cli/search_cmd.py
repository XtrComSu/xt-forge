"""`xtforge search` — unified federated search across code, memory, knowledge, web, and CVEs.

Bridges the gap between codebase navigation, durable memory, threat intelligence, and the web:
  - Code: ranked source lines matching the query (BM25 + declarations + error lines)
  - Memory: durable facts, architecture decisions, and procedures from mem.db
  - Flash: hot session working notes and pinned reminders
  - Knowledge: verified facts and problem recoveries
  - Recon: security and architectural findings
  - Web: live organic search results via local searchd (Google SERP) / SearXNG
  - Security / CVE: NVD vulnerabilities, EPSS exploit predictions, and CISA KEV catalog
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..core.route import pack, guard
from ..core import intel
from ..core.mcp_registry import search_tools
from .recall_cmd import _from_mem, _from_flash, _from_recon, _from_artifacts
from .common import _store, _flash

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _search_web(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Query web search via local searchd (127.0.0.1:8765) or optional SearXNG."""
    # 1. Try local searchd daemon (Google SERP via treg)
    searchd_host = os.environ.get("SEARCHD_HOST", "127.0.0.1")
    searchd_port = os.environ.get("SEARCHD_PORT", "8765")
    searchd_url = f"http://{searchd_host}:{searchd_port}/search"
    try:
        req = urllib.request.Request(
            searchd_url,
            data=json.dumps({"query": query, "count": limit}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            out = []
            for r in results:
                out.append({
                    "title": r.get("title") or "",
                    "url": r.get("url") or "",
                    "snippet": r.get("snippet") or "",
                    "date": r.get("date"),
                    "source": "google/searchd",
                })
            if out:
                return out
    except Exception:
        pass

    # 2. Try SearXNG if configured
    searxng = os.environ.get("SEARXNG_URL")
    if searxng:
        try:
            base = searxng.rstrip("/")
            q_enc = urllib.parse.quote(query)
            url = f"{base}/search?q={q_enc}&format=json&language=auto"
            req = urllib.request.Request(url, headers={"User-Agent": "xt-forge/0.4.2"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                out = []
                for r in data.get("results", [])[:limit]:
                    out.append({
                        "title": r.get("title") or "",
                        "url": r.get("url") or "",
                        "snippet": r.get("content") or "",
                        "source": "searxng",
                    })
                if out:
                    return out
        except Exception:
            pass

    return []


def _search_cve(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Search CVEs and security intelligence (NVD, EPSS, CISA KEV)."""
    out = []
    # If query is a direct CVE id
    cve_match = _CVE_PATTERN.search(query)
    if cve_match:
        cve_id = cve_match.group(0).upper()
        try:
            detail = intel.cve(cve_id)
            if detail.get("ok"):
                epss = detail.get("epss") or {}
                kev = detail.get("kev") or {}
                out.append({
                    "cve": cve_id,
                    "severity": detail.get("severity") or "UNKNOWN",
                    "cvss": detail.get("cvss"),
                    "epss_score": epss.get("score"),
                    "epss_percentile": epss.get("percentile"),
                    "kev_listed": kev.get("listed", False),
                    "kev_due": kev.get("due"),
                    "description": detail.get("description") or "",
                    "references": detail.get("references", [])[:3],
                })
                return out
        except Exception:
            pass

    # Keyword search across NVD & CISA KEV
    try:
        res = intel.search(query, limit=limit)
        for r in res.get("results", [])[:limit]:
            out.append({
                "cve": r.get("cve"),
                "severity": r.get("severity"),
                "cvss": r.get("score"),
                "published": r.get("published"),
                "description": r.get("description", "")[:200],
            })
    except Exception:
        pass

    # Also check CISA KEV catalog for matching software
    try:
        kev_res = intel.kev(query=query)
        if kev_res.get("matches"):
            for k in kev_res["matches"][:3]:
                if not any(o.get("cve") == k.get("cveID") for o in out):
                    out.append({
                        "cve": k.get("cveID"),
                        "severity": "CRITICAL",
                        "cvss": None,
                        "kev_listed": True,
                        "vendor_project": k.get("vendorProject"),
                        "product": k.get("product"),
                        "description": k.get("shortDescription", "")[:200],
                    })
    except Exception:
        pass

    return out


def _search_knowledge(db_path: str | Path | None, query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Search knowledge records in SQLite database."""
    import sqlite3
    db = str(db_path) if db_path else os.environ.get("XT_DB", str(Path.home() / ".xt-forge" / "mem.db"))
    if not os.path.isfile(db):
        return []
    try:
        conn = sqlite3.connect(db, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        q_tokens = [t for t in query.lower().split() if len(t) > 2]
        if not q_tokens:
            return []
        likes = " AND ".join("(lower(title) LIKE ? OR lower(body) LIKE ?)" for _ in q_tokens)
        params: list[str] = []
        for t in q_tokens:
            params.extend([f"%{t}%", f"%{t}%"])
        sql = f"SELECT id, title, body, kind, status, confidence, project, target FROM memory WHERE {likes} LIMIT {limit}"
        rows = cur.execute(sql, params).fetchall()
        out = []
        for r in rows:
            out.append({
                "store": "knowledge",
                "id": r["id"],
                "kind": r["kind"],
                "status": r["status"] or "observed",
                "title": r["title"] or "",
                "body": (r["body"] or "")[:200],
                "confidence": r["confidence"],
                "project": r["project"],
                "target": r["target"],
            })
        conn.close()
        return out
    except Exception:
        return []


def _search_code(root: str, query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Ranked code search across root using route pack."""
    try:
        canon = guard.read_guard(root)
        if not canon.exists():
            return []
        hits = pack.rank_lines(str(canon), query, limit=limit)
        out = []
        for h in hits:
            out.append({
                "path": h["path"],
                "line": h["line"],
                "text": h["text"].strip(),
                "score": h["score"],
                "error_line": h["error_line"],
            })
        return out
    except Exception:
        return []


def cmd_search(args) -> int:
    # Handle shorthand subcommands: `xtforge search web <query>` or `xtforge search cve <query>`
    val = (getattr(args, "value", None) or getattr(args, "query", None) or "").strip()
    path_arg = getattr(args, "path", None)
    
    # Check if first positional is a search mode
    web_flag = getattr(args, "web", False)
    cve_flag = getattr(args, "cve", False)
    tools_flag = getattr(args, "tools", False)
    all_flag = getattr(args, "all", False)

    if val.lower() in ("web", "google", "searchxng") and path_arg:
        web_flag = True
        query = path_arg
        path = "."
    elif val.lower() == "cve" and path_arg:
        cve_flag = True
        query = path_arg
        path = "."
    elif val.lower() in ("tool", "tools") and path_arg:
        tools_flag = True
        query = path_arg
        path = "."
    else:
        query = val
        path = path_arg or "."

    if not query:
        msg = "search requires a query string, e.g.: xtforge search 'pattern' or xtforge search --web 'query'"
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 2

    limit = max(1, min(int(getattr(args, "limit", 8) or 8), 50))
    stores_raw = getattr(args, "stores", None)
    
    if web_flag:
        stores = {"web"}
    elif cve_flag or _CVE_PATTERN.search(query):
        stores = {"cve", "mem", "knowledge"} if not cve_flag else {"cve"}
    elif tools_flag:
        stores = {"tools"}
    elif all_flag:
        stores = {"code", "mem", "flash", "knowledge", "recon", "web", "cve", "tools"}
    elif stores_raw:
        stores = {s.strip().lower() for s in stores_raw.split(",") if s.strip()}
    else:
        stores = {"code", "mem", "flash", "knowledge", "recon", "tools"}

    results: dict[str, list[dict[str, Any]]] = {}
    total = 0

    # 1. Code search
    if "code" in stores:
        code_hits = _search_code(path, query, limit=limit)
        results["code"] = code_hits
        total += len(code_hits)

    # 2. Durable Memory search
    if "mem" in stores:
        try:
            mem_hits, _ = _from_mem(_store(args), query, k=limit)
            results["mem"] = mem_hits
            total += len(mem_hits)
        except Exception:
            results["mem"] = []

    # 3. Knowledge search
    if "knowledge" in stores:
        know_hits = _search_knowledge(getattr(args, "db", None), query, limit=limit)
        results["knowledge"] = know_hits
        total += len(know_hits)

    # 4. Flash search
    if "flash" in stores:
        try:
            flash_hits, _ = _from_flash(_flash(args), query, limit=limit)
            results["flash"] = flash_hits
            total += len(flash_hits)
        except Exception:
            results["flash"] = []

    # 5. Recon search
    if "recon" in stores:
        try:
            recon_hits, _ = _from_recon(query, getattr(args, "target", None), limit=limit)
            results["recon"] = recon_hits
            total += len(recon_hits)
        except Exception:
            results["recon"] = []

    # 6. Web search (Google SERP / searchd / SearXNG)
    if "web" in stores:
        web_hits = _search_web(query, limit=limit)
        results["web"] = web_hits
        total += len(web_hits)

    # 7. Security / CVE intelligence (NVD / EPSS / KEV)
    if "cve" in stores:
        cve_hits = _search_cve(query, limit=limit)
        results["cve"] = cve_hits
        total += len(cve_hits)

    # 8. External MCP Tools & Capabilities
    if "tools" in stores:
        tool_hits = search_tools(query, limit=limit)
        if tool_hits:
            results["tools"] = tool_hits
            total += len(tool_hits)

    if getattr(args, "json", False):
        print(json.dumps({
            "ok": True,
            "query": query,
            "path": path,
            "stores": sorted(stores),
            "total": total,
            "results": results,
        }, indent=2))
        return 0

    # Formatted terminal output
    print(f"=== XT-Forge Search: \"{query}\" (total matches: {total}) ===\n")

    if results.get("cve"):
        print(f"🚨 Security & CVE Intelligence ({len(results['cve'])}):")
        for cv in results["cve"]:
            cve_id = cv.get("cve")
            sev = cv.get("severity") or "UNKNOWN"
            cvss = f" (CVSS {cv.get('cvss')})" if cv.get("cvss") is not None else ""
            kev_badge = " [CISA KEV EXPLOITED]" if cv.get("kev_listed") else ""
            epss_str = f" [EPSS {round(cv['epss_score'] * 100, 1)}%]" if cv.get("epss_score") is not None else ""
            print(f"  - [{sev}]{cvss}{kev_badge}{epss_str} {cve_id}:")
            desc = " ".join((cv.get("description") or "").split())[:140]
            print(f"    {desc}")
        print()

    if results.get("web"):
        print(f"🌐 Web Results ({len(results['web'])}):")
        for w in results["web"]:
            print(f"  - {w.get('title')}")
            print(f"    URL: {w.get('url')}")
            snippet = " ".join((w.get("snippet") or "").split())[:130]
            if snippet:
                print(f"    {snippet}")
        print()

    if results.get("code"):
        print(f"📁 Code Matches ({len(results['code'])}):")
        for c in results["code"]:
            err_badge = " [ERROR]" if c.get("error_line") else ""
            print(f"  {c['path']}:{c['line']}{err_badge}")
            print(f"    {c['text']}")
        print()

    if results.get("mem"):
        print(f"🧠 Durable Memory ({len(results['mem'])}):")
        for m in results["mem"]:
            scope = f"[{m.get('project') or 'global'}] " if m.get("project") else ""
            print(f"  - {scope}{m.get('title')}:")
            body_preview = " ".join((m.get("body") or "").split())[:120]
            print(f"    {body_preview}")
        print()

    if results.get("knowledge"):
        print(f"📖 Knowledge Records ({len(results['knowledge'])}):")
        for k in results["knowledge"]:
            status = f"[{k.get('status')}]"
            print(f"  - {status} {k.get('title')}:")
            body_preview = " ".join((k.get("body") or "").split())[:120]
            print(f"    {body_preview}")
        print()

    if results.get("flash"):
        print(f"⚡ Active Flash Notes ({len(results['flash'])}):")
        for f in results["flash"]:
            key = f"[{f.get('target') or f.get('title') or 'note'}] "
            text_preview = " ".join((f.get("body") or "").split())[:120]
            print(f"  - {key}{text_preview}")
        print()

    if results.get("recon"):
        print(f"🛡️ Recon Findings ({len(results['recon'])}):")
        for r in results["recon"]:
            print(f"  - {r.get('title')}")
        print()

    if results.get("tools"):
        print(f"🛠️ External MCP Tools & Capabilities ({len(results['tools'])}):")
        for t in results["tools"]:
            print(f"  - [{t.get('server')}] {t.get('title')}: {t.get('description')}")
            print(f"    Invocation: {t.get('invocation')}")
            for sub_t in t.get("tools", [])[:4]:
                print(f"      • {sub_t['name']}: {sub_t['description']}")
        print()

    if total == 0:
        print("No matches found across selected stores.")

    return 0
