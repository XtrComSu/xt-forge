"""Unified multi-source research dossier orchestrator (Python fallback)."""
from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..version import xt_home
from .mem.scopes import project_scope
from .mem.search import search as mem_search
from .mem.store import Store
from .route import guard, pack


def run_research(
    topic: str,
    *,
    root: str | Path = ".",
    k: int = 5,
    save_dossier: bool = False,
) -> dict[str, Any]:
    """Fan out across memory, symbol/code context, and return one deduplicated dossier."""
    t0 = time.monotonic()
    topic = topic.strip()
    if not topic:
        return {"ok": False, "err": "research requires a non-empty topic"}
    canon = guard.read_guard(root)

    def _query_mem() -> list[dict[str, Any]]:
        db = xt_home() / "mem.db"
        if not db.is_file():
            return []
        st = Store(db)
        try:
            scopes = [project_scope(str(canon)), "global"]
            res = mem_search(st, query=topic, scopes=scopes, k=k, token_budget=900)
            return [r["record"] for r in res.get("results") or []]
        finally:
            st.close()

    def _query_code() -> list[dict[str, Any]]:
        res = pack.pack(str(canon), topic, token_budget=900, file_limit=6, use_symbols=True)
        if not res.get("ok"):
            return []
        return list((res.get("data") or {}).get("evidence") or [])

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_mem = pool.submit(_query_mem)
        f_code = pool.submit(_query_code)
        mem_hits = f_mem.result()
        code_hits = f_code.result()

    summary_lines = [f"TOPIC: {topic}", f"ROOT: {canon}",
                     f"MEMORY HITS: {len(mem_hits)}", f"CODE EVIDENCE: {len(code_hits)}"]
    for m in mem_hits[:k]:
        summary_lines.append(f"- [MEM:{m.get('kind')}] {m.get('title')}: {str(m.get('body', ''))[:140]}")
    for c in code_hits[:k]:
        summary_lines.append(f"- [CODE] {c.get('path')}:L{c.get('line')}")
    dossier_text = "\n".join(summary_lines)

    saved_path = None
    if save_dossier:
        ddir = xt_home() / "research"
        ddir.mkdir(parents=True, exist_ok=True)
        slug = hashlib.sha256(topic.encode("utf-8")).hexdigest()[:12]
        out_file = ddir / f"dossier_{slug}.md"
        out_file.write_text(dossier_text + "\n", encoding="utf-8")
        saved_path = str(out_file)

    return {
        "ok": True,
        "topic": topic,
        "root": str(canon),
        "memory_count": len(mem_hits),
        "code_count": len(code_hits),
        "memory_hits": mem_hits[:k],
        "code_evidence": code_hits[:k],
        "dossier": dossier_text,
        "saved_path": saved_path,
        "ms": int((time.monotonic() - t0) * 1000),
        "engine": "python",
    }
