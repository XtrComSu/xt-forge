"""Memory retrieval: BM25 (FTS5) or trigram LIKE fallback, budget-packed (F2).

Score components (explain=True): text, recency, pin, uses.

Hybrid mode (`hybrid=True`, default) blends the lexical score with a local
embedding similarity and lets semantic-only matches enter the candidate set.
When no embedding is available or produces no match, the result is exactly the
lexical ranking — the FTS-only path is not re-tuned.
"""
from __future__ import annotations

import math
import re
import time
from typing import Any

from .embed import Embedder, VectorIndex
from .scopes import read_order
from .store import Store, trigrams

MAX_BODY_CHARS = 300
_TOKEN = re.compile(r"[a-z0-9_]{2,}", re.IGNORECASE)
DAY = 86400.0

W_TEXT = 1.0
W_RECENCY = 0.35
W_PIN = 0.5
W_USE = 0.15
RRF_K = 60          # reciprocal-rank-fusion constant
_SEMANTIC_CAP = 2000  # records considered by the vector pass


def _ranks(scores: dict[str, float]) -> dict[str, int]:
    """1-based rank by descending score; ties broken by id for determinism."""
    order = sorted(scores, key=lambda rid: (-scores[rid], rid))
    return {rec_id: index for index, rec_id in enumerate(order, start=1)}


def _fuse(lexical: dict[str, float], semantic: dict[str, float]) -> dict[str, float]:
    """Reciprocal rank fusion: scale-free, so a noisy lexical magnitude cannot
    bury a correct semantic hit. A candidate absent from one list simply
    collects one term instead of two."""
    lex_rank, sem_rank = _ranks(lexical), _ranks(semantic)
    out: dict[str, float] = {}
    for rec_id in set(lex_rank) | set(sem_rank):
        total = 0.0
        if rec_id in lex_rank:
            total += 1.0 / (RRF_K + lex_rank[rec_id])
        if rec_id in sem_rank:
            total += 1.0 / (RRF_K + sem_rank[rec_id])
        out[rec_id] = total
    return out


def est_tokens(text: str) -> int:
    """Cheap 4-chars-per-token estimate."""
    return max(0, (len(text or "") + 3) // 4)


def inject_line(rec: dict[str, Any], body_chars: int = MAX_BODY_CHARS) -> str:
    body = (rec.get("body") or "")[:body_chars].replace("\n", " ")
    return f"[MEM:{rec['id']}|{rec['kind']}|{rec['scope']}] {rec.get('title','')}: {body}"


def _fts_query(q: str) -> str:
    toks = _TOKEN.findall(q.lower())
    if not toks:
        return ""
    return " OR ".join(f'"{t}"' for t in toks)


def _boosts(rec: dict[str, Any], t: float) -> dict[str, float]:
    created = rec.get("created") or t
    age_days = max(0.0, (t - created) / DAY)
    recency = math.exp(-age_days / 30.0)
    uses = rec.get("uses") or 0
    return {
        "pin": W_PIN if rec.get("pin") else 0.0,
        "recency": W_RECENCY * recency,
        "use": W_USE * math.log1p(uses),
    }


def _scope_rank(rec_scope: str, order: list[str]) -> float:
    try:
        return float(len(order) - order.index(rec_scope))
    except ValueError:
        return 0.0


def _vector_index(store: Store, embedder: Embedder) -> VectorIndex:
    """Cached per store, invalidated by row count and newest update."""
    row = store.conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(MAX(updated), 0) AS u FROM mem").fetchone()
    key = (row["n"], row["u"])
    cached = getattr(store, "_vec_index", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    index = VectorIndex(embedder)
    for rec in store.conn.execute(
            "SELECT id, title, body, tags FROM mem LIMIT ?",
            (_SEMANTIC_CAP,)).fetchall():
        index.add(rec["id"], f"{rec['title']}\n{rec['body']}\n{rec['tags']}")
    store._vec_index = (key, index)  # type: ignore[attr-defined]
    return index


def search(store: Store, query: str, scopes: list[str] | None = None, k: int = 5,
           token_budget: int = 800, session_id: str | None = None,
           workflow_id: str | None = None, project: str | None = None,
           explain: bool = False, kinds: list[str] | None = None,
           include_pending: bool = False, hybrid: bool = True,
           embedder: Embedder | None = None) -> dict[str, Any]:
    t = time.time()
    order = scopes or read_order(session_id, workflow_id, project)
    hits: dict[str, dict[str, Any]] = {}
    text_scores: dict[str, float] = {}

    if store.fts and query.strip():
        fq = _fts_query(query)
        if fq:
            sql = ("SELECT rowid, bm25(mem_fts) AS rank FROM mem_fts WHERE mem_fts MATCH ? "
                   "ORDER BY rank LIMIT ?")
            try:
                rows = store.conn.execute(sql, (fq, max(k * 8, 50))).fetchall()
            except Exception:
                rows = []
            for r in rows:
                rec = store.conn.execute("SELECT * FROM mem WHERE rowid=?", (r["rowid"],)).fetchone()
                if rec:
                    rec = dict(rec)
                    # bm25 returns lower-is-better; normalize.
                    text_scores[rec["id"]] = -float(r["rank"])
                    hits[rec["id"]] = rec
    elif not store.fts and query.strip():
        q_tr = set(trigrams(query).split())
        rows = store.conn.execute("SELECT * FROM mem LIMIT 2000").fetchall()
        for row in rows:
            rec = dict(row)
            cand = set(trigrams(f"{rec['title']} {rec['body']} {rec['tags']}").split())
            if not cand:
                continue
            inter = len(q_tr & cand)
            if inter:
                rec_id = rec["id"]
                text_scores[rec_id] = inter / len(q_tr | cand)
                hits[rec_id] = rec

    if not query.strip():
        ph = ",".join("?" * len(order))
        rows = store.conn.execute(
            f"SELECT * FROM mem WHERE scope IN ({ph}) ORDER BY pin DESC, updated DESC LIMIT ?",
            (*order, max(k * 8, 50))).fetchall()
        for row in rows:
            rec = dict(row)
            text_scores[rec["id"]] = 1.0
            hits[rec["id"]] = rec

    # Semantic pass: additive. It can only add candidates and re-rank; when it
    # contributes nothing the scoring below is the original lexical one.
    semantic_scores: dict[str, float] = {}
    embedder = embedder if embedder is not None else Embedder()
    use_hybrid = bool(hybrid and query.strip() and embedder.available)
    if use_hybrid:
        index = _vector_index(store, embedder)
        semantic_scores = dict(index.query(query, k=max(k * 8, 50)))
        for rec_id in semantic_scores:
            if rec_id not in hits:
                rec = store.get(rec_id)
                if rec:
                    hits[rec_id] = rec
                    text_scores.setdefault(rec_id, 0.0)
        use_hybrid = bool(semantic_scores)
    fused_scores: dict[str, float] = {}
    fused_max = 0.0
    if use_hybrid:
        lexical_only = {rid: score for rid, score in text_scores.items()
                        if score > 0}
        fused_scores = _fuse(lexical_only, semantic_scores)
        fused_max = max(fused_scores.values(), default=0.0)

    scored: list[dict[str, Any]] = []
    for rec_id, rec in hits.items():
        if rec["scope"] not in order:
            continue
        if not include_pending and rec.get("pending"):
            continue
        if kinds and rec["kind"] not in kinds:
            continue
        comp = _boosts(rec, t)
        scope_w = _scope_rank(rec["scope"], order) / max(1, len(order))
        text = text_scores.get(rec_id, 0.0)
        boosts = comp["pin"] + comp["recency"] + comp["use"] + 0.5 * scope_w
        if use_hybrid:
            semantic = semantic_scores.get(rec_id, 0.0)
            blended = (fused_scores.get(rec_id, 0.0) / fused_max) if fused_max else 0.0
            total = W_TEXT * blended + boosts
        else:
            semantic = 0.0
            blended = 0.0
            total = W_TEXT * text + boosts
        if explain:
            rec = dict(rec)
            rec["_explain"] = {"text": round(text, 4),
                               "semantic": round(semantic, 4),
                               "blended": round(blended, 4),
                               "recency": round(comp["recency"], 4),
                               "pin": round(comp["pin"], 4),
                               "uses": round(comp["use"], 4),
                               "scope": round(scope_w, 4),
                               "total": round(total, 4)}
        scored.append((total, rec))

    scored.sort(key=lambda x: (-x[0], x[1].get("pin", 0), -(x[1].get("updated") or 0)))
    results: list[dict[str, Any]] = []
    used = 0
    for _, rec in scored:
        line = inject_line(rec)
        cost = est_tokens(line)
        if used + cost > token_budget and results:
            break
        used += cost
        results.append({"record": rec, "line": line, "tokens": cost})
        if len(results) >= k:
            break
    return {"results": results, "tokens_used": used,
            "fts_mode": "fts5" if store.fts else "like_trigram",
            "hybrid": use_hybrid, "embed_mode": embedder.backend,
            "scopes": order, "truncated": len(scored) > len(results)}