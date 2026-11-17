"""`xtforge recall` — one query across every place knowledge is stored.

The environment keeps four stores that each answer a different question:

  mem      durable facts, decisions and procedures (typed, scoped)
  recon    findings and notes per investigation target
  flash    short-lived session state (TTL)
  errors   error-signature -> recovery guidance

Nothing was wrong with any of them individually. The gap was that an agent had
to *guess* which one to ask first, and a miss in one looked identical to "this
is not known anywhere". This command asks all of them and labels every row with
the store that produced it, so a single call gives an honest answer including
"nothing found".

Design notes:

- Read-only. It never writes to any store.
- Each source is called inside its own try/except: a broken or absent store
  degrades to a reported skip instead of failing the whole recall.
- Rows are deduplicated by a normalised content hash, so a fact that lives in
  two stores appears once with both sources named.
- The error store is only consulted when a query looks like an error (the
  caller passes --tool, or the text matches a tool/error shape); otherwise
  querying it would be noise.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time


def _norm(text: str) -> str:
    """Collapse whitespace/case so the same fact from two stores dedupes."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _fp(text: str) -> str:
    return hashlib.sha256(_norm(text).encode("utf-8")).hexdigest()[:16]


def _row(store: str, kind: str, title: str, body: str, **extra) -> dict:
    return {
        "store": store,
        "kind": kind,
        "title": title or "",
        "body": body or "",
        "sources": [store],
        "project": extra.pop("project", None),
        "target": extra.pop("target", None),
        "freshness": extra.pop("freshness", None),
        "partial": False,
        "fingerprint": _fp((title or "") + "\n" + (body or "")),
        # Body-only identity, so the same fact stored under different names in
        # two stores still collapses to one row.
        "body_fp": _fp(body or "") if (body or "").strip() else "",
        **extra,
    }


def _freshness(ts) -> str | None:
    """Age of a record as a coarse, honest label rather than a fake precision."""
    try:
        age = max(0, int(time.time()) - int(ts))
    except (TypeError, ValueError):
        return None
    for limit, label in ((3600, "fresh"), (86400, "recent"),
                         (7 * 86400, "this week"), (30 * 86400, "this month")):
        if age < limit:
            return label
    return "older"


def _from_mem(store, query: str, k: int) -> tuple[list[dict], str | None]:
    from ..core.mem.search import search as memsearch

    try:
        res = memsearch(store, query, k=k, token_budget=max(400, k * 220))
    except Exception as exc:  # noqa: BLE001 - degrade, never fail the recall
        return [], f"mem: {type(exc).__name__}: {exc}"
    out = []
    for hit in (res.get("results") or res.get("hits") or []):
        rec = hit.get("record") or hit
        out.append(_row(
            "mem",
            rec.get("kind") or "fact",
            rec.get("title") or "",
            rec.get("body") or "",
            scope=rec.get("scope"),
            record_id=rec.get("id"),
            confidence=rec.get("confidence"),
            project=rec.get("scope"),
            freshness=_freshness(rec.get("updated") or rec.get("created")),
        ))
    return out, None


def _from_recon(query: str, target: str | None, limit: int) -> tuple[list[dict], str | None]:
    from ..core import recon as reconmod

    if not target:
        return [], "recon: skipped (no --target; findings are keyed by target)"
    try:
        data = reconmod.ledger(target)
    except Exception as exc:  # noqa: BLE001
        return [], f"recon: {type(exc).__name__}: {exc}"
    needle = _norm(query)
    rows = []
    for kind, items in (("finding", data.get("findings") or []),
                        ("note", data.get("notes") or [])):
        for item in items:
            blob = _norm(json.dumps(item, ensure_ascii=False))
            if needle and needle not in blob:
                continue
            rows.append(_row(
                "recon", kind,
                item.get("title") or item.get("text") or "",
                item.get("detail") or item.get("evidence") or "",
                severity=item.get("severity"),
                target=data.get("target"),
                freshness=_freshness(item.get("ts") or item.get("at")),
            ))
    return rows[:limit], None


def _from_flash(flash, query: str, limit: int) -> tuple[list[dict], str | None]:
    """Read flash notes.

    Flash records are compact: `k` is the key, `v` the text, `ts`/`ttl_s` the
    lifetime, `pin` the pin flag. Reading `key`/`text` here silently matched
    nothing, which is exactly the failure mode this command exists to remove,
    so the aliases are handled explicitly.
    """
    try:
        notes = flash.list(n=limit)
    except TypeError:
        try:
            notes = flash.list()
        except Exception as exc:  # noqa: BLE001
            return [], f"flash: {type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return [], f"flash: {type(exc).__name__}: {exc}"
    needle = _norm(query)
    rows = []
    for note in notes or []:
        key = note.get("k") or note.get("key") or note.get("id") or ""
        text = note.get("v") or note.get("text") or note.get("value") or ""
        blob = _norm(f"{key} {text} {json.dumps(note.get('tags') or [], ensure_ascii=False)}")
        if needle and needle not in blob:
            continue
        rows.append(_row("flash", "session", key, text,
                         pinned=note.get("pin"),
                         ttl_s=note.get("ttl_s"),
                         freshness=_freshness(note.get("ts"))))
    return rows[:limit], None


def _from_artifacts(query: str, roots: list[str] | None, limit: int) -> tuple[list[dict], str | None]:
    """Find recorded artifacts whose path or producer matches the query.

    An artifact sidecar records that a produced file was checked. Without this
    adapter the record exists but nothing can find it, which makes it as good
    as absent. Search is over the sidecars under the given roots (default: the
    caller's directory), never over the filesystem at large.

    Cost matters here because this runs at the start of a turn. Two bounds:

    - The sidecar index (maintained by `artifact.record`) answers without
      touching the tree at all. That is the normal path.
    - The walk behind it is pruned (dependency caches, VCS, virtualenvs are
      skipped - a sidecar never lives there) and carries a deadline. A bounded
      walk that ends early reports `partial` instead of silently pretending the
      tree was fully searched.
    """
    from ..core import artifact as art

    bases = roots or [os.environ.get("XT_INVOKE_CWD") or os.getcwd()]
    # The launcher `cd`s into the tool root, so a caller-supplied relative root
    # must be resolved against where they actually ran, not against the tool.
    cwd = os.environ.get("XT_INVOKE_CWD") or os.getcwd()
    bases = [b if os.path.isabs(b) else os.path.abspath(os.path.join(cwd, b))
             for b in bases]
    needle = _norm(query)
    rows: list[dict] = []

    def consider(sidecar: str) -> bool:
        """Add one sidecar's row. True once `limit` rows are collected."""
        target = sidecar[: -len(art.SIDECAR_SUFFIX)]
        try:
            data = art.read(target)
        except art.ArtifactError:
            return False
        if data is None:
            return False
        blob = _norm(f"{target} {data.get('producer') or ''} {data.get('mediaType') or ''}")
        if needle and needle not in blob:
            return False
        status, reason = art.effective_status(target, data)
        rows.append(_row(
            "artifact", "file", os.path.basename(target),
            f"{status}: {reason}",
            path=target,
            status=status,
            checks=len(data.get("checks") or []),
            producer=data.get("producer") or None,
        ))
        return len(rows) >= limit

    # Fast path: the index knows where every recorded sidecar is.
    for sidecar in art.indexed_sidecars(bases):
        if consider(sidecar):
            return rows, None
    if rows:
        return rows, None

    # A root already walked to completion has its sidecars in the index, so a
    # second walk would re-derive what is already known. Skip it; a new sidecar
    # writes an index line the moment it is recorded.
    if art.scanned_recently(bases):
        return rows, None

    # Fallback: walk, but pruned and bounded by a wall clock.
    budget = float(os.environ.get("XT_ARTIFACT_WALK_BUDGET") or 2.0)
    deadline = time.monotonic() + budget
    walked: list[str] = []
    for base in bases:
        found = _walk_sidecars(base, deadline)
        walked.extend(found)
        for sidecar in found:
            if consider(sidecar):
                return rows, None
    if time.monotonic() > deadline:
        return rows, ("artifacts: search ended at its time budget; "
                      "some sidecars were not examined")
    # The walk finished: remember its result so the next call is index-only.
    art.mark_scanned(bases, walked)
    return rows, None


# Directory names that never hold artifact sidecars but dominate a home
# directory walk. Pruned by name, so the cost stays independent of how much
# dependency junk the tree carries.
_PRUNE_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".venv", "venv", ".tox", "dist", "build",
    ".npm", ".bun", ".cargo", ".rustup", ".gradle", ".m2", ".cache",
    ".local", ".venvs", ".nvm", ".pyenv", ".conda", "site-packages",
    "snap", ".Trash", ".trash", ".mozilla", ".android", ".ollama",
})


def _walk_sidecars(base: str, deadline: float) -> list[str]:
    """Sidecar paths under `base`, newest-first, pruned and deadline-bounded.

    A plain `glob(**)` on a home directory takes minutes because it descends
    into every dependency cache. This walks the same tree once, skips the
    directories that cannot contain a sidecar, and stops at the deadline.
    """
    found: list[tuple[float, str]] = []
    try:
        for root, dirs, files in os.walk(base, onerror=lambda _e: None, followlinks=False):
            if time.monotonic() > deadline:
                break
            dirs[:] = [d for d in dirs if d not in _PRUNE_DIRS and not d.startswith(".git")]
            for name in files:
                if not name.endswith(art_suffix()):
                    continue
                path = os.path.join(root, name)
                try:
                    found.append((os.stat(path).st_mtime, path))
                except OSError:
                    continue
    except OSError:
        pass
    found.sort(reverse=True)
    return [p for _m, p in found]


def art_suffix() -> str:
    from ..core.artifact import SIDECAR_SUFFIX
    return SIDECAR_SUFFIX


def _from_errors(tool: str | None, query: str) -> tuple[list[dict], str | None]:
    """Consult error memory only when the query looks like an error."""
    if not tool:
        return [], "errors: skipped (no --tool given)"
    # Error memory is an optional external layer, not part of this package.
    # Look for it where the operator says, then in a sibling checkout; if it is
    # absent, say so rather than failing the whole recall.
    errdir = os.environ.get("XT_ERROR_MEMORY_DIR")
    if not errdir:
        for cand in (os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                  "..", "..", "error-memory")),
                     os.path.expanduser("~/workspace/dsh-overhaul/error-memory")):
            if os.path.exists(os.path.join(cand, "error_memory.py")):
                errdir = cand
                break
    if not errdir:
        return [], "errors: skipped (error-memory layer not found; set XT_ERROR_MEMORY_DIR)"
    if errdir not in sys.path:
        sys.path.insert(0, errdir)
    try:
        import error_memory as em
    except Exception as exc:  # noqa: BLE001
        return [], f"errors: {type(exc).__name__}: {exc}"
    try:
        res = em.lookup(tool, query)
    except Exception as exc:  # noqa: BLE001
        return [], f"errors: {type(exc).__name__}: {exc}"
    if not res.get("found"):
        return [], None
    return [_row("errors", "recovery",
                 f"{tool}: {res.get('class') or 'unknown'}",
                 res.get("guidance") or "",
                 usable=res.get("usable"),
                 confidence=res.get("confidence"),
                 caveats=res.get("caveats") or [])], None


_STOP = {"the", "a", "an", "of", "to", "in", "is", "it", "and", "or", "for",
         "on", "with", "this", "that", "be", "as", "at", "by", "from", "how",
         "what", "why", "when", "does", "do", "not", "no"}


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_]{3,}", (text or "").lower())
            if w not in _STOP}


def _relevant(rows: list[dict], query: str) -> list[dict]:
    """Keep rows sharing enough of the query to be a real match.

    A BM25 store always returns *something*; for a cross-store recall that is a
    false positive, and a false positive here is worse than a miss because it
    reads as "this is known". An explicit miss is the honest answer.

    Coverage, not presence: a single common word ("does nothing" matching a
    query containing "nothing") must not qualify. A row is kept when it shares
    at least a third of the query's content tokens, which for a one- or
    two-word query means that one real word must match.
    """
    import math

    q = _tokens(query)
    if not q:
        return rows
    need = max(1, math.ceil(len(q) / 3))
    keep = []
    for row in rows:
        hay = _tokens(f"{row.get('title','')} {row.get('body','')}")
        if len(q & hay) >= need:
            keep.append(row)
    return keep


def merge(rows: list[dict]) -> list[dict]:
    """Deduplicate by content; a fact present in two stores cites both.

    Two keys, because stores name things differently:

    - `fingerprint` is title+body, exact. Catches a true duplicate.
    - `body_fp` is body-only. Two stores will almost never agree on a *title*
      (one has a record title, the other a flash key), so title+body alone
      never collapses a cross-store duplicate. Body-only does.

    A row merges when either key matches. The merged row keeps both sources, so
    the caller can see that two stores agree - which is itself evidence.
    """
    by_fp: dict[str, dict] = {}
    by_body: dict[str, dict] = {}
    out: list[dict] = []
    for row in rows:
        existing = by_fp.get(row["fingerprint"]) or (by_body.get(row["body_fp"]) if row.get("body_fp") else None)
        if existing is not None:
            for src in row["sources"]:
                if src not in existing["sources"]:
                    existing["sources"].append(src)
            continue
        by_fp[row["fingerprint"]] = row
        if row.get("body_fp"):
            by_body[row["body_fp"]] = row
        out.append(row)
    return out


def cmd_recall(args) -> int:
    from .common import _store, _flash

    query = (getattr(args, "value", None) or getattr(args, "query", None) or "").strip()
    if not query:
        msg = "recall needs a query"
        print(json.dumps({"ok": False, "error": msg}) if getattr(args, "json", False) else msg,
              file=sys.stdout if getattr(args, "json", False) else sys.stderr)
        return 2

    k = max(1, min(int(getattr(args, "k", 5) or 5), 25))
    limit = max(1, min(int(getattr(args, "limit", 10) or 10), 50))
    want = {s.strip() for s in (getattr(args, "store", None) or "mem,recon,flash,errors,artifacts").split(",") if s.strip()}
    # `mem` is a BM25/vector search and will return *something* for almost any
    # input (its own fallback). For a cross-store recall that reads as a false
    # positive, so rows are kept only when they share a real token with the
    # query. Set --loose to accept the store's own ranking unfiltered.
    loose = bool(getattr(args, "loose", False))

    rows: list[dict] = []
    skips: list[str] = []

    if "mem" in want:
        r, err = _from_mem(_store(args), query, k)
        rows += r
        if err: skips.append(err)
    if "recon" in want:
        r, err = _from_recon(query, getattr(args, "target", None), limit)
        rows += r
        if err: skips.append(err)
    if "flash" in want:
        r, err = _from_flash(_flash(args), query, limit)
        rows += r
        if err: skips.append(err)
    if "errors" in want:
        r, err = _from_errors(getattr(args, "tool", None), query)
        rows += r
        if err: skips.append(err)
    if "artifacts" in want:
        r, err = _from_artifacts(query, getattr(args, "artifacts_root", None), limit)
        rows += r
        if err: skips.append(err)

    merged = merge(rows)
    if not loose:
        before = len(merged)
        merged = _relevant(merged, query)
        dropped = before - len(merged)
        if dropped:
            skips.append(f"relevance filter: dropped {dropped} unrelated row(s); "
                         "use --loose to see the stores' raw ranking")

    # A hard output bound, expressed in characters rather than tokens: the
    # caller asked for a bounded answer, and characters are what we can measure
    # without a tokenizer. Truncation is reported, never silent.
    budget = int(getattr(args, "budget_chars", 0) or 0)
    truncated = 0
    if budget > 0:
        kept, used = [], 0
        for row in merged:
            cost = len(row.get("title") or "") + len(row.get("body") or "") + 120
            if used + cost > budget:
                truncated += 1
                continue
            used += cost
            kept.append(row)
        merged = kept

    # Partial-store reporting: which stores answered, which degraded, and
    # whether the answer is therefore incomplete.
    answered = sorted({r["store"] for r in merged})
    # Three different things hide behind "skips":
    #   "X: skipped (...)"  -> the store did not apply (no target, no tool).
    #                          Not a degradation: nothing failed.
    #   "relevance filter"  -> a deliberate narrowing, reported separately.
    #   anything else       -> the store failed; the answer is incomplete.
    not_applicable = [s2 for s2 in skips if ": skipped" in s2]
    degraded = [s2 for s2 in skips
                if ": skipped" not in s2 and not s2.startswith("relevance filter")]
    partial = bool(degraded) or truncated > 0
    for row in merged:
        row["partial"] = partial

    if getattr(args, "json", False):
        print(json.dumps({
            "ok": True,
            "query": query,
            "searched": sorted(want),
            "answered": answered,
            "degraded": degraded,
            "notApplicable": not_applicable,
            "partial": partial,
            "truncated": truncated,
            "count": len(merged),
            "results": merged,
        }, indent=2, ensure_ascii=False))
        return 0

    print(f"recall: {query!r}   searched: {', '.join(sorted(want))}")
    if not merged:
        # An explicit miss is the whole point: silence read as "unknown" before.
        print("  no match in any store")
        if degraded:
            print(f"  (partial: {', '.join(degraded)})")
        for s in skips:
            print(f"  ! {s}")
        return 0
    for row in merged:
        src = "+".join(row["sources"])
        print(f"\n  [{src}] {row['kind']}: {row['title'][:110]}")
        body = row["body"].strip().replace("\n", " ")
        if body:
            print(f"      {body[:300]}")
        extra = {k2: v for k2, v in row.items()
                 if k2 not in ("store", "kind", "title", "body", "sources", "fingerprint")
                 and v not in (None, "", [])}
        if extra:
            print(f"      ({', '.join(f'{k2}={v}' for k2, v in extra.items())})")
    if partial:
        print(f"\n  NOTE: this answer is PARTIAL"
              f"{' (truncated ' + str(truncated) + ' row(s))' if truncated else ''}"
              f"{' (degraded: ' + ', '.join(degraded) + ')' if degraded else ''}")
    for s in skips:
        print(f"\n  ! {s}")
    return 0
