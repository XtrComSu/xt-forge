"""Knowledge records: status, evidence, verification, and revision history.

Why this is a layer over `mem` rather than a new table
-------------------------------------------------------
`mem` already stores, scopes, dedupes, indexes and searches records. What it
lacked was the vocabulary to say *how much a record should be believed*: every
row looked equally authoritative, so a passing idea read the same as a fix that
had been executed and confirmed.

This module adds that vocabulary without a parallel store:

    status        observed | proposed | verified | contradicted | superseded | obsolete
    evidence      free-form source references
    verification  {method, result, ...} - how the claim was checked
    author        which agent wrote it
    project/target scope identity
    versions/environment  where it applies

The rule that matters
---------------------
An agent cannot promote a record to `verified` by labelling it. `verify()`
demands a `method` and a `result` and, for an executed check, a `checker` or an
`exit_status`. A bare assertion lands as `proposed` with a note saying so. This
mirrors the artifact sidecar rule, deliberately: the same distinction between
"someone said so" and "something ran" applies to knowledge as to files.
"""

from __future__ import annotations

import json
import time
from typing import Any

STATUSES = ("observed", "proposed", "verified", "contradicted",
            "superseded", "obsolete")

#: Statuses an agent may assert directly. `verified` is deliberately absent:
#: it is reachable only through verify(), which requires a method and result.
AGENT_ASSERTABLE = frozenset({"observed", "proposed"})

#: Knowledge kinds are a richer vocabulary than `mem`'s storage kinds. Each
#: maps onto one of the existing `mem` kinds so the FTS index, scoping, dedupe
#: and links all keep working, and so a v1 database needs no enum change.
KIND_TO_MEM = {
    "fact": "fact",
    "decision": "decision",
    "procedure": "procedure",
    "error_pattern": "error_pattern",
    "problem": "error_pattern",
    "recovery": "procedure",
    "design": "snippet",
    "design_antipattern": "snippet",
    "discovery": "fact",
    "environment": "fact",
    "example": "snippet",
}

KINDS = tuple(KIND_TO_MEM)


class KnowledgeError(ValueError):
    """A caller error in a knowledge operation."""


def _store(path: str | None):
    from .store import Store
    from ...version import db_path
    return Store(path or str(db_path()))


def _row_to_record(row) -> dict[str, Any]:
    d = dict(row)
    if d.get("status") is None:
        # A v1 row predates the lifecycle. It is still a fact someone asserted;
        # do not invent "verified" for it.
        d["status"] = "observed"
        d["statusInferred"] = True
    for key in ("verification",):
        if isinstance(d.get(key), str):
            try:
                d[key] = json.loads(d[key])
            except (ValueError, TypeError):
                pass
    return d


def put(*, kind: str, title: str, body: str, scope: str = "global",
        status: str = "proposed", project: str | None = None,
        target: str | None = None, evidence: str | None = None,
        author: str | None = None, versions: list[str] | None = None,
        environment: str | None = None, tags: list[str] | None = None,
        path: str | None = None) -> dict[str, Any]:
    """Create a knowledge record at an agent-assertable status."""
    if kind not in KINDS:
        raise KnowledgeError(f"unknown kind {kind!r}; expected one of {list(KINDS)}")
    if status not in AGENT_ASSERTABLE:
        raise KnowledgeError(
            f"an agent may assert {sorted(AGENT_ASSERTABLE)}, not {status!r}. "
            "Use `knowledge verify` with a method and result to reach 'verified'.")
    if not (title or "").strip():
        raise KnowledgeError("title is required")
    st = _store(path)
    payload = {
        "kind": kind, "memKind": KIND_TO_MEM[kind],
        "title": title.strip(), "body": (body or "").strip(),
        "status": status, "project": project, "target": target,
        "evidence": evidence, "author": author,
        "versions": versions or [], "environment": environment,
    }
    res = st.put(scope=scope, kind=KIND_TO_MEM[kind], title=payload["title"],
                 body=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                 tags=tags or [], source=author or "agent",
                 confidence=0.4 if status == "proposed" else 0.6)
    _update_columns(st, res.get("id"), payload, status=status)
    return {"id": res.get("id"), "action": res.get("action"),
            "status": status, "kind": kind, "title": payload["title"],
            "notes": res.get("notes") or []}


def _update_columns(st, rec_id: str | None, payload: dict[str, Any],
                    status: str) -> None:
    if not rec_id:
        return
    st.conn.execute(
        "UPDATE mem SET status=?, evidence=?, author=?, target=?, project=?, "
        "versions=?, environment=? WHERE id=?",
        (status, payload.get("evidence"), payload.get("author"),
         payload.get("target"), payload.get("project"),
         json.dumps(payload.get("versions") or [], ensure_ascii=False),
         payload.get("environment"), rec_id))
    st.conn.commit()


def get(rec_id: str, *, path: str | None = None) -> dict[str, Any] | None:
    st = _store(path)
    row = st.conn.execute("SELECT * FROM mem WHERE id=?", (rec_id,)).fetchone()
    return _row_to_record(row) if row else None


def verify(rec_id: str, *, method: str, result: str,
           checker: str | None = None, exit_status: int | None = None,
           evidence: str | None = None, verified_status: str = "verified",
           path: str | None = None) -> dict[str, Any]:
    """Attach a verification to a record and move its status.

    `method` names how it was checked; `result` says what happened. A
    verification claiming execution must supply a checker or exit status,
    otherwise it is recorded as an attributed assertion rather than a check.
    """
    if verified_status not in ("verified", "contradicted"):
        raise KnowledgeError("verified_status must be 'verified' or 'contradicted'")
    if not (method or "").strip():
        raise KnowledgeError("a verification needs a method describing how it was checked")
    if result not in ("pass", "fail", "inconclusive"):
        raise KnowledgeError("result must be pass|fail|inconclusive")

    executed = bool((checker or "").strip()) or exit_status is not None
    st = _store(path)
    row = st.conn.execute("SELECT * FROM mem WHERE id=?", (rec_id,)).fetchone()
    if row is None:
        raise KnowledgeError(f"no record {rec_id}")
    rec = dict(row)
    try:
        body = json.loads(rec.get("body") or "{}")
    except (ValueError, TypeError):
        body = {}

    record = {
        "method": method.strip(),
        "result": result,
        "checker": checker or None,
        "exitStatus": exit_status,
        "evidence": evidence,
        "executed": executed,
        "at": int(time.time()),
    }
    history = body.get("verifications") or []
    history.append(record)
    body["verifications"] = history

    status = verified_status if (result == "pass" and executed) else (
        "contradicted" if result == "fail" else rec.get("status") or "observed")
    if result == "pass" and not executed:
        # An attributed assertion is not a check. Say so in the record.
        status = rec.get("status") or "observed"
        body["verificationCaveat"] = (
            "pass recorded without an executed check; status not promoted")

    # Confidence must move in the direction the evidence points. A failed
    # recovery that leaves confidence untouched would keep recommending advice
    # that has already been shown not to work.
    prior = float(rec.get("confidence") or 0.5)
    if status == "verified":
        confidence = min(0.95, max(prior, 0.85))
    elif status == "contradicted":
        confidence = max(0.05, prior - 0.35)
    else:
        confidence = prior
    st.conn.execute(
        "UPDATE mem SET body=?, status=?, verification=?, updated=?, "
        "confidence=? WHERE id=?",
        (json.dumps(body, ensure_ascii=False, sort_keys=True), status,
         json.dumps(record, ensure_ascii=False), int(time.time()),
         round(confidence, 3), rec_id))
    st.conn.commit()
    return {"id": rec_id, "status": status, "verification": record,
            "promoted": status == "verified",
            "confidence": round(confidence, 3)}


def revise(rec_id: str, *, title: str | None = None, body: str | None = None,
           evidence: str | None = None, status: str | None = None,
           author: str | None = None, path: str | None = None) -> dict[str, Any]:
    """Change a record, keeping the previous revision in history."""
    st = _store(path)
    row = st.conn.execute("SELECT * FROM mem WHERE id=?", (rec_id,)).fetchone()
    if row is None:
        raise KnowledgeError(f"no record {rec_id}")
    rec = dict(row)
    if status is not None and status not in STATUSES:
        raise KnowledgeError(f"unknown status {status!r}")
    if status == "verified":
        raise KnowledgeError("a revision cannot promote to 'verified'; use `knowledge verify`")

    try:
        payload = json.loads(rec.get("body") or "{}")
    except (ValueError, TypeError):
        payload = {"body": rec.get("body")}
    revisions = payload.get("revisions") or []
    revisions.append({
        "at": int(time.time()), "author": author,
        "previous": {k: payload.get(k) for k in ("title", "body", "evidence", "status")},
    })
    payload["revisions"] = revisions[-20:]
    if title is not None:
        payload["title"] = title.strip()
    if body is not None:
        payload["body"] = body.strip()
    if evidence is not None:
        payload["evidence"] = evidence

    st.conn.execute(
        "UPDATE mem SET title=?, body=?, status=COALESCE(?, status), updated=? WHERE id=?",
        (payload.get("title") or rec.get("title"),
         json.dumps(payload, ensure_ascii=False, sort_keys=True),
         status, int(time.time()), rec_id))
    st.conn.commit()
    return {"id": rec_id, "revisions": len(revisions),
            "status": status or rec.get("status")}


def deprecate(rec_id: str, *, reason: str, superseded_by: str | None = None,
              path: str | None = None) -> dict[str, Any]:
    """Mark a record obsolete or superseded, preserving why."""
    if not (reason or "").strip():
        raise KnowledgeError("a deprecation needs a reason")
    st = _store(path)
    row = st.conn.execute("SELECT * FROM mem WHERE id=?", (rec_id,)).fetchone()
    if row is None:
        raise KnowledgeError(f"no record {rec_id}")
    status = "superseded" if superseded_by else "obsolete"
    rec = dict(row)
    try:
        payload = json.loads(rec.get("body") or "{}")
    except (ValueError, TypeError):
        payload = {}
    payload.setdefault("deprecations", []).append(
        {"at": int(time.time()), "reason": reason.strip(),
         "supersededBy": superseded_by})
    st.conn.execute(
        "UPDATE mem SET body=?, status=?, updated=?, confidence=0.1 WHERE id=?",
        (json.dumps(payload, ensure_ascii=False, sort_keys=True), status,
         int(time.time()), rec_id))
    st.conn.commit()
    return {"id": rec_id, "status": status, "reason": reason}


def link(src: str, dst: str, *, relation: str = "related",
         path: str | None = None) -> dict[str, Any]:
    """Relate two records. Relations live in the existing links table."""
    st = _store(path)
    try:
        res = st.link(src, dst, relation)
    except ValueError as exc:
        raise KnowledgeError(str(exc)) from exc
    return {"src": src, "dst": dst, "relation": res.get("rel", relation),
            "action": res.get("action"), "meaning": res.get("meaning")}


def search_all(query: str, *, status: str | None = None, kind: str | None = None,
               project: str | None = None, target: str | None = None,
               k: int = 8, path: str | None = None) -> dict[str, Any]:
    """Search knowledge, filtering on scope and lifecycle status."""
    from .search import search as memsearch
    st = _store(path)
    res = memsearch(st, query, k=max(k * 3, 24), token_budget=6000)
    out = []
    for hit in (res.get("results") or res.get("hits") or []):
        rec = hit.get("record") or hit
        rid = rec.get("id")
        if rid is None:
            continue
        row = st.conn.execute("SELECT * FROM mem WHERE id=?", (rid,)).fetchone()
        if row is None:
            continue
        r = _row_to_record(row)
        if status and r.get("status") != status:
            continue
        if kind and r.get("kind") != kind:
            continue
        if project and r.get("project") != project:
            continue
        if target and r.get("target") != target:
            continue
        out.append(r)
        if len(out) >= k:
            break
    # A record marked obsolete must not be presented as current knowledge.
    current = [r for r in out if r.get("status") not in ("obsolete", "superseded")]
    historical = [r for r in out if r.get("status") in ("obsolete", "superseded")]
    return {"current": current, "historical": historical,
            "counts": {"current": len(current), "historical": len(historical)}}
