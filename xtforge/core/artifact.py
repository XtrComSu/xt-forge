"""Artifact sidecars: record that a produced file was actually checked.

The gap this closes
-------------------
Nothing in the environment records whether an output file was verified. A
deliverables card can list a changed file, and a report can claim a result, but
"produced" and "checked" were indistinguishable. That is how a polished-looking
artifact hides a wrong number.

Model
-----
A sidecar is JSON stored beside the artifact at `<artifact>.xt-artifact.json`:

    id          sha256 of the artifact's bytes (identity, not a filename)
    path        where it lives
    mediaType
    producer    tool/attempt/model, free-form
    sources     [{path, sha256}] what it was built from
    checks      [{id, version, result, detail, at, subjectSha256}]
    status      unverified | verified | failed | stale
    history     [{change, at, by}]

Rules that matter
-----------------
- **Identity is content, not name.** Editing a file changes its sha256, so the
  sidecar no longer describes it. That is `stale`, and it is computed on read
  rather than trusted from the stored field.
- **A check records what it examined.** `subjectSha256` is the hash the check
  looked at. A check whose subject no longer matches the artifact proves
  nothing about the current bytes, so it cannot upgrade the status.
- **Absence is not success.** No sidecar, or a sidecar with no passing check,
  reads as `unverified`. Only an explicit passing check against the current
  bytes yields `verified`.
- **A declared verdict is not a check.** `artifact check --declared` records
  what someone *asserted*, never what ran. Declared passes are kept for the
  audit trail but can never produce `verified`; they surface as
  `attested_unsupported` so a claim is visible without being trusted.
- **Checks carry their executor.** A check stores the checker's identity
  (`--checker`), its version, and the executor's exit status when one exists.
  A pass with no executor and no exit status is treated as declared.
- **Unrelated passes do not imply completion.** `verified` means "every
  required check ran and passed on these bytes". A file with one passing
  smoke check and no declared requirement is `partially_verified`, not
  `verified`. Callers declare the requirement with `artifact require`.

This module is deliberately sidecar-only: it writes no database rows and calls
no network. A caller that wants the finding in a report can pass --target to
link it into the recon ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

SIDECAR_SUFFIX = ".xt-artifact.json"
SCHEMA = "xt.artifact/1"

UNVERIFIED = "unverified"
PARTIALLY_VERIFIED = "partially_verified"
VERIFIED = "verified"
FAILED = "failed"
STALE = "stale"
ATTESTED_UNSUPPORTED = "attested_unsupported"


class ArtifactError(RuntimeError):
    """A caller error: missing file, unreadable sidecar, bad check id."""


def resolve(path: str) -> str:
    """Resolve a user-supplied path against the caller's directory.

    The `xtforge` launcher `cd`s into the tool root so imports resolve, which
    would otherwise make a relative artifact path point at the tool instead of
    the user's file. `XT_INVOKE_CWD` carries the directory the user actually
    ran from.
    """
    if not path:
        raise ArtifactError("no artifact path given")
    expanded = os.path.expanduser(path)
    if os.path.isabs(expanded):
        return os.path.abspath(expanded)
    base = os.environ.get("XT_INVOKE_CWD") or os.getcwd()
    return os.path.abspath(os.path.join(base, expanded))


def sidecar_path(artifact: str) -> str:
    return resolve(artifact) + SIDECAR_SUFFIX


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read(artifact: str) -> dict[str, Any] | None:
    p = sidecar_path(artifact)
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ArtifactError(f"unreadable sidecar {p}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ArtifactError(f"sidecar {p} is not {SCHEMA}")
    return data


INDEX_VERSION = 1


def index_path() -> str:
    """Where the sidecar index lives (runtime cache, never the artifact tree)."""
    from ..version import cache_dir
    return str(cache_dir() / "artifact-index.jsonl")


def index_append(sidecar: str) -> None:
    """Record that a sidecar exists, so recall need not walk the tree to find it.

    Best effort by design: the sidecar is the record, this is only an
    accelerator, so a failed index write never fails the artifact write that
    produced it.
    """
    try:
        line = json.dumps({"v": INDEX_VERSION, "path": os.path.abspath(sidecar),
                           "at": int(time.time())}, ensure_ascii=False)
        p = index_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:  # noqa: BLE001
        pass


def index_append_many(sidecars: list[str]) -> None:
    for sidecar in sidecars:
        index_append(sidecar)


def scan_marker_path(roots: list[str]) -> str:
    """Marker recording that `roots` was fully walked, so it is not walked again."""
    import hashlib as _h
    key = _h.sha256("\x00".join(sorted(os.path.abspath(r) for r in roots))
                    .encode("utf-8")).hexdigest()[:16]
    return str(_cache_dir() / "artifact-scan" / (key + ".json"))


def _cache_dir():
    from ..version import cache_dir
    return cache_dir()


def mark_scanned(roots: list[str], sidecars: list[str]) -> None:
    """Remember a completed walk: its sidecars are now in the index.

    Called only after a walk that finished inside its budget. An unfinished
    walk is never marked, so a truncated search cannot masquerade as a
    complete one on the next call.
    """
    index_append_many(sidecars)
    try:
        p = scan_marker_path(roots)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"roots": [os.path.abspath(r) for r in roots],
                       "at": int(time.time()), "count": len(sidecars)}, fh)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def scanned_recently(roots: list[str], max_age: float = 86400.0) -> bool:
    """True when `roots` was fully walked within `max_age` seconds."""
    try:
        p = scan_marker_path(roots)
        age = time.time() - os.stat(p).st_mtime
        return 0 <= age < max_age
    except OSError:
        return False
    except Exception:  # noqa: BLE001
        return False


def indexed_sidecars(roots: list[str] | None = None) -> list[str]:
    """Existing sidecar paths from the index, newest first, scoped to `roots`.

    Deduplicated by path so a rewritten artifact appears once. Paths that no
    longer exist are dropped rather than returned as stale candidates.
    """
    try:
        p = index_path()
        if not os.path.exists(p):
            return []
        bases = [os.path.abspath(r) for r in roots] if roots else []
        seen: dict[str, int] = {}
        with open(p, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                path = rec.get("path")
                if not isinstance(path, str) or not path:
                    continue
                if bases and not any(path == b or path.startswith(b + os.sep) for b in bases):
                    continue
                seen[path] = max(seen.get(path, 0), int(rec.get("at") or 0))
    except Exception:  # noqa: BLE001
        return []
    out = [p for p in seen if os.path.exists(p)]
    out.sort(key=lambda p: seen[p], reverse=True)
    return out


def _write(artifact: str, data: dict[str, Any]) -> str:
    p = sidecar_path(artifact)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, p)
    index_append(p)
    return p


def effective_status(artifact: str, data: dict[str, Any] | None) -> tuple[str, str]:
    """Status derived from the artifact's *current* bytes.

    Returns (status, reason). The stored `status` field is only a hint: the
    bytes decide, and so does the declared requirement.

    Order of precedence:
      1. missing/shifted bytes        -> stale
      2. any executed failure on bytes -> failed
      3. requirement declared         -> verified only if every required check
                                        ran and passed on these bytes
      4. no requirement               -> partially_verified when executed
                                        checks passed, never plain `verified`
      5. declared-only passes         -> attested_unsupported
    """
    artifact = resolve(artifact)
    if not os.path.exists(artifact):
        return STALE, "artifact missing"
    if data is None:
        return UNVERIFIED, "no sidecar"
    current = sha256_file(artifact)
    if data.get("id") != current:
        return STALE, (f"content changed (sidecar {str(data.get('id'))[:12]}, "
                       f"now {current[:12]})")

    checks = [c for c in (data.get("checks") or []) if c.get("subjectSha256") == current]
    required = list(data.get("requiredChecks") or [])
    by_id = {c.get("id"): c for c in checks}

    executed_fail = [c for c in checks
                     if c.get("result") == "fail" and not c.get("declared")]
    if executed_fail:
        return FAILED, ("%d failing check(s) on current bytes: %s"
                        % (len(executed_fail),
                           ", ".join(str(c.get("id")) for c in executed_fail)))

    declared_fail = [c for c in checks
                     if c.get("result") == "fail" and c.get("declared")]
    if declared_fail:
        return FAILED, ("%d declared failure(s) on current bytes: %s"
                        % (len(declared_fail),
                           ", ".join(str(c.get("id")) for c in declared_fail)))

    executed_pass = [c for c in checks
                     if c.get("result") == "pass" and not c.get("declared")]
    declared_pass = [c for c in checks
                     if c.get("result") == "pass" and c.get("declared")]

    if required:
        missing, still_declared, not_passed = [], [], []
        for name in required:
            c = by_id.get(name)
            if c is None:
                missing.append(name)
            elif c.get("declared"):
                still_declared.append(name)
            elif c.get("result") != "pass":
                not_passed.append(f"{name}={c.get('result')}")
        if not missing and not still_declared and not not_passed:
            return VERIFIED, ("all %d required check(s) executed and passed "
                              "on current bytes" % len(required))
        bits = []
        if missing:
            bits.append("not run: " + ", ".join(missing))
        if still_declared:
            bits.append("declared only: " + ", ".join(still_declared))
        if not_passed:
            bits.append("not passing: " + ", ".join(not_passed))
        return UNVERIFIED, ("requirement not satisfied (%d required) - %s"
                            % (len(required), "; ".join(bits)))

    if executed_pass:
        return PARTIALLY_VERIFIED, (
            "%d executed check(s) passed, but no requirement declared, so this "
            "does not establish completion" % len(executed_pass))
    if declared_pass:
        return ATTESTED_UNSUPPORTED, (
            "%d declared pass(es) with no executed check; a declaration is not "
            "evidence" % len(declared_pass))
    if checks:
        return UNVERIFIED, "checks exist but none examined the current bytes"
    return UNVERIFIED, "no checks recorded"


def record(artifact: str, *, media_type: str = "application/octet-stream",
           producer: str = "", sources: list[dict[str, Any]] | None = None,
           by: str = "cli") -> dict[str, Any]:
    """Create or refresh the sidecar for an artifact."""
    artifact = resolve(artifact)
    if not os.path.exists(artifact):
        raise ArtifactError(f"no such artifact: {artifact}")
    digest = sha256_file(artifact)
    existing = read(artifact)
    now = int(time.time())
    if existing is not None:
        history = existing.get("history") or []
        if existing.get("id") != digest:
            history.append({"change": "content changed", "at": now, "by": by,
                            "from": existing.get("id"), "to": digest})
        data = {**existing, "id": digest, "path": os.path.abspath(artifact),
                "mediaType": media_type or existing.get("mediaType"),
                "producer": producer or existing.get("producer", ""),
                "sources": sources if sources is not None else existing.get("sources", []),
                "history": history}
    else:
        data = {"schema": SCHEMA, "id": digest, "path": os.path.abspath(artifact),
                "mediaType": media_type, "producer": producer,
                "sources": sources or [], "checks": [], "status": UNVERIFIED,
                "history": [{"change": "created", "at": now, "by": by}]}
    status, reason = effective_status(artifact, data)
    data["status"] = status
    data["statusReason"] = reason
    data["updatedAt"] = now
    path = _write(artifact, data)
    return {**data, "sidecar": path}


def add_check(artifact: str, *, check_id: str, result: str, detail: str = "",
              version: str = "1", by: str = "cli", checker: str = "",
              exit_status: int | None = None, evidence: str = "",
              declared: bool = False) -> dict[str, Any]:
    """Append one check, bound to the bytes it examined.

    Distinguishes a check that *ran* from a verdict someone *declared*:

    - An executed check names its `checker` and, when a subprocess was
      involved, the `exit_status`. That pair is what makes a `pass` evidence.
    - `declared=True` records an assertion ("I believe this is correct").
      It is stored for the audit trail and is never convertible into
      `verified` by itself.
    - A `pass` that supplies neither a checker nor an exit status is treated
      as declared, because nothing distinguishes it from a claim.
    """
    if result not in ("pass", "fail", "skipped"):
        raise ArtifactError(f"result must be pass|fail|skipped, got {result!r}")
    if not check_id.strip():
        raise ArtifactError("check id must not be empty")
    artifact = resolve(artifact)
    if not os.path.exists(artifact):
        raise ArtifactError(f"no such artifact: {artifact}")
    data = read(artifact)
    if data is None:
        data = record(artifact)
    digest = sha256_file(artifact)

    # A pass is only evidence if something executed. Failures are always
    # admissible: refusing to record a failure would lose information.
    executed = bool(checker.strip()) or exit_status is not None
    if declared and executed:
        raise ArtifactError(
            "a check cannot be both declared and executed; drop --declared or "
            "supply --checker/--exit-status")
    if result == "pass" and not executed:
        declared = True

    checks = [c for c in (data.get("checks") or []) if c.get("id") != check_id]
    checks.append({
        "id": check_id,
        "version": version,
        "result": result,
        "detail": detail[:2000],
        "at": int(time.time()),
        "subjectSha256": digest,
        "by": by,
        "checker": checker or None,
        "exitStatus": exit_status,
        "evidence": evidence[:2000] or None,
        "declared": bool(declared),
    })
    data["checks"] = checks
    label = "declared" if declared else "check"
    data["history"] = (data.get("history") or []) + [
        {"change": f"{label}:{check_id}={result}", "at": int(time.time()), "by": by}]
    status, reason = effective_status(artifact, data)
    data["status"] = status
    data["statusReason"] = reason
    data["updatedAt"] = int(time.time())
    path = _write(artifact, data)
    return {**data, "sidecar": path}


def set_requirement(artifact: str, checks: list[str], *, by: str = "cli") -> dict[str, Any]:
    """Declare which checks must pass for this artifact to count as complete.

    Without a requirement, one passing smoke check would otherwise read as
    "done" - the unrelated-passes problem. The requirement is the caller's
    statement of what completion means for this artifact.
    """
    artifact = resolve(artifact)
    if not os.path.exists(artifact):
        raise ArtifactError(f"no such artifact: {artifact}")
    data = read(artifact)
    if data is None:
        data = record(artifact)
    required = [c.strip() for c in checks if c and c.strip()]
    # A required check that is not also an actual check id is a typo, not a
    # plan; accepting it would make "complete" unreachable and silent.
    known = {c.get("id") for c in (data.get("checks") or [])}
    unknown = [c for c in required if c not in known]
    data["requiredChecks"] = required
    data["history"] = (data.get("history") or []) + [
        {"change": f"require:{','.join(required) or '(none)'}", "at": int(time.time()), "by": by}]
    status, reason = effective_status(artifact, data)
    data["status"] = status
    data["statusReason"] = reason
    data["updatedAt"] = int(time.time())
    out = _write(artifact, data)
    return {**data, "sidecar": out, "unknownRequired": unknown}


def inspect(artifact: str) -> dict[str, Any]:
    """Report the current, derived status without modifying anything."""
    data = read(artifact)
    status, reason = effective_status(artifact, data)
    out = {"artifact": resolve(artifact), "status": status,
           "statusReason": reason,
           "sidecar": sidecar_path(artifact),
           "hasSidecar": data is not None}
    if data:
        out.update({"id": data.get("id"), "mediaType": data.get("mediaType"),
                    "producer": data.get("producer"),
                    "sources": data.get("sources") or [],
                    "checks": data.get("checks") or []})
    return out
