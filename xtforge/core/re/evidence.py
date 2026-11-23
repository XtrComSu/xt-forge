"""Versioned evidence records for reverse-engineering results.

An evidence record identifies the *bytes* an analysis ran against: the whole
file hash, the container member and Mach-O slice selected, the address space
assumed, and the backend that produced the view. It is deliberately not a
signature -- the same bytes analysed twice must produce the same record, and a
record must say what the analysis did not cover.

The record is a plain dict so it can travel through annotations, reports and
the CLI/MCP paging paths without a new serialisation layer.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

EVIDENCE_SCHEMA = 1

_SCHEMA_NOTE = "identifies the analysed bytes; not a signature"

# Stream the file: a multi-gigabyte image must not become a multi-gigabyte
# bytes object just to be identified.
_READ_CHUNK = 1024 * 1024


def build(path, *, member=None, arch=None, verb="overview", backend="xtforge-hub",
          backend_version="", limits=None, address_space=None) -> dict:
    """Build a versioned evidence record for ``path``.

    ``arch`` is the selected image architecture (a Mach-O slice name when the
    file is a universal binary) and is recorded under the ``slice`` key.
    ``address_space`` describes the assumed load space, e.g.
    ``{"base": 0x1000, "bits": 64}``. ``verb`` names the analysis that requested
    the record; it is accepted for callers that build records from a verb
    dispatch, but it is not part of the on-disk shape.

    Raises FileNotFoundError when the path is absent and ValueError when it is
    not a regular file (a directory, a device, a missing target behind a broken
    symlink). Hashing is streamed over the whole file, never a truncated head.
    """
    path_text = os.fspath(path) if hasattr(path, "__fspath__") else str(path)
    target = Path(path_text)

    if not target.exists():
        raise FileNotFoundError(f"evidence path does not exist: {path_text}")
    mode = target.stat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"evidence path is not a regular file: {path_text}")

    digest = hashlib.sha256()
    size = 0
    with target.open("rb") as handle:
        while True:
            chunk = handle.read(_READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)

    return {
        "schema": EVIDENCE_SCHEMA,
        "path": path_text,
        "size": size,
        "sha256": digest.hexdigest(),
        "member": member,
        "slice": arch,
        "address_space": (dict(address_space)
                          if isinstance(address_space, dict) else address_space),
        "backend": backend,
        "backend_version": str(backend_version),
        "limits": dict(limits) if isinstance(limits, dict) else {},
        "schema_note": _SCHEMA_NOTE,
    }


def attach(result: dict, record: dict) -> dict:
    """Return a shallow copy of ``result`` carrying ``record`` as evidence.

    The caller's dict is never modified, so an analysis result can be attached
    to a record and still be emitted in its original shape elsewhere.
    """
    combined = dict(result)
    combined["evidence"] = record
    return combined


# --------------------------------------------------------------------- evidence bundles
#
# A record identifies one file. A *bundle* is a whole investigation: many records, the
# findings attached to them, and the open questions still outstanding, in one file that can
# be handed to someone else and verified on arrival.
#
# The design constraint is that a bundle must be self-checking. Anyone receiving one should
# be able to tell whether it was edited in transit — not by trusting a signature (there is
# no key infrastructure here) but by recomputing a content hash over the canonical form and
# comparing. That catches corruption and casual editing; it does not stop a determined
# forger, and the bundle says so rather than implying more.

BUNDLE_SCHEMA = 1
BUNDLE_KIND = "xt-forge-evidence-bundle"


def _canonical(payload: dict) -> bytes:
    """Canonical JSON bytes for hashing: sorted keys, no whitespace, ASCII-safe."""
    import json
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _bundle_digest(body: dict) -> str:
    digest = hashlib.sha256()
    digest.update(_canonical(body))
    return digest.hexdigest()


def export_bundle(destination: str | Path, *, records: list[dict] | None = None,
                  findings: list[dict] | None = None,
                  unknowns: list[dict] | None = None,
                  note: str = "") -> dict:
    """Write an evidence bundle and return its manifest.

    ``records`` are evidence records from :func:`build`; ``findings`` are analysis results
    or annotations; ``unknowns`` are obligation-ledger rows. The bundle is written as JSON
    with a content digest over its canonical body, so :func:`import_bundle` can prove the
    bytes arrived intact.
    """
    import json

    body = {
        "schema": BUNDLE_SCHEMA,
        "kind": BUNDLE_KIND,
        "records": list(records or []),
        "findings": list(findings or []),
        "unknowns": list(unknowns or []),
        "note": note,
    }
    document = dict(body)
    document["digest"] = _bundle_digest(body)
    document["digest_algorithm"] = "sha256 over canonical JSON of the body"
    document["integrity_note"] = (
        "the digest proves the bundle was not corrupted or casually edited in transit; it "
        "is not a signature and does not authenticate the author")

    target = Path(os.fspath(destination) if hasattr(destination, "__fspath__")
                  else str(destination))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=1, sort_keys=True), encoding="utf-8")
    return {
        "ok": True,
        "path": str(target),
        "digest": document["digest"],
        "record_count": len(body["records"]),
        "finding_count": len(body["findings"]),
        "unknown_count": len(body["unknowns"]),
        "size": target.stat().st_size,
    }


def import_bundle(source: str | Path, *, verify_files: bool = False) -> dict:
    """Read an evidence bundle, verify its digest, and report what it contains.

    With ``verify_files``, every evidence record's file is re-hashed and compared to the
    recorded digest. That is the check that matters when the *inputs* may have changed
    since the analysis ran — a bundle that verifies its own integrity but whose underlying
    binary has since been replaced is a trap.
    """
    import json

    path = Path(os.fspath(source) if hasattr(source, "__fspath__") else str(source))
    if not path.is_file():
        return {"ok": False, "path": str(path), "error": "bundle file does not exist"}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "path": str(path), "error": f"cannot parse bundle: {exc}"}
    if not isinstance(document, dict) or document.get("kind") != BUNDLE_KIND:
        return {"ok": False, "path": str(path),
                "error": f"not an evidence bundle (kind={document.get('kind')!r})"}

    recorded = document.get("digest")
    body = {key: document.get(key) for key in
            ("schema", "kind", "records", "findings", "unknowns", "note")}
    actual = _bundle_digest(body)
    integrity = "intact" if recorded == actual else "MISMATCH"

    result = {
        "ok": True,
        "path": str(path),
        "schema": document.get("schema"),
        "integrity": integrity,
        "recorded_digest": recorded,
        "computed_digest": actual,
        "record_count": len(body["records"] or []),
        "finding_count": len(body["findings"] or []),
        "unknown_count": len(body["unknowns"] or []),
        "records": body["records"] or [],
        "unknowns": body["unknowns"] or [],
        "findings": body["findings"] or [],
        "note": document.get("note", ""),
    }
    if integrity != "intact":
        result["warning"] = ("the bundle digest does not match its contents; it was edited "
                             "after export or corrupted. Treat every claim inside as "
                             "unverified")

    if verify_files:
        checks = []
        for record in body["records"] or []:
            recorded_path = record.get("path")
            recorded_hash = record.get("sha256")
            entry = {"path": recorded_path, "recorded_sha256": recorded_hash}
            try:
                probe = Path(recorded_path)
                if not probe.is_file():
                    entry["status"] = "missing"
                else:
                    digest = hashlib.sha256()
                    with probe.open("rb") as handle:
                        while True:
                            chunk = handle.read(_READ_CHUNK)
                            if not chunk:
                                break
                            digest.update(chunk)
                    entry["actual_sha256"] = digest.hexdigest()
                    entry["status"] = ("match" if digest.hexdigest() == recorded_hash
                                       else "CHANGED")
            except OSError as exc:
                entry["status"] = "unreadable"
                entry["error"] = str(exc)
            checks.append(entry)
        result["file_checks"] = checks
        result["changed_files"] = [c["path"] for c in checks if c["status"] != "match"]
    return result


def inspect(path: str | Path, **kwargs):
    """Dispatch on content: a bundle is a JSON document with our kind, a bare evidence
    record is one file's identity."""
    import json

    probe = Path(os.fspath(path) if hasattr(path, "__fspath__") else str(path))
    if probe.is_file() and probe.suffix.lower() == ".json":
        try:
            document = json.loads(probe.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            document = None
        if isinstance(document, dict) and document.get("kind") == BUNDLE_KIND:
            return import_bundle(probe, **kwargs)
    return build(path, **kwargs)
