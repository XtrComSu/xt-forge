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
