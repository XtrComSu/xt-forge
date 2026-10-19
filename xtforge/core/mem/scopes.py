"""Scope resolution for universal memory (F2).

Scopes: global | project:<abs-path-hash> | session:<id> | workflow:<id>
Read order: session -> workflow -> project -> global.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

GLOBAL = "global"
KINDS = (
    "fact", "preference", "decision", "procedure", "snippet",
    "artifact_ref", "error_pattern", "person", "device",
)
VALID_KINDS = frozenset(KINDS)


def project_scope(path: str | Path) -> str:
    p = str(Path(path).expanduser().resolve())
    h = hashlib.sha256(p.encode("utf-8")).hexdigest()[:12]
    return f"project:{h}"


def session_scope(session_id: str) -> str:
    return f"session:{session_id}"


def workflow_scope(workflow_id: str) -> str:
    return f"workflow:{workflow_id}"


def base_scope(scope: str) -> str:
    return scope.split(":", 1)[0]


def is_valid_kind(kind: str) -> bool:
    return kind in VALID_KINDS


def read_order(session_id: str | None = None, workflow_id: str | None = None,
               project: str | Path | None = None) -> list[str]:
    """Ordered scope list, most specific first. Missing scopes are omitted."""
    out: list[str] = []
    if session_id:
        out.append(session_scope(session_id))
    if workflow_id:
        out.append(workflow_scope(workflow_id))
    if project:
        out.append(project_scope(project))
    out.append(GLOBAL)
    return out


def normalize_scope(scope: str | None, project: str | Path | None = None) -> str:
    if not scope:
        return project_scope(project or Path.cwd())
    if ":" in scope:
        base, _, rest = scope.partition(":")
        if base == "project" and not rest:
            return project_scope(project or Path.cwd())
        if base not in {"session", "workflow", "project", "global"}:
            raise ValueError(f"invalid scope: {scope!r}")
        return scope
    return scope