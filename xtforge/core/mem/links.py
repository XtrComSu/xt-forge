"""Typed links between memory records.

The `links` table existed since migration 001 but had no vocabulary, no
validation and no reader: `rel` was free text and `forget()` left orphans.
Links are typed so a graph query means something: `caused_by` is not
`see_also`, and both differ from `supersedes` (which the store also tracks in
`mem.supersedes`).

Relations are a closed vocabulary — a typo is rejected, not silently stored.
"""
from __future__ import annotations

from typing import Any

# rel -> meaning
RELATIONS: dict[str, str] = {
    "relates_to": "loose association",
    "supersedes": "this record replaces the target",
    "derived_from": "this record was distilled from the target",
    "part_of": "this record is a component of the target",
    "caused_by": "this record's problem traces to the target",
    "fixes": "this record resolves the target",
    "contradicts": "this record disagrees with the target",
    "see_also": "worth reading together",
}

DEFAULT_RELATION = "relates_to"


def is_valid_relation(rel: str) -> bool:
    return (rel or "").strip().lower() in RELATIONS


def normalize_relation(rel: str | None) -> str:
    value = (rel or "").strip().lower()
    return value if value in RELATIONS else DEFAULT_RELATION


def describe(rel: str) -> str:
    return RELATIONS.get((rel or "").strip().lower(), "unknown relation")


def shape(rows: list[dict[str, Any]], direction: str) -> list[dict[str, Any]]:
    """Compact, stable edge shape for CLI/MCP output."""
    out = []
    for row in rows:
        edge = dict(row)
        edge["direction"] = direction
        edge["meaning"] = describe(edge.get("rel", ""))
        out.append(edge)
    return out
