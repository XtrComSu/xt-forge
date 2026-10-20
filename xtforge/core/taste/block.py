"""Render the taste block injected into a session.

One format, one place. The OpenCode plugin asks for the rendered block instead
of rebuilding it, so the plugin and the CLI can never disagree about what the
model sees.

Rules:
- only `enforced` learnings are eligible; `hint`, `weak` and `conflict` are
  deliberately invisible to the model
- statements are stripped of `<>&` so they can never close the block or open a
  nested tag
- bounded in count and characters: taste is context, not the task
"""
from __future__ import annotations

import re
from typing import Any, Iterable

MAX_RULES = 40
MAX_CHARS = 2400
_UNSAFE = re.compile(r"[<>&]")
_SPACE = re.compile(r"\s+")


def _clean(text: Any) -> str:
    return _SPACE.sub(" ", _UNSAFE.sub(" ", str(text or ""))).strip()


def render_block(rows: Iterable[dict[str, Any]], source: str = "xt-forge",
                 max_rules: int = MAX_RULES,
                 max_chars: int = MAX_CHARS) -> str:
    """Render the `<taste>` block, or "" when nothing qualifies."""
    rules = []
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "enforced":
            continue
        statement = _clean(row.get("statement"))
        if not statement:
            continue
        category = _clean(row.get("category")) or "general"
        try:
            confidence = float(row.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        rules.append(f'  <rule category="{category}" '
                     f'confidence="{confidence:.2f}">{statement}</rule>')
        if len(rules) >= max_rules:
            break
    if not rules:
        return ""
    body = (f'<taste source="{_clean(source)}" enforcement="enforced only">\n'
            f'{chr(10).join(rules)}\n</taste>')
    if len(body) <= max_chars:
        return body
    return body[:max_chars].rstrip() + "\n…</taste>"
