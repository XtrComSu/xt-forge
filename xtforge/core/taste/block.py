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
- a rule the user *avoided* is rendered as a prohibition, never as the bare
  object: "Never fabricate output" must not reach the model as
  "fabricate output", which reads as an instruction to do exactly that
"""
from __future__ import annotations

import re
from typing import Any, Iterable

MAX_RULES = 12
MAX_CHARS = 1200
_UNSAFE = re.compile(r"[<>&]")
_SPACE = re.compile(r"\s+")

# A statement that already reads as a prohibition must not be prefixed again.
_NEGATED = re.compile(
    r"^\s*(?:never|avoid|avoiding|no\b|no\s+more|do\s+not|don'?t|stop\s+using|"
    r"quit\s+using|refuse\s+to|don'?t\s+ever)\b", re.IGNORECASE)


def _clean(text: Any) -> str:
    return _SPACE.sub(" ", _UNSAFE.sub(" ", str(text or ""))).strip()


def _directive(statement: str, polarity: int) -> str:
    """The rule as the model should read it, polarity included.

    A learning's statement is the subject of the preference ("fabricate
    output"), and the polarity says which way it points. Dropping the polarity
    inverts the rule, so it is restored here: a negative learning is rendered
    as a prohibition unless its statement already is one.
    """
    if polarity >= 0 or _NEGATED.match(statement):
        return statement
    return f"Never {statement}"


def render_block(rows: Iterable[dict[str, Any]], source: str = "xt-forge",
                 max_rules: int = MAX_RULES,
                 max_chars: int = MAX_CHARS) -> str:
    """Render the `<taste>` block, or "" when nothing qualifies."""
    rules = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "enforced":
            continue
        statement = _clean(row.get("statement"))
        if not statement:
            continue
        try:
            polarity = int(row.get("polarity", 1))
        except (TypeError, ValueError):
            polarity = 1
        statement = _directive(statement, polarity)
        # a cue glued onto an article reads as gibberish ("Never a panic");
        # identical statements learned under two categories must not repeat
        if re.match(r"^(?:never|avoid)\s+(?:a|an|the|no)\b", statement,
                    re.IGNORECASE) or statement.lower() in seen:
            continue
        seen.add(statement.lower())
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
