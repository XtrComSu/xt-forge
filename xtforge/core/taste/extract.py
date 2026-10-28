"""Deterministic extraction of explicit preferences. No LLM.

The design allows an LLM at the edge, but the decision layer must never depend
on one — and the highest-quality signal is the one a human wrote outright.
This is the pattern grammar Command Code describes as the first stage, kept
regex-only so it is reproducible and free.

Only explicit phrases create a learning key. Inferred behaviour (corrections,
retries) is handled by the signal kinds in `schema.py` and can only reinforce
or contradict a key that already exists.

Precision beats recall here. A bare "use" is a work order far more often than
it is a durable preference — "TASK: Use error-based SQLi to extract the
version" is an instruction for this run, not a rule for every run. So a key
needs a preference word that means "from now on": always, never, prefer,
avoid, please use, "use X not Y". The profile that gets injected is worth
nothing if it fills with sentences copied out of a task list.
"""
from __future__ import annotations

import re
from typing import Any

from .schema import Signal, normalize_key

PREFER = re.compile(
    r"\b(always|prefer(?:\s+to|ably)?|please\s+use|keep\s+using|go\s+with)\s+"
    r"([^\n.,;!?]{3,80})", re.IGNORECASE)
AVOID = re.compile(
    r"\b(never|avoid|do\s+not\s+use|don't\s+use|stop\s+using|no\s+more|"
    r"quit\s+using)\s+([^\n.,;!?]{3,80})", re.IGNORECASE)
RATHER = re.compile(
    r"\b([^\n.,;!?]{3,60}?)\s+(?:over|instead\s+of|rather\s+than)\s+"
    r"([^\n.,;!?]{3,60})", re.IGNORECASE)
USE_NOT = re.compile(
    r"\buse\s+([^\n.,;!?]{2,60}?)\s+not\s+([^\n.,;!?]{2,60})", re.IGNORECASE)
# "X over Y" is only a preference when the line carries a preference cue;
# otherwise ordinary prose ("the fox jumps over the lazy dog") matches.
#
# The cue has to be a preference word, not the connective itself: every
# "instead of" carries "instead", so allowing it would make the rule fire on
# any prose that contrasts two things ("subtle foreshadowing instead of a
# plain introduction"). A durable preference announces itself: always, never,
# prefer, avoid.
CUE = re.compile(
    r"\b(prefer(?:ably)?|rather|choose|pick|always|never|avoid|go\s+with|"
    r"keep\s+using)\b", re.IGNORECASE)

CATEGORY_HINTS: dict[str, tuple[str, ...]] = {
    "typescript": ("typescript", "javascript", "ts ", "node", "npm", "pnpm",
                   "semicolons", "interface", "type ", "react", "eslint"),
    "python": ("python", "pytest", "pip", "type hint", "f-string", "import",
               "venv", "dunder", "pep8", "ruff"),
    "rust": ("rust", "cargo", "clippy", "borrow", "unwrap", "crate", "trait"),
    "go": ("golang", "goroutine", "gofmt", "go code", " go "),
    "cli": ("cli", "command", "flag", "argument", "stdout", "json output",
            "terminal", "shell", "help text", "subcommand", "exit code"),
    "testing": ("test", "fixture", "assert", "coverage", "benchmark",
                "regression", "snapshot"),
    "docs": ("doc", "readme", "changelog", "comment", "docstring", "example"),
    "security": ("secret", "token", "permission", "allowlist", "guard",
                 "auth", "credential", "sanitize", "redact", "encrypt"),
    "performance": ("performance", "latency", "cache", "memory", "fast",
                    "slow", "profile", "hot path"),
    "naming": ("name", "naming", "rename", "variable", "identifier",
               "spelling", "convention"),
    "errors": ("error", "exception", "raise", "traceback", "hint", "message",
               "panic", "unwrap"),
    "dependencies": ("dependency", "dependencies", "package", "vendor",
                     "library", "version pin", "lockfile"),
    "git": ("git", "commit", "branch", "merge", "rebase", "pull request",
            "pr ", "changelog"),
    "ui": ("ui", "ux", "formatting", "colour", "color", "layout", "output"),
}

_PRIORITY = ("security", "testing", "errors", "dependencies", "cli",
             "typescript", "python", "rust", "go", "git", "performance",
             "naming", "docs", "ui", "architecture")


def infer_category(text: str) -> str:
    """Pick the category with the most keyword hits; ties break by priority."""
    lowered = f" {text.lower()} "
    scores = {
        category: sum(lowered.count(hint) for hint in hints)
        for category, hints in CATEGORY_HINTS.items()
    }
    best = max(scores.values())
    if best == 0:
        return "architecture"
    for category in _PRIORITY:
        if scores.get(category) == best:
            return category
    return "architecture"


def _sentence(text: str) -> str:
    return " ".join((text or "").split())[:160]


_TRAILING = ("**", ",", ":", ";", "(", "[", " and", " or", " in", " the",
             " a", " an", " to", " of", " with", " that", " when", " is")


def _valid_statement(statement: str) -> bool:
    """A rule must read as a complete, self-contained sentence fragment.

    Fragments are worse than silence: "Never a panic**" or "Never no bypass at
    all" both mislead and cost context on every turn. A cue plus an object is
    the minimum ("never delete"); anything unbalanced, truncated or too long is
    dropped instead of promoted.
    """
    s = " ".join((statement or "").split())
    if len(s) < 8 or len(s) > 140:
        return False
    if s.count("(") != s.count(")") or s.count("[") != s.count("]"):
        return False
    if s.count('"') % 2 or s.count("`") % 2:
        return False
    # double negation is not a rule, it is a mangled sentence
    if re.match(r"^(?:never|avoid|do\s+not|don'?t)\s+(?:no|not|never)\b",
                s, re.IGNORECASE):
        return False
    if s.endswith(_TRAILING):
        return False
    return len(s.split()) >= 2


def extract(text: str, source: str = "", scope: str = "global",
            ) -> list[Signal]:
    """Explicit preference signals from free text. Deterministic.

    Patterns are matched most-specific first and each match claims its span,
    so "Never use X" never also yields a *prefer X* from the generic rule.
    """
    out: list[Signal] = []
    seen: set[tuple[str, str, int]] = set()

    def add(statement: str, polarity: int, quote: str) -> None:
        key = normalize_key(statement)
        if len(key) < 3 or not _valid_statement(statement):
            return
        identity = (key, scope, polarity)
        if identity in seen:
            return
        seen.add(identity)
        out.append(Signal(
            kind="explicit", polarity=polarity, category=infer_category(quote),
            key=key, statement=_sentence(statement), quote=_sentence(quote),
            source=source or "text"))

    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        claimed: list[tuple[int, int]] = []

        def free(span: tuple[int, int]) -> bool:
            return not any(span[0] < end and start < span[1]
                           for start, end in claimed)

        stages: list[tuple[re.Pattern[str], int]] = [(USE_NOT, 2)]
        if CUE.search(stripped):
            stages.append((RATHER, 2))
        stages.extend(((AVOID, 1), (PREFER, 1)))
        for pattern, take in stages:
            for match in pattern.finditer(stripped):
                if not free(match.span()):
                    continue
                claimed.append(match.span())
                cue = " ".join(match.group(1).split()).lower()
                if take == 2:
                    # "use X not Y": X is preferred, Y is refused
                    add(f"prefer {match.group(1)}", 1, stripped)
                    add(f"avoid {match.group(2)}", -1, stripped)
                elif pattern is AVOID:
                    add(f"{cue} {match.group(2)}", -1, stripped)
                else:
                    add(f"{cue} {match.group(2)}", 1, stripped)
    return out


def extract_one(statement: str, source: str = "manual",
                scope: str = "global") -> Signal:
    """A human-authored learning; weight 1.0 and immediately eligible."""
    text = statement.strip()
    negative = bool(re.match(r"^(never|avoid|do not|don't|no)\b",
                            text, re.IGNORECASE))
    polarity = -1 if negative else 1
    return Signal(
        kind="manual", polarity=polarity, category=infer_category(text),
        key=normalize_key(text), statement=_sentence(text),
        quote=_sentence(text), source=source)


def as_dict(signals: list[Signal]) -> list[dict[str, Any]]:
    return [signal.to_dict() for signal in signals]
