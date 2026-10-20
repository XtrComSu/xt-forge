"""Taste learning schema: fixed categories, typed learnings, scored signals.

A taste learning is one **falsifiable preference**, not free-form prose:

    category: typescript · key: semicolons · polarity: avoid
    statement: "Omit semicolons in TypeScript."
    confidence: 0.91 (alpha 7.0 / beta 2.0) · status: enforced

Identity is `(scope, category, key)`. Evidence **for** the current statement
raises `alpha`; evidence **against** raises `beta`; confidence is
`alpha / (alpha + beta)`. When both arms carry weight the learning is a
`conflict` — visible, never silently overwritten — and if the balance flips,
the polarity flips with it and the statement changes to match.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

CATEGORIES: tuple[str, ...] = (
    "cli", "python", "typescript", "rust", "go", "architecture", "testing",
    "docs", "security", "performance", "naming", "errors", "dependencies",
    "git", "ui",
)

# Signal kinds and their evidence weight. Explicit statements and manual
# learnings are strong; inferred behaviour is weak and can only reinforce.
SIGNAL_KINDS: dict[str, float] = {
    "manual": 1.0,
    "explicit": 1.0,
    "correction": 0.7,
    "permission": 0.6,
    "test": 0.5,
    "tool_retry": 0.4,
}

STATUSES = ("weak", "hint", "enforced", "conflict", "retired")

# Beta prior: Jeffreys (0.5 / 0.5). Weak enough that three consistent signals
# reach `enforced`, strong enough that one signal cannot.
ALPHA0 = 0.5
BETA0 = 0.5

ENFORCED_MIN_CONFIDENCE = 0.85
ENFORCED_MIN_EVIDENCE = 3
HINT_MIN_CONFIDENCE = 0.60
CONFLICT_MIN_ARM = 1.5
RETIRE_AFTER_DAYS = 90

_PUNCT = re.compile(r"[^a-z0-9\s]+")
_SPACES = re.compile(r"\s+")

# Key normalisation drops glue words and imperative verbs so the same subject
# phrased two ways lands on one key. That is what lets "always use X" and
# "never use X" meet as a contradiction instead of living as two unrelated
# rows. Polarity is carried by the signal, never by the key.
KEY_STOPWORDS = frozenset("""
a an the this that these those and or but of in on at to for with from by as
is are be been being always never please just really also instead rather than
over under not no do don't does did use using used prefer prefers preferring
avoid avoiding keep keeps keeping stop stops stopping more any some our my
your their its you we i he she they it code codes file files style way thing
things stuff item items
""".split())


def normalize_key(text: str) -> str:
    """Stable key: lowercase, punctuation stripped, glue words dropped."""
    cleaned = _PUNCT.sub(" ", (text or "").lower())
    words = [word for word in cleaned.split() if word not in KEY_STOPWORDS]
    return _SPACES.sub(" ", " ".join(words)).strip()


def learning_id(scope: str, category: str, key: str) -> str:
    raw = f"{scope}|{category}|{key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class Learning:
    id: str
    scope: str
    category: str
    key: str
    statement: str
    polarity: int                 # +1 prefer, -1 avoid
    alpha: float = ALPHA0
    beta: float = BETA0
    status: str = "weak"
    evidence: int = 0
    first_seen: int = 0
    last_seen: int = 0
    retired: bool = False

    @property
    def confidence(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["confidence"] = round(self.confidence, 4)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Learning":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Signal:
    kind: str
    polarity: int
    category: str
    key: str
    statement: str
    quote: str = ""
    source: str = ""
    weight: float = field(default=0.0)
    created: int = 0

    def __post_init__(self) -> None:
        if self.weight <= 0:
            self.weight = SIGNAL_KINDS.get(self.kind, 0.3)
        self.polarity = 1 if self.polarity >= 0 else -1
        self.category = self.category if self.category in CATEGORIES else "architecture"
        self.key = normalize_key(self.key)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Signal":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})
