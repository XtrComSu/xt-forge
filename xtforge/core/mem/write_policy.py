"""Secret detection + normalized-body hashing + token Jaccard (F2 write policy, R10)."""
from __future__ import annotations

import hashlib
import re
import unicodedata

# Deliberately conservative: each pattern must match real secret shapes.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b")),
    ("assign_secret", re.compile(
        r"(?i)\b(api[_-]?key|secret|passwd|password|token|access[_-]?key)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
    ("pg_url_pw", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s:@/]{4,}@\S+")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
]

REDACTED = "[REDACTED]"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return [(kind, matched_snippet)] for every secret shape found."""
    hits: list[tuple[str, str]] = []
    for kind, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            hits.append((kind, m.group(0)[:60]))
    return hits


def redact(text: str) -> tuple[str, list[str]]:
    """Replace secret matches with [REDACTED]. Returns (clean_text, kinds_found)."""
    kinds: list[str] = []
    out = text
    for kind, pat in SECRET_PATTERNS:
        def _sub(_m: re.Match[str]) -> str:
            if kind not in kinds:
                kinds.append(kind)
            return REDACTED
        out = pat.sub(_sub, out)
    return out, kinds


def has_secret(text: str) -> bool:
    return bool(find_secrets(text))


_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s]", re.UNICODE)
_TOKEN = re.compile(r"\w+", re.UNICODE)


def normalize_body(text: str) -> str:
    """Casefold, strip punctuation/whitespace, collapse runs. Used for dedupe hashing."""
    t = unicodedata.normalize("NFKC", text or "")
    t = _PUNCT.sub(" ", t).casefold()
    return _WS.sub(" ", t).strip()


def body_hash(text: str) -> str:
    return hashlib.sha256(normalize_body(text).encode("utf-8")).hexdigest()[:16]


def tokenize(text: str) -> set[str]:
    """Token set for Jaccard. Normalizes once; words of any length count."""
    return set(_TOKEN.findall(normalize_body(text)))


def jaccard(a: str | set[str], b: str | set[str]) -> float:
    sa = a if isinstance(a, set) else tokenize(a)
    sb = b if isinstance(b, set) else tokenize(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0