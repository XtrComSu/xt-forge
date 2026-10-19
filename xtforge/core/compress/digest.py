"""Digest grammar (F5): machine-parseable key=value lines, <= 800 tokens.

OBJ=... | DONE=... | FILES=... | DECISIONS=... | ERRORS=<sig:count> | NEXT=... | OPEN=...
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

KEYS = ("OBJ", "DONE", "FILES", "DECISIONS", "ERRORS", "NEXT", "OPEN")
MAX_DIGEST_TOKENS = 800

ERR_PAIR = re.compile(r"(?P<sig>[^:;]+):(?P<count>\d+)")


def empty() -> dict[str, str]:
    return {k: "none" for k in KEYS}


def render(digest: dict[str, str]) -> str:
    return " | ".join(f"{k}={digest.get(k, 'none')}" for k in KEYS)


def parse(text: str) -> dict[str, str]:
    out = empty()
    for part in (text or "").split("|"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip().upper()
        if k in out:
            out[k] = v.strip()
    return out


def error_sig(line: str) -> str:
    """Compact signature for an error line, for repetition counting."""
    line = (line or "").strip()
    if not line:
        return "unknown"
    line = re.sub(r"\b0x[0-9a-f]+\b", "0xADDR", line, flags=re.I)
    line = re.sub(r"\b\d+\b", "N", line)
    line = re.sub(r"\s+", " ", line)
    return line[:80]


def tally_errors(lines: list[str]) -> str:
    counts: dict[str, int] = {}
    for line in lines:
        counts[error_sig(line)] = counts.get(error_sig(line), 0) + 1
    if not counts:
        return "none"
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    return ";".join(f"{sig}:{n}" for sig, n in top)


def build(*, obj: str = "none", done: str = "none", files: str = "none",
          decisions: str = "none", errors: str = "none", nxt: str = "none",
          open_: str = "none") -> str:
    d = {"OBJ": obj, "DONE": done, "FILES": files, "DECISIONS": decisions,
         "ERRORS": errors, "NEXT": nxt, "OPEN": open_}
    return render(d)


def tokens(digest: str) -> int:
    return max(0, (len(digest) + 3) // 4)


def digest_hash(digest: str) -> str:
    """Normalized hash for stuck detection: digests differing only in round number match."""
    d = parse(digest)
    d.pop("NEXT", None)
    return hashlib.sha256(render(d).encode("utf-8")).hexdigest()[:12]


def validate(digest: str) -> dict[str, Any]:
    d = parse(digest)
    missing = [k for k in KEYS if not d.get(k)]
    over = tokens(digest) > MAX_DIGEST_TOKENS
    return {"valid": not missing and not over, "missing": missing,
            "tokens": tokens(digest), "over_budget": over, "parsed": d}