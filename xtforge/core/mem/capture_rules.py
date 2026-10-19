"""Deterministic auto-capture rules (F2): no LLM. Stage candidates at confidence 0.5."""
from __future__ import annotations

import re
from typing import Any, Iterable

CAPTURE_CONFIDENCE = 0.5

# (rule_name, regex over a log line)
DECISION_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("decision_marker", re.compile(r"^\s*(?:DECISION|CHOSE|CHOSEN)\s*[:=]\s*(?P<v>.+)$", re.I)),
    ("decision_word", re.compile(r"\b(?:we|i)\s+(?:decided|chose|picked)\s+(?:to\s+)?(?P<v>.{5,160})", re.I)),
    ("adr", re.compile(r"\bADR[- ]?\d+\b.*?\b(?P<v>.{5,160})")),
]

ERROR_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("traceback", re.compile(r"^\s*Traceback \(most recent call last\):?\s*(?P<v>.*)$")),
    ("exception", re.compile(r"^\s*(?P<v>\w*(?:Error|Exception|Warning)\b.{0,140})$")),
    ("assert", re.compile(r"^\s*(?P<v>(?:AssertionError|assert\b).{0,140})$", re.I)),
    ("failed_cmd", re.compile(r"^\s*(?:FAILED|ERROR:)\s+(?P<v>.{0,140})$", re.I)),
    ("test_fail", re.compile(r"^\s*(?P<v>\d+ (?:failed|error)s? in \d+\.\d+s)", re.I)),
]

_DECISION_KIND = "decision"
_ERROR_KIND = "error_pattern"


def extract_candidates(lines: Iterable[str], source: str = "") -> list[dict[str, Any]]:
    """Return pending candidate records from raw log lines. Deterministic."""
    out: list[dict[str, Any]] = []
    for raw in lines:
        line = (raw or "").rstrip()
        if not line.strip():
            continue
        for name, pat in ERROR_RULES:
            m = pat.search(line)
            if m:
                out.append({"kind": _ERROR_KIND, "title": _sig(line),
                            "body": line.strip()[:400], "source": source,
                            "rule": name})
                break
        for name, pat in DECISION_RULES:
            m = pat.search(line)
            if m:
                out.append({"kind": _DECISION_KIND, "title": m.group("v").strip()[:80],
                            "body": line.strip()[:400], "source": source,
                            "rule": name})
                break
    return _dedupe(out)


def _sig(line: str) -> str:
    line = line.strip()
    return line[:80] if line else "error"


def _dedupe(cands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for c in cands:
        key = (c["kind"], c["body"][:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out