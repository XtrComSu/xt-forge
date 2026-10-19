"""Artifact spool (F5): tool output above the cap becomes runs/<id>/artifacts/<n>.txt."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ...version import artifacts_dir
from .passes import est_tokens

CAP_TOKENS = 4000


def _next_index(d: Path) -> int:
    d.mkdir(parents=True, exist_ok=True)
    mx = 0
    for p in d.glob("*.txt"):
        m = re.match(r"^(\d+)\.txt$", p.name)
        if m:
            mx = max(mx, int(m.group(1)))
    return mx + 1


def spool(text: str, run_id: str) -> dict[str, Any]:
    """Store oversized output on disk; return a short reference marker."""
    n = _next_index(artifacts_dir(run_id))
    path = artifacts_dir(run_id) / f"{n}.txt"
    path.write_text(text or "", encoding="utf-8")
    return marker(n, text, str(path))


def marker(n: int, text: str, path: str | None = None) -> dict[str, Any]:
    lines = (text or "").split("\n")
    return {"n": n, "path": path, "bytes": len((text or "").encode("utf-8")),
            "lines": len(lines), "ref": f"[ARTIFACT:{n} bytes={len((text or '').encode('utf-8'))} "
                                        f"lines={len(lines)} head/tail shown]"}


def _split(text: str) -> tuple[str, str]:
    lines = (text or "").split("\n")
    if len(lines) <= 30:
        return text, ""
    return "\n".join(lines[:15]), "\n".join(lines[-15:])


def maybe_spool(text: str, run_id: str, cap_tokens: int = CAP_TOKENS) -> dict[str, Any]:
    """Returns {stored: bool, text: str, artifact: dict|null}."""
    if est_tokens(text) <= cap_tokens:
        return {"stored": False, "text": text, "artifact": None}
    art = spool(text, run_id)
    head, tail = _split(text)
    kept = f"{art['ref']}\n--- head ---\n{head}\n--- tail ---\n{tail}"
    return {"stored": True, "text": kept, "artifact": art}


def read_slice(run_id: str, n: int, start: int = 1, count: int = 50,
               grep: str | None = None) -> dict[str, Any]:
    path = artifacts_dir(run_id) / f"{n}.txt"
    if not path.exists():
        return {"ok": False, "err": f"artifact {n} not found"}
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    if grep:
        pat = re.compile(grep)
        hits = [{"line": i + 1, "text": l} for i, l in enumerate(lines) if pat.search(l)]
        return {"ok": True, "n": n, "grep": grep, "matches": hits[:200],
                "total": len(hits)}
    s = max(1, start)
    e = s + max(0, count)
    return {"ok": True, "n": n, "start": s, "end": min(e, len(lines) + 1),
            "total_lines": len(lines),
            "lines": [{"line": i + 1, "text": lines[i]} for i in range(s - 1, min(e - 1, len(lines)))]}