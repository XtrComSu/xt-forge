"""Compression and oversized payload spilling helpers."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ...version import cache_dir
from .passes import compress


def clip_or_spill(payload: Any, *, max_bytes: int = 16384) -> Any:
    """Return payload inline if small, else spill full JSON to cache/artifacts/ and return preview."""
    raw = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    raw_bytes = raw.encode("utf-8", errors="replace")
    if len(raw_bytes) <= max_bytes:
        return payload
    digest = hashlib.sha256(raw_bytes).hexdigest()[:16]
    adir = cache_dir() / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    out_path = adir / f"spill_{digest}.json"
    out_path.write_text(raw, encoding="utf-8")
    comp = compress(raw, level="L1")
    return {
        "spilled": True,
        "artifact_path": str(out_path),
        "bytes": len(raw_bytes),
        "preview": comp["text"][:1500],
    }
