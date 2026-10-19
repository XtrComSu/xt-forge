"""JSONL run log with size-based rotation (R9: all state on disk).

Header line records prompt/artifact hashes so runs are auditable.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ...version import version_str

MAX_BYTES = 512 * 1024
KEEP = 3


class RunLog:
    def __init__(self, path: str | Path, run_id: str = "-"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id

    def header(self, meta: dict | None = None, **extra: Any) -> None:
        rec = {"ts": time.time(), "run_id": self.run_id, "ev": "header",
               "xt_version": version_str()}
        if meta:
            rec.update(meta)
        rec.update(extra)
        from ...atomicio import append_jsonl
        append_jsonl(self.path, rec)

    def write(self, ev: Any, **fields: Any) -> None:
        rec = {"ts": time.time(), "run_id": self.run_id, "ev": ev, **fields}
        line = _json(rec)
        self._rotate_if_needed(len(line) + 1)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _rotate_if_needed(self, incoming: int) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size + incoming > MAX_BYTES:
                self.rotate()
        except OSError:
            pass

    def rotate(self) -> None:
        for i in range(KEEP - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{i}")
            if src.exists():
                os.replace(src, self.path.with_suffix(self.path.suffix + f".{i + 1}"))
        if self.path.exists():
            os.replace(self.path, self.path.with_suffix(self.path.suffix + ".1"))


def _json(rec: dict) -> str:
    import json
    return json.dumps(rec, ensure_ascii=False, default=str, sort_keys=True)


def read_log(path: str | Path, limit: int | None = None) -> list[dict]:
    import json
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit is not None and len(out) > limit:
        return out[-limit:]
    return out