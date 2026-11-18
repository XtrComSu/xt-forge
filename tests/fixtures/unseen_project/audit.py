"""Structured audit event sink."""
from __future__ import annotations

import json
import time


class AuditLog:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def append(self, actor: str, action: str, target: str) -> str:
        entry = {
            "ts": round(time.time(), 3),
            "actor": actor,
            "action": action,
            "target": target,
        }
        self.records.append(entry)
        return json.dumps(entry, sort_keys=True)
