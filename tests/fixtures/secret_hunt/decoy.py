"""Plausible config that must produce ZERO scan findings.

Every credential-looking value here is either read from the environment, a
placeholder, or shorter than a real secret. The scan fixture fails if this
file reports anything.
"""
from __future__ import annotations

import hashlib
import os
from typing import Optional

API_TOKEN: Optional[str] = os.environ.get("API_TOKEN")
DATABASE_URL = os.environ["DATABASE_URL"]
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
TOKEN = os.environ["AUTH_TOKEN"]


def ask_password() -> str:
    return input("enter password: ")


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Auth:
    def __init__(self) -> None:
        self.token = self._resolve()

    def _resolve(self) -> str:
        return ""


AUTH_BACKEND = "none"
TEMPLATE = "${SECRET}"
PLACEHOLDER_KEY = "CHANGEME"  # 8 chars, not a secret
DEFAULT_LABEL = "local-dev-only"
MAX_RETRIES = 3
