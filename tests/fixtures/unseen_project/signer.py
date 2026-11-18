"""HMAC signature checks and request nonces."""
from __future__ import annotations

import hashlib
import secrets


def mint_nonce() -> str:
    return secrets.token_hex(12)


def verify_signature(secret: bytes, payload: bytes, expected_hex: str) -> None:
    digest = hashlib.sha256(secret + payload).hexdigest()
    if digest != expected_hex:
        raise PermissionError("invalid hmac signature")
