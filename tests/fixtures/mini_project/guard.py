"""Write safety: allowlisted roots, one-shot confirm tokens.

Reads are unrestricted inside the project; writes need to land inside an
allowlisted root and, for destructive operations, a confirm token that was
issued for this run only.
"""
from __future__ import annotations

import secrets
from pathlib import Path


class Denied(Exception):
    """A write was refused; `code` explains which rule fired."""


ALLOWED_ROOTS = ("/tmp", "/var/tmp", "/home")


def is_allowed(path: str | Path) -> bool:
    resolved = str(Path(path).expanduser().resolve())
    return any(resolved.startswith(root + "/") or resolved == root
               for root in ALLOWED_ROOTS)


def write_guard(path: str | Path, write: bool = False,
                confirm_token: str | None = None) -> dict[str, object]:
    """Return an allow/deny decision for a write.

    write=False is always allowed (a dry run). Destructive writes additionally
    need a token minted by `issue_token` in this process.
    """
    if not write:
        return {"allowed": True, "reason": "dry_run"}
    if not is_allowed(path):
        raise Denied(f"path outside allowlisted roots: {path}", "root_denied")
    if not confirm_token or not _consume(confirm_token):
        raise Denied("missing or reused confirm token", "confirm_required")
    return {"allowed": True, "reason": "confirmed"}


def issue_token() -> str:
    """Mint a one-shot token; it is invalid after the first use."""
    token = secrets.token_hex(16)
    _TOKENS.add(token)
    return token


_TOKENS: set[str] = set()


def _consume(token: str) -> bool:
    if token in _TOKENS:
        _TOKENS.discard(token)
        return True
    return False
