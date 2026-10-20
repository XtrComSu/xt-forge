"""Error taxonomy.

One hierarchy so callers can catch `MiniError` and branch on `code` without
string matching on messages. Codes are stable and documented here.
"""
from __future__ import annotations


class MiniError(Exception):
    """Base for every error this package raises."""

    code = "internal"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        if code:
            self.code = code

    def payload(self) -> dict[str, str]:
        return {"error": self.code, "message": str(self)}


class ValidationError(MiniError):
    """Input failed a rule before any work happened."""
    code = "invalid_input"


class NotFound(MiniError):
    """The requested record does not exist."""
    code = "not_found"


class Conflict(MiniError):
    """The request conflicts with current state."""
    code = "conflict"


class Unavailable(MiniError):
    """A dependency is down; retry later."""
    code = "unavailable"


def classify(exc: BaseException) -> str:
    """Map an arbitrary exception to a stable error code."""
    if isinstance(exc, MiniError):
        return exc.code
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    return "internal"
