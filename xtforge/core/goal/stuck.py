"""Stuck detection (F3): identical digests, no diffs, repeated error signatures."""
from __future__ import annotations

from typing import Any

from ..compress import digest as dg

NO_PROGRESS_K = 2
ERROR_SIG_LIMIT = 3


def error_signatures(report: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for e in (report.get("errors") or []):
        sig = e.get("sig") if isinstance(e, dict) else str(e)
        if sig:
            out.append(dg.error_sig(str(sig)))
    return out


class StuckDetector:
    """Tracks the last K digest hashes, error signatures and file-change state."""

    def __init__(self, k: int = NO_PROGRESS_K):
        self.k = max(1, k)
        self.digests: list[str] = []
        self.error_sigs: list[str] = []
        self.changed_flags: list[bool] = []
        self.evidence_counts: list[int] = []

    def observe(self, report: dict[str, Any], changed_files: bool,
                new_evidence: bool) -> None:
        self.digests.append(dg.digest_hash(report.get("state_digest", "")))
        self.changed_flags.append(bool(changed_files))
        self.evidence_counts.append(int(new_evidence))
        for sig in error_signatures(report):
            self.error_sigs.append(sig)

    def is_stuck(self) -> tuple[bool, str]:
        """Return (stuck, reason). K consecutive no-progress rounds trip it.

        No-progress = no file changes AND no new evidence. Among no-progress
        rounds, an identical state digest is an additional, faster signal.
        """
        if len(self.changed_flags) < self.k:
            return False, ""
        recent_changed = self.changed_flags[-self.k:]
        recent_evidence = self.evidence_counts[-self.k:]
        if not any(recent_changed) and not any(recent_evidence):
            recent_digests = self.digests[-self.k:]
            if len(set(recent_digests)) == 1:
                return True, f"identical state digest for {self.k} rounds with no progress"
            return True, f"no file changes and no new evidence for {self.k} rounds"
        return False, ""

    def repeated_error(self, limit: int = ERROR_SIG_LIMIT) -> tuple[bool, str]:
        if not self.error_sigs:
            return False, ""
        counts: dict[str, int] = {}
        for s in self.error_sigs:
            counts[s] = counts.get(s, 0) + 1
        worst = max(counts.items(), key=lambda kv: kv[1])
        if worst[1] >= limit:
            return True, f"error signature repeated {worst[1]}x: {worst[0]}"
        return False, ""

    def status(self) -> dict[str, Any]:
        stuck, reason = self.is_stuck()
        err, err_reason = self.repeated_error()
        return {"rounds_seen": len(self.changed_flags), "stuck": stuck,
                "stuck_reason": reason, "error_loop": err,
                "error_reason": err_reason, "k": self.k}