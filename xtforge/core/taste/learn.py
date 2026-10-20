"""The taste decision model: deterministic, explainable, contradiction-safe.

Command Code runs an LLM extractor over a proprietary `taste-1` classifier.
We cannot ship their classifier, so this is the clean-room equivalent: a
Beta-dose counter over a fixed category vocabulary. No sampling, no model
call, no hidden state — the same ordered signals always produce the same
learning, which is what makes the profile auditable.

Confidence is `alpha / (alpha + beta)`:
  - supporting evidence raises alpha, contradicting evidence raises beta
  - a balance flip swaps the arms and adopts the opposing statement
  - both arms above 1.5 means the preference is genuinely contested: the
    learning is marked `conflict` and is never injected into a session
"""
from __future__ import annotations

import time
from typing import Any

from .schema import (ALPHA0, BETA0, ENFORCED_MIN_CONFIDENCE,
                     ENFORCED_MIN_EVIDENCE, HINT_MIN_CONFIDENCE, Learning,
                     RETIRE_AFTER_DAYS, Signal, learning_id)


def confidence(alpha: float, beta: float) -> float:
    total = alpha + beta
    return alpha / total if total > 0 else 0.0


def status_for(alpha: float, beta: float, evidence: int,
               retired: bool = False) -> str:
    """Classify a learning from its dose counts.

    weak      evidence is thin or the balance is close
    hint      usable, but not settled
    enforced  settled: high confidence and at least three pieces of evidence
    conflict  genuinely contested: both sides carry real evidence
    """
    if retired:
        return "retired"
    support = alpha - ALPHA0
    against = beta - BETA0
    if support >= 1.5 and against >= 1.5 and confidence(alpha, beta) < 0.75:
        return "conflict"
    conf = confidence(alpha, beta)
    if conf >= ENFORCED_MIN_CONFIDENCE and evidence >= ENFORCED_MIN_EVIDENCE:
        return "enforced"
    if conf >= HINT_MIN_CONFIDENCE and max(support, against) >= 1.0:
        return "hint"
    return "weak"


def new_learning(signal: Signal, scope: str = "global",
                 now: int | None = None) -> Learning:
    ts = int(now if now is not None else time.time())
    return Learning(
        id=learning_id(scope, signal.category, signal.key),
        scope=scope, category=signal.category, key=signal.key,
        statement=signal.statement, polarity=signal.polarity,
        alpha=ALPHA0, beta=BETA0, status="weak", evidence=0,
        first_seen=ts, last_seen=ts,
    )


def absorb(learning: Learning, signal: Signal,
           now: int | None = None) -> dict[str, Any]:
    """Fold one signal into a learning. Returns an explainable delta."""
    ts = int(now if now is not None else time.time())
    before = {"confidence": round(learning.confidence, 4),
              "status": learning.status, "polarity": learning.polarity}
    supporting = learning.evidence == 0 or signal.polarity == learning.polarity

    if learning.evidence == 0:
        # First evidence defines the statement; there is nothing to contradict.
        learning.statement = signal.statement
        learning.polarity = signal.polarity
        learning.alpha += signal.weight
    elif signal.polarity == learning.polarity:
        learning.alpha += signal.weight
    else:
        learning.beta += signal.weight
        if learning.beta > learning.alpha:
            # The balance flipped: adopt the opposing statement and swap arms
            # so alpha always means "support for what the row now claims".
            learning.polarity = signal.polarity
            learning.statement = signal.statement
            learning.alpha, learning.beta = learning.beta, learning.alpha

    learning.evidence += 1
    learning.last_seen = ts
    if not learning.first_seen:
        learning.first_seen = ts
    learning.status = status_for(learning.alpha, learning.beta,
                                 learning.evidence, learning.retired)
    return {
        "id": learning.id,
        "before": before,
        "after": {"confidence": round(learning.confidence, 4),
                  "status": learning.status, "polarity": learning.polarity},
        "supporting": supporting,
        "weight": signal.weight,
        "kind": signal.kind,
    }


def retire_stale(learnings: list[Learning], now: int | None = None,
                 after_days: int = RETIRE_AFTER_DAYS) -> list[Learning]:
    """Retire learnings with no recent evidence. Returns those changed."""
    ts = int(now if now is not None else time.time())
    cutoff = ts - after_days * 86400
    changed = []
    for learning in learnings:
        if learning.retired or learning.evidence == 0:
            continue
        if learning.last_seen < cutoff:
            learning.retired = True
            learning.status = status_for(learning.alpha, learning.beta,
                                         learning.evidence, retired=True)
            changed.append(learning)
    return changed


def enforced(learnings: list[Learning]) -> list[Learning]:
    """The only learnings allowed into a session's context."""
    return [learning for learning in learnings
            if learning.status == "enforced"]


def summarize(learnings: list[Learning]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for learning in learnings:
        counts[learning.status] = counts.get(learning.status, 0) + 1
    return {
        "total": len(learnings),
        "by_status": dict(sorted(counts.items())),
        "enforced": len(enforced(learnings)),
        "conflicts": counts.get("conflict", 0),
    }
