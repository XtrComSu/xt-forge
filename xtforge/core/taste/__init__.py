"""Taste: local, deterministic preference learning.

Four stages, mirroring the architecture Command Code documents and replacing
the parts we cannot ship:

    extract  -> learn   -> store        -> inject
    (regex)    (Beta)     (SQLite + md)   (OpenCode plugin, round 9)

Extraction is a pattern grammar, the decision model is arithmetic, and storage
is a plain database. Nothing here calls a model; `learn.py` explains every
confidence change as a delta you can read.
"""
from __future__ import annotations

from .block import render_block
from .extract import extract, extract_one
from .learn import absorb, enforced, new_learning, status_for, summarize
from .schema import CATEGORIES, SIGNAL_KINDS, Learning, Signal
from .store import TasteStore

__all__ = [
    "CATEGORIES", "SIGNAL_KINDS", "Learning", "Signal", "TasteStore",
    "absorb", "enforced", "extract", "extract_one", "new_learning",
    "render_block", "status_for", "summarize",
]
