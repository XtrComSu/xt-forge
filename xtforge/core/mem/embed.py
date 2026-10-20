"""Optional embeddings for hybrid memory search.

Default backend is **deterministic and dependency-free**: a hashed bag of word
and character-trigram features. It is not a neural embedding; it exists to
catch word-shape similarity (inflections, stems, near-spellings) that exact
term matching misses, which is where FTS5 recall leaks.

A real embedding backend is used when `XT_EMBED_CMD` is set: the command reads
text on stdin and writes a JSON array of numbers on stdout. If it is missing,
slow or malformed, we fall back to the hash backend — retrieval never fails
because an optional model is absent.

Vectors are L2-normalized so similarity is a dot product.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from typing import Iterable

DIM = 256
_TOKEN = re.compile(r"[a-z0-9_]+", re.IGNORECASE)
_CMD_TIMEOUT = 5.0


def _hash32(text: str) -> int:
    """Stable across processes — unlike Python's salted `hash()`."""
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"),
                                          digest_size=8).digest(), "big")


def stem(word: str) -> str:
    """Light suffix stripping. Cheap, and it is where inflection leaks happen:
    'indexing'/'indexed' are one concept, 'licensing' and 'license' share a stem.
    """
    if len(word) > 4 and word.endswith("ing"):
        return word[:-3]
    if len(word) > 3 and word.endswith("ed"):
        return word[:-2]
    if len(word) > 3 and word.endswith("es"):
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def features(text: str) -> list[str]:
    """Word stems, character trigrams and prefix shapes of each word."""
    out: list[str] = []
    for word in _TOKEN.findall((text or "").lower()):
        out.append(f"w:{stem(word)}")
        out.append(f"p:{word[:5]}")
        padded = f"#{word}#"
        out.extend(f"c:{padded[i:i + 3]}" for i in range(len(padded) - 2))
    return out


def hash_embed(text: str, dim: int = DIM) -> list[float]:
    """Feature-hashed embedding: signed, sublinear TF, L2-normalized."""
    counts: dict[str, int] = {}
    for feat in features(text):
        counts[feat] = counts.get(feat, 0) + 1
    vec = [0.0] * dim
    for feat, count in counts.items():
        digest = _hash32(feat)
        index = digest % dim
        sign = 1.0 if (digest >> 63) & 1 else -1.0
        vec[index] += sign * (1.0 + _log(count))
    return normalize(vec)


def _log(count: int) -> float:
    """Sublinear TF: 1 + ln(n)."""
    import math
    return math.log(count) if count > 1 else 0.0


def normalize(vec: list[float]) -> list[float]:
    norm = sum(value * value for value in vec) ** 0.5
    if norm <= 0.0:
        return vec
    return [value / norm for value in vec]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


class Embedder:
    """Embedding backend with a capability probe and graceful fallback."""

    def __init__(self, mode: str = "auto", dim: int = DIM):
        self.dim = dim
        self.command = os.environ.get("XT_EMBED_CMD", "").strip() or None
        if mode == "off":
            self.mode = "off"
        elif mode == "hash":
            self.mode = "hash"
        elif self.command:
            self.mode = "cmd"
        else:
            self.mode = "hash"
        self.fallbacks = 0

    @property
    def available(self) -> bool:
        return self.mode != "off"

    @property
    def backend(self) -> str:
        return self.mode

    def embed(self, text: str) -> list[float] | None:
        if not self.available:
            return None
        if self.mode == "cmd":
            vec = self._embed_cmd(text)
            if vec is not None:
                return vec
            self.fallbacks += 1
        return hash_embed(text, self.dim)

    def embed_many(self, texts: Iterable[str]) -> list[list[float] | None]:
        return [self.embed(text) for text in texts]

    def _embed_cmd(self, text: str) -> list[float] | None:
        """Run the configured embedding command. Any failure is a fallback."""
        try:
            proc = subprocess.run(
                ["sh", "-c", self.command], input=text, capture_output=True,
                text=True, timeout=_CMD_TIMEOUT)
            if proc.returncode != 0:
                return None
            vec = json.loads(proc.stdout)
            if not isinstance(vec, list) or not vec:
                return None
            vec = [float(value) for value in vec]
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        return normalize(vec)


class VectorIndex:
    """Small in-memory vector index; one per search corpus.

    The hash backend builds sparse TF-IDF vectors at query time: raw hashed
    bag-of-features is noisy (common word shapes dominate), and inverse
    document frequency is the standard correction. The `cmd` backend gets
    plain cosine over its real vectors, which are already dense.
    """

    def __init__(self, embedder: Embedder):
        self.embedder = embedder
        self.vectors: dict[str, list[float]] = {}
        self.counts: dict[str, dict[str, int]] = {}
        self.df: dict[str, int] = {}

    def add(self, rec_id: str, text: str) -> None:
        if self.embedder.mode == "cmd":
            vec = self.embedder.embed(text)
            if vec is not None:
                self.vectors[rec_id] = vec
            return
        counts: dict[str, int] = {}
        for feat in features(text):
            counts[feat] = counts.get(feat, 0) + 1
        self.counts[rec_id] = counts
        for feat in counts:
            self.df[feat] = self.df.get(feat, 0) + 1

    def _idf(self, feat: str) -> float:
        import math
        n_docs = max(1, len(self.counts))
        return math.log((n_docs + 1) / (self.df.get(feat, 0) + 1)) + 1.0

    def _weight(self, counts: dict[str, int]) -> dict[str, float]:
        return {feat: (1.0 + _log(count)) * self._idf(feat)
                for feat, count in counts.items()}

    @staticmethod
    def _dot(a: dict[str, float], b: dict[str, float]) -> float:
        if len(b) < len(a):
            a, b = b, a
        return sum(value * b.get(feat, 0.0) for feat, value in a.items())

    def query(self, text: str, k: int = 50) -> list[tuple[str, float]]:
        if not self.vectors and not self.counts:
            return []
        if self.embedder.mode == "cmd":
            vec = self.embedder.embed(text)
            if vec is None:
                return []
            scored = [(rec_id, cosine(vec, other))
                      for rec_id, other in self.vectors.items()]
        else:
            query_counts: dict[str, int] = {}
            for feat in features(text):
                query_counts[feat] = query_counts.get(feat, 0) + 1
            query_vec = self._weight(query_counts)
            q_norm = sum(value * value for value in query_vec.values()) ** 0.5
            if q_norm <= 0.0:
                return []
            scored = []
            for rec_id, counts in self.counts.items():
                doc_vec = self._weight(counts)
                d_norm = sum(value * value for value in doc_vec.values()) ** 0.5
                if d_norm <= 0.0:
                    continue
                score = self._dot(query_vec, doc_vec) / (q_norm * d_norm)
                scored.append((rec_id, score))
        scored = [item for item in scored if item[1] > 0.0]
        scored.sort(key=lambda item: (-item[1], item[0]))
        return scored[:k]
