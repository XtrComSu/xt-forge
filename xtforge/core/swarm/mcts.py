"""Speculative multi-hypothesis solver for obfuscated or encrypted binary data."""
from __future__ import annotations

import base64
import zlib
from pathlib import Path
from typing import Any

from ..route import guard
from .worker import SwarmPool

KEYWORD_BONUSES = (
    b"http", b"token", b"pass", b"admin", b"system", b"bypass",
    b"user", b"config", b"error", b"kernel", b"wine", b"ntdll",
    b"MZ", b"\x7fELF",
)


COMMON_BIGRAMS = (
    b"th", b"he", b"in", b"er", b"an", b"re", b"ed", b"on", b"es", b"st",
    b"en", b"at", b"to", b"nt", b"ha", b"nd", b"ou", b"ea", b"ng", b"as",
    b"or", b"ti", b"is", b"et", b"it", b"ar", b"te", b"se", b"hi", b"of",
    b"io", b"ss", b"ey", b"ke", b"ic", b"ca", b"al", b"de", b"ro", b"lo",
)


def _score_plain(data: bytes) -> float:
    """Score decoded bytes by letter/word density, bigrams, and vowel distribution."""
    if not data:
        return 0.0
    s = 0.0
    for b in data:
        if (65 <= b <= 90) or (97 <= b <= 122):
            s += 3.0
        elif (48 <= b <= 57) or b in (32, 9, 10, 13, 95):  # digits, space, newline, underscore
            s += 2.0
        elif 32 <= b <= 126:
            s += 0.5
        else:
            s -= 3.0

    score = (s / (len(data) * 3.0)) * 100.0

    lower = data.lower()
    # Bonus for common bigrams
    for bg in COMMON_BIGRAMS:
        if bg in lower:
            score += 5.0

    # Natural language vowel ratio check
    vowels = sum(1 for b in lower if b in b"aeiou")
    v_ratio = vowels / max(1, len(data))
    if 0.25 <= v_ratio <= 0.50:
        score += 20.0

    for kw in KEYWORD_BONUSES:
        if kw in lower:
            score += 25.0

    return score


def _try_xor_single(data: bytes) -> tuple[float, int, bytes]:
    best_score = 0.0
    best_key = 0
    best_out = b""
    for k in range(1, 256):
        out = bytes(b ^ k for b in data)
        score = _score_plain(out)
        if score > best_score:
            best_score = score
            best_key = k
            best_out = out
    return best_score, best_key, best_out


def _try_xor_rolling(data: bytes) -> tuple[float, int, bytes]:
    best_score = 0.0
    best_key = 0
    best_out = b""
    for k in range(1, 256):
        out = bytes(b ^ ((k + i) & 0xFF) for i, b in enumerate(data))
        score = _score_plain(out)
        if score > best_score:
            best_score = score
            best_key = k
            best_out = out
    return best_score, best_key, best_out


def _try_b64(data: bytes) -> tuple[float, None, bytes]:
    try:
        dec = base64.b64decode(data, validate=False)
        return _score_plain(dec), None, dec
    except Exception:
        return 0.0, None, b""


def _try_zlib(data: bytes) -> tuple[float, None, bytes]:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
        try:
            dec = zlib.decompress(data, wbits)
            return _score_plain(dec), None, dec
        except Exception:
            pass
    return 0.0, None, b""


def speculative_solve(
    target: str | Path,
    offset: int = 0,
    size: int = 256,
    hypotheses: list[str] | None = None,
    workers: int = 4,
) -> dict[str, Any]:
    """Test speculative decoding hypotheses concurrently across a swarm."""
    canon = guard.read_guard(target)
    if not canon.is_file():
        return {"ok": False, "err": "target is not a file"}

    data = canon.read_bytes()
    if offset < 0 or offset >= len(data):
        return {"ok": False, "err": f"offset {offset} out of bounds"}

    chunk = data[offset : offset + size]
    if not chunk:
        return {"ok": False, "err": "empty data slice"}

    active_hypotheses = hypotheses or ["xor_single", "xor_rolling", "b64", "zlib"]
    tasks = []

    for hyp in active_hypotheses:
        if hyp == "xor_single":
            tasks.append(("xor_single", lambda c=chunk: _try_xor_single(c)))
        elif hyp == "xor_rolling":
            tasks.append(("xor_rolling", lambda c=chunk: _try_xor_rolling(c)))
        elif hyp == "b64":
            tasks.append(("b64", lambda c=chunk: _try_b64(c)))
        elif hyp == "zlib":
            tasks.append(("zlib", lambda c=chunk: _try_zlib(c)))

    pool = SwarmPool(workers=workers)
    runner_callables = [t[1] for t in tasks]
    raw_results = pool.run_all(runner_callables)

    best_score = -1.0
    best_hyp = ""
    best_key = None
    best_data = b""

    for idx, r in enumerate(raw_results):
        if r["ok"]:
            score, key, decoded = r["result"]
            hyp_name = tasks[idx][0]
            if score > best_score:
                best_score = score
                best_hyp = hyp_name
                best_key = key
                best_data = decoded

    sample_str = best_data[:200].decode("latin1", "replace")

    return {
        "ok": True,
        "offset": hex(offset),
        "size": len(chunk),
        "winning_hypothesis": best_hyp,
        "score": round(best_score, 1),
        "key": best_key,
        "hex_key": hex(best_key) if isinstance(best_key, int) else None,
        "decoded_sample": sample_str,
        "hypotheses_evaluated": len(tasks),
    }
