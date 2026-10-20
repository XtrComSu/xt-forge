"""Codec toolkit: hashing, encoding, entropy and format inspection.

The CyberChef-shaped Swiss army knife, stdlib-only and offline: every value
you paste in is handled locally, because half the time the value is a secret
and the other half it is evidence.

    xtforge codec hash --algo sha256 "text"
    xtforge codec encode --scheme base64 "text"
    xtforge codec decode --scheme hex 68656c6c6f
    xtforge codec entropy --path suspicious.bin
    xtforge codec inspect eyJhbGciOi...

Round-tripping is guaranteed for every reversible scheme, and `inspect`
tells you what a value *is* before you decide what to do with it.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
import urllib.parse
import uuid as uuidlib
from typing import Any, Callable

# ------------------------------------------------------------------ hashing

HASHES: dict[str, Callable[[bytes], str]] = {
    "md5": lambda d: hashlib.md5(d).hexdigest(),
    "sha1": lambda d: hashlib.sha1(d).hexdigest(),
    "sha256": lambda d: hashlib.sha256(d).hexdigest(),
    "sha512": lambda d: hashlib.sha512(d).hexdigest(),
    "sha3_256": lambda d: hashlib.sha3_256(d).hexdigest(),
    "blake2b": lambda d: hashlib.blake2b(d).hexdigest(),
    "blake2s": lambda d: hashlib.blake2s(d).hexdigest(),
    "crc32": lambda d: format(binascii.crc32(d) & 0xFFFFFFFF, "08x"),
}


def digest(data: bytes, algo: str = "sha256") -> dict[str, Any]:
    """Hash bytes. `all` returns every supported algorithm."""
    if algo == "all":
        return {"length": len(data),
                "digests": {name: fn(data) for name, fn in HASHES.items()}}
    fn = HASHES.get(algo)
    if fn is None:
        raise ValueError(f"unknown hash algorithm: {algo}; "
                         f"try one of {sorted(HASHES)} or 'all'")
    return {"length": len(data), "algorithm": algo, "digest": fn(data)}


# ------------------------------------------------------------------ encoding

def _b64_encode(raw: bytes, url: bool = False) -> str:
    out = base64.urlsafe_b64encode(raw) if url else base64.b64encode(raw)
    return out.decode("ascii").rstrip("=")


def _b64_decode(text: str, url: bool = False) -> bytes:
    padded = text.strip() + "=" * (-len(text.strip()) % 4)
    if url:
        return base64.urlsafe_b64decode(padded)
    return base64.b64decode(padded, validate=False)


def _hex_encode(raw: bytes) -> str:
    return raw.hex()


def _hex_decode(text: str) -> bytes:
    cleaned = re.sub(r"[\s:]", "", text.strip())
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return bytes.fromhex(cleaned)


def _binary_encode(raw: bytes) -> str:
    return " ".join(f"{byte:08b}" for byte in raw)


def _binary_decode(text: str) -> bytes:
    parts = [p for p in re.split(r"[\s,]+", text.strip()) if p]
    return bytes(int(p, 2) for p in parts)


def _rot13(text: str) -> str:
    def shift(ch: str) -> str:
        base = ord("A") if ch.isupper() else ord("a")
        return chr(base + (ord(ch) - base + 13) % 26) if ch.isalpha() else ch
    return "".join(shift(ch) for ch in text)


SCHEMES: dict[str, dict[str, Callable[..., Any]]] = {
    "base64": {"encode": _b64_encode, "decode": _b64_decode},
    "base64url": {"encode": lambda b: _b64_encode(b, url=True),
                  "decode": lambda s: _b64_decode(s, url=True)},
    "base32": {"encode": lambda b: base64.b32encode(b).decode("ascii").rstrip("="),
               "decode": lambda s: base64.b32decode(s.strip() + "=" * (-len(s.strip()) % 8))},
    "hex": {"encode": _hex_encode, "decode": _hex_decode},
    "binary": {"encode": _binary_encode, "decode": _binary_decode},
    "url": {"encode": lambda b: urllib.parse.quote(b.decode("utf-8", "replace"), safe=""),
            "decode": lambda s: urllib.parse.unquote_to_bytes(s.strip())},
    "html": {"encode": lambda b: html.escape(b.decode("utf-8", "replace")),
             "decode": lambda s: html.unescape(s.strip()).encode("utf-8")},
    "rot13": {"encode": lambda b: _rot13(b.decode("utf-8", "replace")),
              "decode": lambda s: _rot13(s)},
    "upper": {"encode": lambda b: b.decode("utf-8", "replace").upper(),
              "decode": lambda s: s.lower()},
    "reverse": {"encode": lambda b: b.decode("utf-8", "replace")[::-1],
                "decode": lambda s: s[::-1]},
}

# Schemes where decode(encode(x)) == x. `upper` is offered but lossy: it is a
# transform, not a codec, so `codec roundtrip` correctly reports it as broken.
REVERSIBLE = {"base64", "base64url", "base32", "hex", "binary", "url", "html",
              "rot13", "reverse"}


def encode(data: bytes, scheme: str = "base64") -> str:
    entry = SCHEMES.get(scheme)
    if entry is None:
        raise ValueError(f"unknown scheme: {scheme}; try one of {sorted(SCHEMES)}")
    out = entry["encode"](data)
    return out if isinstance(out, str) else out.decode("utf-8", "replace")


def decode(text: str, scheme: str = "base64") -> bytes:
    entry = SCHEMES.get(scheme)
    if entry is None:
        raise ValueError(f"unknown scheme: {scheme}; try one of {sorted(SCHEMES)}")
    out = entry["decode"](text)
    return out if isinstance(out, bytes) else str(out).encode("utf-8")


# ------------------------------------------------------------------ entropy

def shannon(data: bytes) -> float:
    """Bits of entropy per byte; 0 for constant, ~8 for random."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    import math
    value = -sum((n / total) * math.log2(n / total) for n in counts if n)
    return 0.0 if value == 0 else value


def entropy_report(data: bytes, block: int = 0, limit: int = 32) -> dict[str, Any]:
    overall = round(shannon(data), 4)

    def verdict(value: float) -> str:
        if value >= 7.0:
            return "random_or_encrypted"
        if value >= 5.5:
            return "mixed"
        if value >= 3.5:
            return "structured"
        return "low"

    out: dict[str, Any] = {"length": len(data), "entropy": overall,
                           "bits_per_byte": overall, "verdict": verdict(overall)}
    if block and block > 0:
        size = max(4, int(block))
        blocks = []
        for offset in range(0, len(data), size):
            chunk = data[offset:offset + size]
            value = round(shannon(chunk), 4)
            blocks.append({"offset": offset, "size": len(chunk),
                           "entropy": value, "verdict": verdict(value)})
            if len(blocks) >= max(1, int(limit)):
                break
        out["block_size"] = size
        out["blocks"] = blocks
        out["truncated"] = len(data) > size * len(blocks)
    return out


# ------------------------------------------------------------------ inspect

_JWT = re.compile(r"^([A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]*)$")
_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)([-+][0-9A-Za-z.\-+]+)?$")
_COLOR = re.compile(r"^#?([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$")
_TIMESTAMP = re.compile(r"^\d{10}(\d{3})?$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


def _iso(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def inspect(value: str) -> dict[str, Any]:
    """Identify a value and decode it where the shape is unambiguous."""
    text = (value or "").strip()
    findings: list[dict[str, Any]] = []
    if not text:
        return {"ok": False, "err": "empty input", "findings": []}

    jwt = _JWT.match(text)
    if jwt:
        parts = []
        for index, name in ((0, "header"), (1, "payload")):
            try:
                raw = _b64_decode(jwt.group(index + 1), url=True)
                parts.append({name: json.loads(raw.decode("utf-8", "replace"))})
            except Exception as exc:                       # noqa: BLE001
                parts.append({name: f"(undecodable: {exc.__class__.__name__})"})
        findings.append({"type": "jwt", "detail": parts})

    pem = _PEM.search(text)
    if pem:
        body = re.sub(r"-----[A-Z0-9 ]+-----|\s", "", text)
        findings.append({"type": "pem", "label": pem.group(1),
                         "body_chars": len(body),
                         "approx_der_bytes": int(len(body) * 3 / 4)})

    if _UUID.match(text):
        parsed = uuidlib.UUID(text)
        findings.append({"type": "uuid", "version": parsed.version,
                         "urn": parsed.urn})

    semver = _SEMVER.match(text)
    if semver:
        findings.append({"type": "semver", "major": int(semver.group(1)),
                         "minor": int(semver.group(2)),
                         "patch": int(semver.group(3)),
                         "suffix": semver.group(4) or ""})

    color = _COLOR.match(text)
    if color:
        hexpart = color.group(1)
        if len(hexpart) == 3:
            hexpart = "".join(ch * 2 for ch in hexpart)
        findings.append({"type": "color", "hex": f"#{hexpart.lower()}",
                         "rgb": tuple(int(hexpart[i:i + 2], 16) for i in (0, 2, 4))})

    if _TIMESTAMP.match(text):
        digits = len(text)
        ts = int(text) / (1000.0 if digits > 10 else 1.0)
        findings.append({"type": "unix_timestamp", "seconds": ts,
                         "iso": _iso(ts)})

    if _EMAIL.match(text) and "://" not in text:
        findings.append({"type": "email", "domain": text.split("@", 1)[1]})
    elif _URL.match(text):
        parsed = urllib.parse.urlparse(text)
        findings.append({"type": "url", "scheme": parsed.scheme,
                         "host": parsed.netloc,
                         "credentials_in_url": "@" in parsed.netloc})

    # Hex and base64 shapes last: they are the most ambiguous.
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", text) and len(text) % 2 == 0:
        raw = _hex_decode(text)
        findings.append({"type": "hex", "bytes": len(raw),
                         "ascii": raw.decode("ascii", "replace")
                         if all(32 <= b < 127 or b in (9, 10, 13) for b in raw)
                         else None})
    elif re.fullmatch(r"[A-Za-z0-9+/=_\-]{8,}", text) and len(text) % 4 in (0, 2, 3):
        try:
            raw = _b64_decode(text, url="-_" in text)
            if raw:
                printable = all(32 <= b < 127 or b in (9, 10, 13) for b in raw)
                findings.append({"type": "base64", "bytes": len(raw),
                                 "ascii": raw.decode("utf-8", "replace")
                                 if printable else None})
        except Exception:                                  # noqa: BLE001
            pass

    return {"ok": bool(findings), "input": text[:80],
            "findings": findings, "count": len(findings)}
