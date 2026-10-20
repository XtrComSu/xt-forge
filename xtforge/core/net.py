"""Cached JSON over HTTP.

Three rules, learned the hard way:

1. **Cache on disk.** NVD without an API key is slow and rate-limited; the KEV
   catalog is 1.7 MB. A verb run twice should cost one request.
2. **Never hang.** Every call has a hard timeout and returns an error tuple
   instead of raising into the caller.
3. **Work offline when asked.** `XT_NET_OFFLINE=1` makes every call serve from
   cache or fail honestly — tests must never depend on a live third party.

Cache entries live in `$XT_HOME/cache/net/`, keyed by the request. They are
plain files so they can be inspected or deleted by hand.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..version import cache_dir

UA = "xt-forge/0.4 (+intel)"
DEFAULT_TIMEOUT = 20
MAX_BODY = 8 << 20


def offline() -> bool:
    return os.environ.get("XT_NET_OFFLINE", "").strip() not in ("", "0", "false")


def _cache_file(key: str) -> Path:
    directory = cache_dir() / "net"
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return directory / f"{digest}.json"


def _read_cache(key: str, ttl: int) -> tuple[bool, Any]:
    path = _cache_file(key)
    if not path.is_file():
        return False, None
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, None
    age = time.time() - float(entry.get("at") or 0)
    if ttl > 0 and age > ttl:
        return False, None
    return True, entry.get("payload")


def _write_cache(key: str, payload: Any) -> None:
    try:
        _cache_file(key).write_text(
            json.dumps({"at": time.time(), "payload": payload}),
            encoding="utf-8")
    except OSError:
        pass          # a cache miss is not worth failing a query over


def get_json(url: str, *, headers: dict[str, str] | None = None,
             timeout: int = DEFAULT_TIMEOUT, ttl: int = 0,
             method: str = "GET", body: Any = None,
             form: dict[str, Any] | None = None,
             max_body: int = MAX_BODY) -> tuple[bool, Any, str]:
    """Fetch JSON. Returns (ok, payload, error). Never raises."""
    key = (f"{method} {url} "
           f"{json.dumps(body, sort_keys=True) if body else ''}"
           f"{json.dumps(form, sort_keys=True) if form else ''}")
    if ttl > 0:
        hit, payload = _read_cache(key, ttl)
        if hit:
            return True, payload, ""
    if offline():
        hit, payload = _read_cache(key, 0)
        if hit:
            return True, payload, ""
        return False, None, "offline (XT_NET_OFFLINE=1) and no cached copy"

    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", UA)
    if form is not None:
        request.add_header("Content-Type",
                           "application/x-www-form-urlencoded")
    for name, value in (headers or {}).items():
        request.add_header(name, value)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(max_body + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(64_000) if exc.fp else b""
        status = exc.code
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, None, f"network: {exc}"

    text = raw.decode("utf-8", "replace")
    if len(raw) > max_body:
        return False, None, f"response larger than {max_body} bytes"

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # Some APIs answer with a bare string; keep it rather than lose it.
        payload = text

    if status in (200, 201):
        if ttl > 0:
            _write_cache(key, payload)
        return True, payload, ""
    # 404 is a real answer for reputation APIs: "I have never seen this".
    if status == 404:
        return False, payload, "not found"
    return False, payload, f"http {status}"


def quote(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")
