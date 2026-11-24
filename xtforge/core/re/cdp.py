"""Observe a live browser over the Chrome DevTools Protocol, with no third-party client.

The breadth matrix called this out of lane with the note "requires a running browser and
DevTools endpoint". That note was wrong twice: Chromium ships in the Playwright cache on this
host, and CDP is a documented protocol with an HTTP discovery surface plus RFC 6455 framing that
is about forty lines to speak. Measured, not assumed — a real `Runtime.evaluate` against
HeadlessChrome 141 returns its user agent.

Scope is deliberately observation, which is the question a reverse-engineer actually has when
looking at a packaged desktop app: what URLs does it open, what JavaScript does it run before
it settles, what does its DOM contain, and what does the page think its environment is. This is
not a test-automation driver and does not pretend to be one.

Why hand-roll the WebSocket: adding a dependency for one protocol, in a tool whose value
proposition is that it answers from its own engine, is the wrong trade. The frame format here
covers text frames, which is all CDP uses, and rejects anything else rather than guessing.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

MAX_MESSAGE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 20.0
_MAX_EVALUATIONS = 40

# Where a Playwright-managed Chromium usually lives, newest first.
_CHROME_CANDIDATES = (
    "~/.cache/ms-playwright/chromium-{v}/chrome-linux/chrome",
)
_CHROME_GLOBS = (
    "~/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
    "~/.cache/ms-playwright/chromium_headless_shell-*/chrome-linux/headless_shell",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/opt/google/chrome/chrome",
)


def find_browser() -> str | None:
    """Locate a Chromium build we can actually launch."""
    import glob
    for pattern in _CHROME_GLOBS:
        for candidate in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def _http_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read(MAX_MESSAGE_BYTES).decode("utf-8", "replace"))


class WebSocket:
    """The smallest RFC 6455 client that can carry CDP: text frames, no extensions."""

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ws":
            raise ValueError(f"only ws:// is supported, got {parsed.scheme!r}")
        self._sock = socket.create_connection((parsed.hostname, parsed.port or 80),
                                              timeout=timeout)
        self._buffer = b""
        key = base64.b64encode(os.urandom(16)).decode()
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        request = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {parsed.hostname}:{parsed.port}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self._sock.sendall(request.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise RuntimeError("CDP closed during the websocket handshake")
            head += chunk
            if len(head) > 64 * 1024:
                raise RuntimeError("websocket handshake response too large")
        header, _, rest = head.partition(b"\r\n\r\n")
        # 101 is the only acceptable answer; anything else is a refusal we should name.
        if b" 101 " not in header.split(b"\r\n")[0] + b" ":
            raise RuntimeError(
                f"websocket handshake refused: {header.split(chr(13).encode())[0].decode(errors='replace')}")
        self._buffer = rest

    def send(self, payload: str) -> None:
        data = payload.encode()
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        length = len(data)
        if length < 126:
            header = struct.pack(">BB", 0x81, 0x80 | length)
        elif length < 65536:
            header = struct.pack(">BBH", 0x81, 0x80 | 126, length)
        else:
            header = struct.pack(">BBQ", 0x81, 0x80 | 127, length)
        self._sock.sendall(header + mask + masked)

    def recv(self) -> str:
        def need(count: int) -> None:
            while len(self._buffer) < count:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise RuntimeError("CDP closed the websocket")
                self._buffer += chunk
        need(2)
        opcode = self._buffer[0] & 0x0F
        length = self._buffer[1] & 0x7F
        offset = 2
        if length == 126:
            need(4)
            length = struct.unpack(">H", self._buffer[2:4])[0]
            offset = 4
        elif length == 127:
            need(10)
            length = struct.unpack(">Q", self._buffer[2:10])[0]
            offset = 10
        if opcode == 0x8:
            raise RuntimeError("CDP closed the websocket")
        if length > MAX_MESSAGE_BYTES:
            raise RuntimeError(f"CDP message too large: {length} bytes")
        need(offset + length)
        payload = self._buffer[offset:offset + length]
        self._buffer = self._buffer[offset + length:]
        return payload.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _evaluate(ws: WebSocket, expression: str, message_id: int) -> dict[str, Any]:
    """Run one expression and return its value, or the protocol's own error."""
    ws.send(json.dumps({"id": message_id, "method": "Runtime.evaluate",
                        "params": {"expression": expression, "returnByValue": True,
                                   "awaitPromise": True}}))
    # CDP interleaves events with responses; keep reading until our id comes back.
    for _ in range(60):
        message = ws.recv()
        try:
            parsed = json.loads(message)
        except json.JSONDecodeError:
            continue
        if parsed.get("id") != message_id:
            continue
        if "error" in parsed:
            return {"ok": False, "error": parsed["error"].get("message", "protocol error")}
        result = parsed.get("result", {})
        if "exceptionDetails" in result:
            detail = result["exceptionDetails"]
            # `exceptionDetails.text` is only ever the classifier ("Uncaught"); the message the
            # page actually raised lives in `exception.description`. Reporting the classifier
            # alone told the caller nothing about what went wrong.
            message = str(detail.get("text") or "exception")
            exception = detail.get("exception") or {}
            described = exception.get("description") or exception.get("value")
            if described:
                message = f"{message}: {described}"
            return {"ok": False, "error": message}
        inner = result.get("result") or {}
        return {"ok": True, "value": inner.get("value"),
                "type": inner.get("type"), "description": inner.get("description")}
    return {"ok": False, "error": "no response before the event budget ran out"}


def inspect_endpoint(port: int = 9222, *, host: str = "127.0.0.1",
                     expressions: list[str] | None = None,
                     timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Attach to a running Chromium's DevTools endpoint and observe its pages."""
    # `port` can arrive as a string or a float from a caller, and comparing those against ints
    # raises TypeError rather than refusing. Coerce, then range-check.
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"port is not an integer: {port!r}"}
    if not (0 < port < 65536):
        return {"ok": False, "error": f"port out of range: {port}"}
    base = f"http://{host}:{port}"
    try:
        version = _http_json(f"{base}/json/version", timeout=timeout)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "endpoint": base,
                "error": f"no DevTools endpoint at {base}: {exc}",
                "hint": ("start a browser with --remote-debugging-port=<port>, or pass a URL "
                         "with an aspect — `re cdp <url> --symbol=runtime` — to have one "
                         "launched for you")}
    try:
        targets = _http_json(f"{base}/json/list", timeout=timeout)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "endpoint": base, "error": f"target list failed: {exc}"}

    pages = [target for target in targets or [] if target.get("type") == "page"]
    questions = expressions or [
        "location.href",
        "document.title",
        "navigator.userAgent",
        "document.querySelectorAll('*').length",
        "Object.keys(window).length",
        "document.cookie",
    ]
    findings: list[dict[str, Any]] = []
    for page in pages[:4]:
        ws_url = page.get("webSocketDebuggerUrl")
        if not ws_url:
            continue
        entry: dict[str, Any] = {"id": page.get("id"), "url": page.get("url"),
                                 "title": page.get("title"), "values": {}}
        try:
            ws = WebSocket(ws_url, timeout=timeout)
        except (RuntimeError, OSError, ValueError) as exc:
            entry["error"] = str(exc)
            findings.append(entry)
            continue
        try:
            # Wait for the document to finish before asking anything about it. Without this the
            # first evaluation races the parser: a listener count came back 1, 1, 0 across
            # three identical runs, because the element carrying the handler sometimes did not
            # exist yet. Polling is bounded so a page that never settles still returns.
            _evaluate(ws, "document.readyState", 0)
            for _ in range(50):
                state = _evaluate(ws, "document.readyState", 0)
                if not state.get("ok") or state.get("value") == "complete":
                    break
                import time as _time
                _time.sleep(0.1)
            for index, expression in enumerate(questions[:_MAX_EVALUATIONS], start=1):
                entry["values"][expression] = _evaluate(ws, expression, index)
            # `page["title"]` comes from the /json target list, which Chrome populates from the
            # document as it was when the target was announced. After a navigation it stays
            # empty, so a page with a real <title> reported `title ""` while `document.title`
            # in the same payload said "probe". Ask the document that is actually loaded.
            live_title = entry["values"].get("document.title") or {}
            if live_title.get("ok") and isinstance(live_title.get("value"), str):
                entry["title"] = live_title["value"]
        finally:
            ws.close()
        findings.append(entry)

    return {
        "ok": True,
        "endpoint": base,
        "browser": version.get("Browser"),
        "protocol_version": version.get("Protocol-Version"),
        "v8_version": version.get("V8-Version"),
        "target_count": len(targets or []),
        "page_count": len(pages),
        "pages": findings,
        "note": ("Observation only. Expressions are evaluated in the page's own context, so "
                 "they can read anything the page can — including cookies, which is useful for "
                 "understanding a session and is why `reveal` exists on the capture verbs."),
    }


def _command(ws: WebSocket, method: str, params: dict[str, Any] | None,
             message_id: int) -> dict[str, Any]:
    """Send one CDP command and return its raw result, skipping interleaved events."""
    ws.send(json.dumps({"id": message_id, "method": method, "params": params or {}}))
    for _ in range(120):
        message = ws.recv()
        try:
            parsed = json.loads(message)
        except json.JSONDecodeError:
            continue
        if parsed.get("id") != message_id:
            continue
        if "error" in parsed:
            return {"ok": False, "error": parsed["error"].get("message", "protocol error")}
        return {"ok": True, "result": parsed.get("result") or {}}
    return {"ok": False, "error": "no response before the event budget ran out"}


def _command_collect(ws: WebSocket, method: str, params: dict[str, Any] | None,
                     message_id: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Send one command, returning its reply *and* the events that arrived before it.

    `_command` discards interleaved events while waiting for its own reply, which is correct for
    a command whose answer is the point and fatal for network capture: measured against a real
    navigation, `Network.requestWillBeSent` arrives *before* the `Page.navigate` reply, so
    navigating with `_command` collected zero requests for a page that made two. The events are
    not late — they were thrown away.
    """
    ws.send(json.dumps({"id": message_id, "method": method, "params": params or {}}))
    events: list[dict[str, Any]] = []
    for _ in range(400):
        message = ws.recv()
        try:
            parsed = json.loads(message)
        except json.JSONDecodeError:
            continue
        if parsed.get("id") == message_id:
            if "error" in parsed:
                return ({"ok": False, "error": parsed["error"].get("message", "protocol error")},
                        events)
            return ({"ok": True, "result": parsed.get("result") or {}}, events)
        if parsed.get("method"):
            events.append(parsed)
    return ({"ok": False, "error": "no response before the event budget ran out"}, events)


# Expressions that answer the observation questions the REA tool list is really asking.
_OBSERVATIONS = {
    "runtime": [
        "document.title",
        "navigator.userAgent",
        "document.readyState",
        "document.querySelectorAll('*').length",
        # Enumerating `window` with a property read throws SecurityError on an opaque origin
        # (`data:` URLs have no storage), which is why this counts only own keys and never
        # dereferences them. Reading the value of each property was the original form and it
        # failed on every `data:` page.
        "Object.getOwnPropertyNames(globalThis).length",
    ],
    "execution": [
        "(window.__errors__ || []).length",
        "performance.now()",
        "document.querySelectorAll('script').length",
        "(document.currentScript && document.currentScript.src) || ''",
    ],
    # WebMCP tools. The API is `document.modelContext`, specified at
    # github.com/webmachinelearning/webmcp, and the registry is not a CDP domain — Chromium 141
    # (the build shipped with Playwright on this host) has no `WebMCP` domain at all, checked
    # against `/json/protocol`. It is ordinary page state, so `Runtime.evaluate` reaches it and a
    # polyfilled page answers the same way a native one would.
    #
    # Two shapes are tried because the spec has moved: `document.modelContext.getTools()` and an
    # array-shaped `document.modelContext.tools`. A page that registered nothing reports an empty
    # list rather than an error, which is why `available` is reported separately from `tool_count`.
    "webmcp": [
        "(function(){try{"
        "var mc=document.modelContext;"
        "if(!mc)return {available:false,reason:'document.modelContext is not defined'};"
        "var tools=null;"
        "if(typeof mc.getTools==='function'){tools=mc.getTools();}"
        "else if(Array.isArray(mc.tools)){tools=mc.tools;}"
        "else if(typeof mc.tools==='object'&&mc.tools!==null){tools=Object.values(mc.tools);}"
        "if(!tools)return {available:true,tool_count:0,"
        "reason:'modelContext exists but exposes no tool list'};"
        "return {available:true,tool_count:tools.length,"
        "tools:tools.map(function(t){return {name:t&&t.name,"
        "description:(t&&t.description||'').slice(0,200),"
        "input_schema:t&&t.inputSchema?Object.keys(t.inputSchema.properties||{}):[]}})};"
        "}catch(e){return {available:false,reason:String(e&&e.message||e)};}})()",
    ],
    "listeners": [
        # Inline handlers only — `addEventListener` registrations are not enumerable from page
        # script at all, which is a CDP/DOM limitation rather than something to paper over. The
        # count is of elements carrying an `on*` property.
        "(function(){var n=0;var all=document.querySelectorAll('*');"
        "for(var i=0;i<all.length;i++){var el=all[i];"
        "for(var k in el){if(k.slice(0,2)==='on'&&typeof el[k]==='function'){n++;break}}}"
        "return n;})()",
    ],
}


def capture_screenshot(port: int, *, host: str = "127.0.0.1", index: int = 0,
                       image_format: str = "png", quality: int | None = None,
                       timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Capture a PNG/JPEG of one page's viewport over the DevTools socket.

    `Page.captureScreenshot` returns base64 in the protocol's JSON, which needs no binary
    transport, no browser-automation dependency and no display — it works against a headless
    instance over the same socket the other observations already use. The row describing this as
    unimplemented was accurate about the code and wrong about the obstacle: the call works
    unmodified, returning a 1922-byte PNG for `about:blank`.

    The image is written to `out` when given and summarised otherwise; the base64 body is
    never echoed back, because a full-page capture of a real site is megabytes and would make
    the report unreadable.
    """
    if image_format not in ("png", "jpeg", "webp"):
        return {"ok": False, "error": f"unsupported image format {image_format!r}",
                "formats": ["png", "jpeg", "webp"]}
    pages = _page_targets(port, host=host, timeout=timeout)
    if isinstance(pages, dict):
        return pages
    if not pages:
        return {"ok": False, "endpoint": f"http://{host}:{port}",
                "error": "no page targets to capture"}
    chosen = pages[index] if 0 <= index < len(pages) else pages[0]
    ws_url = chosen.get("webSocketDebuggerUrl")
    if not ws_url:
        return {"ok": False, "error": "target exposes no webSocketDebuggerUrl",
                "target": chosen.get("id")}
    params: dict[str, Any] = {"format": image_format}
    if quality is not None and image_format in ("jpeg", "webp"):
        params["quality"] = max(0, min(100, int(quality)))

    try:
        ws = WebSocket(ws_url, timeout=timeout)
    except (RuntimeError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"could not attach: {exc}"}
    try:
        reply = _command(ws, "Page.captureScreenshot", params, 1)
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001 - closing must never mask the capture result
            pass
    if not reply.get("ok"):
        return {"ok": False, "error": reply.get("error", "capture failed"),
                "endpoint": f"http://{host}:{port}"}

    import base64
    import hashlib
    encoded = (reply.get("result") or {}).get("data") or ""
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        return {"ok": False, "error": f"the screenshot body is not valid base64: {exc}"}
    # A protocol success with an empty body happens when the surface is not compositing; calling
    # that a capture would be a silent lie, so it is reported as a failure.
    if not raw:
        return {"ok": False, "error": "the browser returned an empty image"}
    magic = {b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg"}
    detected = next((name for prefix, name in magic.items() if raw.startswith(prefix)), None)
    report: dict[str, Any] = {
        "ok": True,
        "endpoint": f"http://{host}:{port}",
        "target": {"id": chosen.get("id"), "url": chosen.get("url"),
                   "title": chosen.get("title"), "type": chosen.get("type")},
        "format": detected or image_format,
        "declared_format": image_format,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "head": raw[:16].hex(),
    }
    if detected and detected != image_format:
        # The protocol accepts a format and may still answer with another; say so rather than
        # letting the caller believe the bytes are what it asked for.
        report["format_mismatch"] = True
    return report


def _page_targets(port: int, *, host: str = "127.0.0.1",
                  timeout: float = DEFAULT_TIMEOUT) -> Any:
    """Fetch the target list and return every target, with its `type` preserved.

    The endpoint reports `page`, `iframe`, `service_worker`, `background_page` and — for an
    Electron app — `webview` and friends. Filtering to `page` before reporting is how a
    service worker executing the app's logic became invisible: it is not a page, but it is
    observing the runtime all the same. Callers that only want pages filter afterwards.
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"port is not an integer: {port!r}"}
    if not (0 < port < 65536):
        return {"ok": False, "error": f"port out of range: {port}"}
    base = f"http://{host}:{port}"
    try:
        targets = _http_json(f"{base}/json/list", timeout=timeout)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "endpoint": base,
                "error": f"no DevTools endpoint at {base}: {exc}"}
    return [target for target in targets or [] if isinstance(target, dict)]


def capture_network(port: int, *, host: str = "127.0.0.1", url: str | None = None,
                    wait: float = 5.0, limit: int = 200,
                    timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Collect CDP `Network` events from a page, optionally navigating first.

    This is the half page-script evaluation fundamentally cannot cover: a response the page has
    already consumed is gone by the time `fetch` is patched, so the request list has to come from
    the protocol's own event stream. `Network.enable` succeeds over the same socket and delivered
    three events for a trivial data-URL page, so the transport was never the obstacle.

    Events are folded into one record per request, because the protocol emits several per
    exchange (`requestWillBeSent`, `responseReceived`, `loadingFinished`) and a raw dump answers
    "what happened" only after the reader does the joining.

    Navigation events arrive *before* the navigation command's own reply, so replies are collected
    with `_command_collect` rather than `_command` — the latter discards exactly the events this
    function exists to gather, which made it report zero requests for a page that made two.
    """
    pages = _page_targets(port, host=host, timeout=timeout)
    if isinstance(pages, dict):
        return pages
    if not pages:
        return {"ok": False, "endpoint": f"http://{host}:{port}",
                "error": "no targets to observe"}
    chosen = next((page for page in pages if page.get("type") == "page"), pages[0])
    ws_url = chosen.get("webSocketDebuggerUrl")
    if not ws_url:
        return {"ok": False, "error": "target exposes no webSocketDebuggerUrl"}

    try:
        ws = WebSocket(ws_url, timeout=timeout)
    except (RuntimeError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"could not attach: {exc}"}

    requests: dict[str, dict[str, Any]] = {}
    pending: list[dict[str, Any]] = []
    others: list[str] = []

    def absorb(event: dict[str, Any]) -> None:
        method = event.get("method") or ""
        params = event.get("params") or {}
        if not method.startswith("Network."):
            return
        request_id = params.get("requestId")
        if method == "Network.requestWillBeSent":
            request = params.get("request") or {}
            requests[request_id] = {
                "request_id": request_id,
                "url": request.get("url"),
                "method": request.get("method"),
                "type": params.get("type"),
                "request_headers": request.get("headers") or {},
                "status": None,
                "mime": None,
                "encoded_bytes": None,
            }
            return
        record = requests.get(request_id)
        if record is None:
            if len(others) < 40:
                others.append(method)
            return
        if method == "Network.responseReceived":
            response = params.get("response") or {}
            record["status"] = response.get("status")
            record["mime"] = response.get("mimeType")
            record["remote_ip"] = response.get("remoteIPAddress")
        elif method == "Network.loadingFinished":
            record["encoded_bytes"] = params.get("encodedDataLength")
        elif method == "Network.loadingFailed":
            record["failed"] = params.get("errorText") or True
        elif method == "Network.requestWillBeSentExtraInfo":
            record["actual_request_headers"] = params.get("headers") or {}
        elif method == "Network.responseReceivedExtraInfo":
            record["actual_response_headers"] = params.get("headers") or {}
        elif method == "Network.dataReceived" and record.get("encoded_bytes") is None:
            record["data_received"] = (record.get("data_received") or 0) + (
                params.get("encodedDataLength") or 0)

    try:
        enabled, first = _command_collect(ws, "Network.enable", {}, 1)
        if not enabled.get("ok"):
            return {"ok": False, "error": enabled.get("error", "Network.enable refused")}
        for event in first:
            absorb(event)
        _reply, more = _command_collect(ws, "Page.enable", {}, 2)
        for event in more:
            absorb(event)
        if url:
            _reply, during = _command_collect(ws, "Page.navigate", {"url": url}, 3)
            for event in during:
                absorb(event)

        import time as _time
        deadline = _time.time() + max(0.0, float(wait))
        while _time.time() < deadline and len(requests) < limit:
            try:
                raw = ws.recv()
            except Exception:  # noqa: BLE001 - a closed socket ends collection, not the report
                break
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            absorb(message)
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001 - closing must not mask the collection result
            pass

    collected = list(requests.values())[:limit]
    statuses = [entry.get("status") for entry in collected if entry.get("status")]
    return {
        "ok": True,
        "endpoint": f"http://{host}:{port}",
        "target": {"id": chosen.get("id"), "url": chosen.get("url"),
                   "title": chosen.get("title"), "type": chosen.get("type")},
        "navigated_to": url,
        "waited_seconds": wait,
        "request_count": len(collected),
        "statuses": sorted({str(status) for status in statuses}),
        "requests": collected,
        # Hosts seen in the request list are the ones the page actually talked to, which is the
        # question a network observation exists to answer.
        "hosts": sorted({_host_of(entry.get("url") or "") for entry in collected} - {""}),
        "unattributed_events": others,
    }


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).netloc or ""
    except ValueError:
        return ""


def enumerate_targets(port: int, *, host: str = "127.0.0.1",
                      timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """List every DevTools target with its type, including non-page execution contexts.

    An Electron app's renderer is a `page`, its preload work often a `service_worker`, and a
    `webview` is a separate target again. The previous report kept only `type == "page"`, so a
    service worker running the application's own logic was not merely unattributed — it was
    absent, and a reader had no way to tell.
    """
    targets = _page_targets(port, host=host, timeout=timeout)
    if isinstance(targets, dict):
        return targets
    by_type: dict[str, int] = {}
    for target in targets:
        kind = target.get("type") or "unknown"
        by_type[kind] = by_type.get(kind, 0) + 1
    electron_markers = ("webview", "background_page", "service_worker")
    return {
        "ok": True,
        "endpoint": f"http://{host}:{port}",
        "target_count": len(targets),
        "types": by_type,
        # Presence of a non-page execution context is the observable trace of an Electron-style
        # embedder, and it is the only part of that question answerable without the app's own
        # ASAR: the fuses live inside the Electron binary, not in the target list.
        "electron_shaped": any(by_type.get(marker) for marker in electron_markers),
        "targets": [{"id": target.get("id"), "type": target.get("type"),
                     "title": target.get("title"), "url": target.get("url")}
                    for target in targets],
    }


def observe(port: int, *, aspect: str = "runtime", host: str = "127.0.0.1",
            timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run one aspect of observation against a live endpoint.

    The aspects map onto the questions the REA browser tools answer — what the JavaScript
    runtime exposes, what executed, what is listening — without pulling in a browser
    automation dependency.
    """
    questions = _OBSERVATIONS.get(aspect)
    if questions is None:
        return {"ok": False, "error": f"unknown aspect {aspect!r}",
                "aspects": sorted(_OBSERVATIONS)}
    report = inspect_endpoint(port, host=host, expressions=questions, timeout=timeout)
    report["aspect"] = aspect
    return report


@contextlib.contextmanager
def launched_browser(url: str = "about:blank", *, timeout: float = DEFAULT_TIMEOUT):
    """Yield the DevTools port of a freshly started headless browser, then tear it down.

    `launch_and_inspect` bundled launch, observation and shutdown into one call, which meant a
    capability that is not an expression list — a screenshot, a network trace — had no way to
    borrow a browser. Every one of them would have had to reimplement startup and, more to the
    point, reimplement the teardown. That teardown is not incidental: a leaked profile is
    hundreds of megabytes, and a stale profile stops the *next* launch from opening a port, which
    is how eleven browsers and nine profiles once survived a single session.

    Yields a dict `{"port": int, "binary": str, "profile": str}`, or raises `RuntimeError` with
    the reason when no browser can be arranged.
    """
    import shutil
    import subprocess
    import tempfile
    import time

    binary = find_browser()
    if not binary:
        raise RuntimeError(f"no Chromium or Chrome build found; searched {list(_CHROME_GLOBS)}")
    profile = tempfile.mkdtemp(prefix="xtcdp-")
    process = subprocess.Popen(
        [binary, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
         "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        port_file = Path(profile) / "DevToolsActivePort"
        port = None
        for _ in range(120):
            if port_file.is_file():
                try:
                    port = int(port_file.read_text().splitlines()[0])
                    break
                except (ValueError, IndexError):
                    pass
            if process.poll() is not None:
                raise RuntimeError(f"the browser exited before opening a port "
                                   f"(exit {process.returncode})")
            time.sleep(0.1)
        if port is None:
            raise RuntimeError("the browser never reported a DevTools port")
        if url and url != "about:blank":
            _navigate_and_wait(port, url, timeout=timeout)
        yield {"port": port, "binary": binary, "profile": profile}
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(profile, ignore_errors=True)


def capture_screenshot_of(url: str = "about:blank", **kwargs: Any) -> dict[str, Any]:
    """Launch a browser, capture a screenshot of `url`, and shut down."""
    try:
        with launched_browser(url) as session:
            report = capture_screenshot(session["port"], **kwargs)
            report["launched"] = {"binary": session["binary"], "port": session["port"]}
            return report
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}


def capture_network_of(url: str = "about:blank", **kwargs: Any) -> dict[str, Any]:
    """Launch a browser, record the network activity of loading `url`, and shut down.

    The browser is started on `about:blank` and then navigated, rather than being started on
    `url` directly. Starting on the URL meant the document request — the one that matters most —
    had already completed before `Network.enable` could be sent, so it was absent from the
    report while its subresources were there. Measured on `https://example.com`: launching on the
    URL reported one request (`s.js`) and no document; launching on `about:blank` and navigating
    reports the document too.
    """
    try:
        with launched_browser("about:blank") as session:
            report = capture_network(session["port"], url=url, **kwargs)
            report["launched"] = {"binary": session["binary"], "port": session["port"]}
            return report
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}


def _navigate_and_wait(port: int, url: str, *, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Navigate the first page target to `url` and wait until its document is parsed.

    Returns True when the page reached `interactive` or `complete`, False on timeout. False is
    deliberately not an error: a slow page is still worth observing, and the caller gets whatever
    state it reached.

    This exists because handing the URL to the browser at launch and attaching immediately races the
    load. The first `Runtime.evaluate` then runs against the blank document, so `document.title`
    comes back empty and anything the page installs at parse time reads as absent — a page with two
    WebMCP tools registered reported `document.modelContext is not defined`. The same race had
    already been found for network capture, which lost the document request; it was fixed there and
    not here, which is why it recurred.
    """
    import time
    targets = _page_targets(port)
    if not isinstance(targets, list) or not targets:
        return False
    try:
        ws = WebSocket(targets[0]["webSocketDebuggerUrl"], timeout=timeout)
    except (OSError, ValueError, KeyError):
        return False
    try:
        _command(ws, "Page.enable", {}, 1)
        _command(ws, "Page.navigate", {"url": url}, 2)
        deadline = time.monotonic() + timeout
        message_id = 10
        while time.monotonic() < deadline:
            reply = _evaluate(ws, "document.readyState", message_id)
            message_id += 1
            if reply.get("ok") and reply.get("value") in ("interactive", "complete"):
                return True
            time.sleep(0.1)
        return False
    finally:
        try:
            ws.close()
        except OSError:
            pass


def launch_and_inspect(url: str = "about:blank", *,
                       expressions: list[str] | None = None,
                       timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Start a headless Chromium, observe it, and shut it down.

    Having to arrange a browser before the tool will talk to one makes the capability
    theoretical for anyone who has not already set it up. This starts its own, on a port the
    kernel picks, so `re cdp` works from nothing.
    """
    import subprocess
    import tempfile
    import time
    binary = find_browser()
    if not binary:
        return {"ok": False, "error": "no Chromium or Chrome build found",
                "searched": list(_CHROME_GLOBS)}
    profile = tempfile.mkdtemp(prefix="xtcdp-")
    # --remote-debugging-port=0 lets the kernel choose; the chosen port is written to
    # DevToolsActivePort inside the profile directory, which is the documented way to find it.
    process = subprocess.Popen(
        [binary, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
         "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port_file = Path(profile) / "DevToolsActivePort"
    port = None
    try:
        for _ in range(120):
            if port_file.is_file():
                try:
                    port = int(port_file.read_text().splitlines()[0])
                    break
                except (ValueError, IndexError):
                    pass
            if process.poll() is not None:
                return {"ok": False, "error": "the browser exited before opening a port",
                        "exit_code": process.returncode, "binary": binary}
            time.sleep(0.1)
        if port is None:
            return {"ok": False, "error": "the browser never reported a DevTools port",
                    "binary": binary}
        if url and url != "about:blank":
            _navigate_and_wait(port, url, timeout=timeout)
        report = inspect_endpoint(port, expressions=expressions, timeout=timeout)
        report["launched"] = {"binary": binary, "port": port, "profile": profile}
        return report
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        # The profile directory is hundreds of megabytes of cache and must not survive the
        # call. Leaving it behind fills the disk and, worse, a stale profile can stop the next
        # launch from opening a port — which is exactly how this leaked eleven browsers and
        # nine profiles before it was noticed.
        import shutil
        shutil.rmtree(profile, ignore_errors=True)


def inspect(path: str | Path | None = None, **kwargs: Any) -> dict[str, Any]:
    """Verb entry point: the target is a port, a URL, or nothing (find a browser)."""
    text = str(path).strip() if path else ""
    if text.startswith("http://") or text.startswith("https://"):
        parsed = urllib.parse.urlparse(text)
        if parsed.port is None:
            return {"ok": False,
                    "error": f"no port in {text!r}; DevTools endpoints always carry a port"}
        return inspect_endpoint(parsed.port, host=parsed.hostname or "127.0.0.1", **kwargs)
    if text.isdigit():
        return inspect_endpoint(int(text), **kwargs)
    if text == "launch" or kwargs.pop("launch", False):
        return launch_and_inspect(**{k: v for k, v in kwargs.items()
                                     if k in ("expressions", "timeout")})
    if text.startswith("about:") or text.startswith("file:") or text.startswith("data:"):
        # A URL to open is a request to run one, not to find an existing browser.
        return launch_and_inspect(text, **{k: v for k, v in kwargs.items()
                                           if k in ("expressions", "timeout")})
    if text:
        return {"ok": False, "error": f"not a DevTools endpoint: {text!r}",
                "hint": "pass a port (9222), http://host:port, a URL to open, or 'launch'"}
    endpoint = inspect_endpoint(9222, **kwargs)
    if not endpoint.get("ok"):
        # Nothing listening on the default port: start our own rather than reporting a dead
        # end, since the capability is what the caller asked about.
        fallback = launch_and_inspect(**{k: v for k, v in kwargs.items()
                                         if k in ("expressions", "timeout")})
        fallback["fallback_from"] = endpoint.get("error")
        return fallback
    return endpoint
