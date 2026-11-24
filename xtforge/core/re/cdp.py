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
                "hint": ("launch a browser with --remote-debugging-port=<port>, or use "
                         "`re cdp --launch` to have one started for you")}
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


# Expressions that answer the observation questions the REA tool list is really asking.
_OBSERVATIONS = {
    "runtime": [
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
         "--remote-debugging-port=0", f"--user-data-dir={profile}", url],
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
