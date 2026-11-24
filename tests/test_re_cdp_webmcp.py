"""The `re cdp` launch race, and WebMCP tool discovery.

Two findings, one of which was a bug in shipped behaviour rather than a missing feature.

**The launch race.** `launch_and_inspect` handed the target URL to the browser at startup and then
attached immediately. The first `Runtime.evaluate` therefore ran against the blank document the
browser had loaded *before* navigating: `document.title` came back `''` and anything a page installs
at parse time read as absent. This was not a WebMCP problem — every `re cdp` aspect was reading a
partially-loaded page. The same race had already been found and fixed for network capture, where it
lost the document request; it was fixed there and not in the shared launch path, so it recurred.

Measured before the fix, against a local page with two WebMCP tools:

    title: ''      document.modelContext: 'undefined'      available: False
measured after:

    title: 'WebMCP demo'      available: True      tool_count: 2

**WebMCP is not a CDP domain.** Chromium 141 (the build shipped with Playwright here) has no
`WebMCP` domain in `/json/protocol`. The registry is `document.modelContext`, ordinary page state,
and the spec (github.com/webmachinelearning/webmcp) has a polyfill — so reading it through
`Runtime.evaluate` works on a polyfilled page exactly as it would on a native one.
"""
from __future__ import annotations

import http.server
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from xtforge.core.re import cdp

PAGE = """<!doctype html><html><head><title>WebMCP demo</title></head><body><h1>hi</h1>
<script>
document.modelContext = {
  _tools: [],
  registerTool(t){ this._tools.push(t); },
  getTools(){ return this._tools; }
};
document.modelContext.registerTool({
  name: "filter-templates",
  description: "Filters templates from a description.",
  inputSchema: { type:"object", properties:{ description:{type:"string"} } }
});
document.modelContext.registerTool({
  name: "edit-design",
  description: "Apply a design edit.",
  inputSchema: { type:"object", properties:{ instructions:{type:"string"} } }
});
</script></body></html>
"""

BARE = """<!doctype html><html><head><title>No WebMCP</title></head><body>plain</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    body = PAGE.encode()

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args) -> None:
        pass


class _Server:
    """A local page server, so the test needs no network."""

    def __init__(self, body: bytes) -> None:
        self._directory = tempfile.mkdtemp(prefix="xtcdppage-")
        path = Path(self._directory) / "index.html"
        path.write_bytes(body)
        handler = type("H", (_Handler,), {"body": body})
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/index.html"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        shutil.rmtree(self._directory, ignore_errors=True)


def _have_browser() -> bool:
    return cdp.find_browser() is not None


@unittest.skipUnless(_have_browser(), "no Chromium build on this host")
class LaunchRaceTest(unittest.TestCase):
    """The page must be loaded before any expression is evaluated."""

    def setUp(self) -> None:
        self.server = _Server(PAGE.encode())
        self.addCleanup(self.server.stop)

    def test_the_page_title_is_read_after_navigation(self) -> None:
        """Before the fix this returned `''` — the blank document's title."""
        report = cdp.launch_and_inspect(self.server.url(), expressions=["document.title"])
        self.assertTrue(report["ok"], report.get("error"))
        page = (report.get("pages") or [{}])[0]
        self.assertEqual(page.get("title"), "WebMCP demo")

    def test_the_document_is_complete_when_expressions_run(self) -> None:
        report = cdp.launch_and_inspect(self.server.url(),
                                        expressions=["document.readyState"])
        page = (report.get("pages") or [{}])[0]
        value = (page.get("values") or {}).get("document.readyState", {}).get("value")
        self.assertIn(value, ("interactive", "complete"), f"readyState was {value!r}")

    def test_parse_time_page_state_is_visible(self) -> None:
        """The registry is installed by an inline script, so it exists only after parsing."""
        report = cdp.launch_and_inspect(
            self.server.url(), expressions=["typeof document.modelContext"])
        page = (report.get("pages") or [{}])[0]
        value = (page.get("values") or {}).get("typeof document.modelContext", {}).get("value")
        self.assertEqual(value, "object", "the page had not been parsed when this ran")


@unittest.skipUnless(_have_browser(), "no Chromium build on this host")
class WebMcpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _Server(PAGE.encode())
        self.addCleanup(self.server.stop)

    def _observe(self, url: str) -> dict:
        report = cdp.launch_and_inspect(url, expressions=cdp._OBSERVATIONS["webmcp"])
        page = (report.get("pages") or [{}])[0]
        for key, entry in (page.get("values") or {}).items():
            if "modelContext" in key:
                return entry.get("value") or {}
        return {}

    def test_registered_tools_are_listed(self) -> None:
        payload = self._observe(self.server.url())
        self.assertTrue(payload.get("available"), payload)
        self.assertEqual(payload.get("tool_count"), 2)

    def test_tool_names_descriptions_and_arguments_are_reported(self) -> None:
        payload = self._observe(self.server.url())
        names = [tool.get("name") for tool in payload.get("tools") or []]
        self.assertEqual(names, ["filter-templates", "edit-design"])
        first = payload["tools"][0]
        self.assertIn("Filters templates", first["description"])
        self.assertEqual(first["input_schema"], ["description"])

    def test_a_page_without_webmcp_reports_it_as_absent_not_as_an_error(self) -> None:
        """A page with no registry is the common case; it must not read as a failure."""
        bare = _Server(BARE.encode())
        self.addCleanup(bare.stop)
        payload = self._observe(bare.url())
        self.assertFalse(payload.get("available"))
        self.assertIn("not defined", str(payload.get("reason")))

    def test_the_webmcp_aspect_is_registered(self) -> None:
        self.assertIn("webmcp", cdp._OBSERVATIONS)

    def test_the_expression_is_self_contained(self) -> None:
        """It must not depend on a CDP domain, because this Chromium has no WebMCP domain.

        Checked against the live protocol below; here the check is that the expression is a plain
        IIFE over page state with no protocol call.
        """
        expression = cdp._OBSERVATIONS["webmcp"][0]
        self.assertIn("document.modelContext", expression)
        self.assertTrue(expression.strip().startswith("(function()"))
        self.assertNotIn("WebMCP.", expression,
                         "the expression must not use a CDP domain command")


class ProtocolSurfaceTest(unittest.TestCase):
    def test_the_shipped_chromium_serves_no_webmcp_domain(self) -> None:
        """Verified against the real protocol document, not assumed.

        If a future Chromium grows a `WebMCP` domain this test starts failing, which is the right
        signal: the expression could then be replaced by a protocol call.
        """
        import json
        import urllib.request
        binary = cdp.find_browser()
        if binary is None:
            self.skipTest("no Chromium build on this host")
        import subprocess
        profile = tempfile.mkdtemp(prefix="xtproto-")
        process = subprocess.Popen(
            [binary, "--headless", "--no-sandbox", "--disable-gpu",
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
                import time
                time.sleep(0.1)
            if port is None:
                self.skipTest("the browser did not report a port")
            document = json.loads(urllib.request.urlopen(
                f"http://127.0.0.1:{port}/json/protocol", timeout=20).read())
            domains = {entry.get("domain") for entry in document.get("domains") or []}
            self.assertNotIn("WebMCP", domains)
            self.assertGreater(len(domains), 50, "the protocol document looks truncated")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
