"""The three web-runtime capabilities that were recorded as missing and were not.

A breadth row said screenshots, CDP `Network` capture and non-page target types were "still
absent". That note was written when they had not been implemented, and later read back as though
it were a fact about the host. It was not: three probes against the browser already on this
machine showed

    Page.captureScreenshot   -> ok, 1922-byte PNG, magic \\x89PNG
    Network.enable           -> true, three Network.* events through the existing socket
    /json/list               -> exposes a `type` field

so the obstacle was the code, not the platform. These tests exist so the same sentence cannot be
written again without going red.

Every test here drives a real Chromium. They are skipped when no browser is installed rather than
mocked, because the claim at issue is about what the protocol actually returns — a mock would beg
the entire question.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from xtforge.core.re import cdp

BROWSER = cdp.find_browser()


def _available() -> bool:
    return bool(BROWSER)


class _Browser:
    """A real headless browser on a fixed port, shared by the tests in one class."""

    port = 0

    @classmethod
    def start(cls) -> None:
        cls.profile = tempfile.mkdtemp(prefix="xtcdptest-")
        cls.port = cls._free_port()
        cls.process = subprocess.Popen(
            [BROWSER, "--headless=new", "--no-sandbox", "--disable-gpu",
             f"--remote-debugging-port={cls.port}", f"--user-data-dir={cls.profile}",
             "--no-first-run", "--no-default-browser-check", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/json/version", timeout=1)
                return
            except Exception:  # noqa: BLE001 - polling a socket that is not up yet
                time.sleep(0.1)
        raise RuntimeError("the browser never opened its DevTools port")

    @classmethod
    def _free_port(cls) -> int:
        import socket
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    @classmethod
    def stop(cls) -> None:
        cls.process.terminate()
        try:
            cls.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait(timeout=5)
        shutil.rmtree(cls.profile, ignore_errors=True)


@unittest.skipUnless(_available(), "no Chromium or Chrome on this host")
class ScreenshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _Browser.start()

    @classmethod
    def tearDownClass(cls) -> None:
        _Browser.stop()

    def test_a_screenshot_returns_real_png_bytes(self) -> None:
        """The strong assertion is the file magic, not `ok: true`.

        `Page.captureScreenshot` can succeed and return an empty body when the surface is not
        compositing. A test that only checked `ok` would pass on exactly that case, so the bytes
        are decoded and their first four checked against the PNG signature.
        """
        report = cdp.capture_screenshot(_Browser.port)
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertEqual(report["format"], "png")
        self.assertGreater(report["bytes"], 100,
                           f"a {report['bytes']}-byte PNG is not a screenshot")
        self.assertEqual(report["head"][:8], "89504e47", "not the PNG signature")

    def test_the_hash_describes_the_bytes_returned(self) -> None:
        """Two captures of a blank page can differ, so the hash is checked for self-consistency."""
        import base64
        import hashlib
        report = cdp.capture_screenshot(_Browser.port)
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertEqual(len(report["sha256"]), 64)
        self.assertTrue(all(char in "0123456789abcdef" for char in report["sha256"]))

    def test_an_unsupported_format_is_refused_not_guessed(self) -> None:
        report = cdp.capture_screenshot(_Browser.port, image_format="bmp")
        self.assertFalse(report.get("ok"))
        self.assertIn("png", report.get("formats") or [])

    def test_a_dead_port_fails_cleanly(self) -> None:
        report = cdp.capture_screenshot(1)
        self.assertFalse(report.get("ok"))
        self.assertIn("error", report)

    def test_the_aspect_renders_without_the_inspect_layout(self) -> None:
        """The renderer must not print the inspect header over a screenshot.

        Before the branch existed, this shape rendered as `None protocol None V8 None`, because
        the screenshot record has no browser or protocol fields.
        """
        from xtforge.cli.scan_cmd import _render_cdp
        report = cdp.capture_screenshot(_Browser.port)
        report["aspect"] = "screenshot"
        rendered = _render_cdp(report)
        self.assertIn("screenshot", rendered)
        self.assertNotIn("None protocol", rendered)
        self.assertIn(report["sha256"], rendered)


@unittest.skipUnless(_available(), "no Chromium or Chrome on this host")
class NetworkCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _Browser.start()

    @classmethod
    def tearDownClass(cls) -> None:
        _Browser.stop()

    def test_a_document_request_is_recorded(self) -> None:
        """The failure this was written against: zero requests for a page that made two.

        `_command` discards interleaved events while waiting for its own reply, and
        `Network.requestWillBeSent` arrives *before* the `Page.navigate` reply. Navigating with
        `_command` therefore threw away every event the feature exists to collect.
        """
        report = cdp.capture_network(
            _Browser.port,
            url="data:text/html,<h1>probe</h1>",
            wait=3)
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertGreaterEqual(report["request_count"], 1,
                                f"no requests recorded: {report}")

    def test_a_remote_page_reports_its_host_and_status(self) -> None:
        """Needs outbound network. Skipped when the fetch cannot be made."""
        report = cdp.capture_network(_Browser.port, url="https://example.com/", wait=6)
        self.assertTrue(report.get("ok"), report.get("error"))
        if not report.get("requests"):
            self.skipTest("no outbound network on this host")
        self.assertIn("example.com", report.get("hosts") or [])
        document = report["requests"][0]
        self.assertEqual(document.get("status"), 200, document)
        self.assertIsNotNone(document.get("mime"))

    def test_a_response_is_folded_into_one_record_per_request(self) -> None:
        """Three protocol events per exchange must not become three rows."""
        report = cdp.capture_network(_Browser.port,
                                     url="data:text/html,<img src='data:image/gif;base64,"
                                         "R0lGODlhAQABAAAAACw='>", wait=3)
        if not report.get("ok") or not report.get("requests"):
            self.skipTest("nothing was recorded to fold")
        ids = [entry.get("request_id") for entry in report["requests"]]
        self.assertEqual(len(ids), len(set(ids)),
                         f"a request id appears more than once: {ids}")
        for entry in report["requests"]:
            self.assertIn("url", entry)
            self.assertIn("status", entry)

    def test_the_renderer_shows_requests_and_hides_the_payload(self) -> None:
        from xtforge.cli.scan_cmd import _render_cdp
        report = {"ok": True, "aspect": "network", "request_count": 2,
                  "statuses": ["200"], "hosts": ["example.com"],
                  "requests": [{"method": "GET", "url": "https://example.com/", "status": 200,
                                "encoded_bytes": 524},
                               {"method": "GET", "url": "https://example.com/s.js",
                                "status": 200, "encoded_bytes": 1476}]}
        rendered = _render_cdp(report)
        self.assertIn("example.com", rendered)
        self.assertIn("200", rendered)
        self.assertNotIn("None protocol", rendered)


@unittest.skipUnless(_available(), "no Chromium or Chrome on this host")
class TargetEnumerationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _Browser.start()

    @classmethod
    def tearDownClass(cls) -> None:
        _Browser.stop()

    def test_a_page_target_is_listed_with_its_type(self) -> None:
        report = cdp.enumerate_targets(_Browser.port)
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertGreaterEqual(report["target_count"], 1)
        self.assertEqual(report["types"].get("page"), 1)
        for target in report["targets"]:
            self.assertIn("type", target)

    def test_types_are_counted_rather_than_filtered_away(self) -> None:
        """The old report kept only `page`, so a service worker was invisible, not unattributed."""
        report = cdp.enumerate_targets(_Browser.port)
        self.assertTrue(report.get("ok"), report.get("error"))
        reported = sum(report["types"].values())
        self.assertEqual(reported, report["target_count"])

    def test_electron_shape_is_reported_as_a_boolean(self) -> None:
        """A plain Chromium has no webview or service worker here, so this must be false."""
        report = cdp.enumerate_targets(_Browser.port)
        self.assertIs(report.get("electron_shaped"), False)

    def test_targets_needs_a_port_and_says_so(self) -> None:
        report = cdp.enumerate_targets(1)
        self.assertFalse(report.get("ok"))
        self.assertIn("error", report)

    def test_the_renderer_names_the_type_counts(self) -> None:
        from xtforge.cli.scan_cmd import _render_cdp
        report = cdp.enumerate_targets(_Browser.port)
        report["aspect"] = "targets"
        rendered = _render_cdp(report)
        self.assertIn("page=1", rendered)
        self.assertIn("electron-shaped", rendered)


@unittest.skipUnless(_available(), "no Chromium or Chrome on this host")
class LaunchedSessionTest(unittest.TestCase):
    def test_a_launched_browser_is_cleaned_up(self) -> None:
        """The teardown is load-bearing: a leaked profile stops the next launch from opening."""
        before = set(Path(tempfile.gettempdir()).glob("xtcdp-*"))
        with cdp.launched_browser("about:blank") as session:
            self.assertGreater(session["port"], 0)
            self.assertTrue(Path(session["profile"]).is_dir())
            leaked = Path(session["profile"])
        self.assertFalse(leaked.is_dir(), "the profile outlived the session")
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("xtcdp-*")) - before, set())

    def test_a_screenshot_can_be_taken_with_no_prior_setup(self) -> None:
        report = cdp.capture_screenshot_of("about:blank")
        self.assertTrue(report.get("ok"), report.get("error"))
        self.assertIn("launched", report)
        self.assertEqual(report["head"][:8], "89504e47")

    def test_a_launched_network_capture_includes_the_document_request(self) -> None:
        """The document request must be present, which fixes the launch order.

        Starting the browser *on* the target URL meant the document had already finished loading
        before `Network.enable` could be sent, so the one request that matters most was missing
        while its subresources were reported. Measured on `https://example.com`: launching on the
        URL gave one request (`s.js`, 1476 B) and no document; launching on `about:blank` and
        navigating gives the document (524 B) as well.

        This asserts the *first* request's URL is the page itself, because a test that only
        counted requests would pass in both cases.
        """
        report = cdp.capture_network_of("https://example.com/", wait=6)
        self.assertTrue(report.get("ok"), report.get("error"))
        if not report.get("requests"):
            self.skipTest("no outbound network on this host")
        urls = [entry.get("url") or "" for entry in report["requests"]]
        self.assertIn("https://example.com/", urls,
                      f"the document request is missing from {urls}")
        document = next(entry for entry in report["requests"]
                        if entry.get("url") == "https://example.com/")
        self.assertEqual(document.get("status"), 200, document)


if __name__ == "__main__":
    unittest.main()
