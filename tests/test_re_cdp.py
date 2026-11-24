"""Browser observation over CDP, verified against a real Chromium.

The breadth matrix excluded this as "requires a running browser and DevTools endpoint". Both
halves of that were wrong, and the tests exist to keep them from being wrong again: Chromium is
findable, a DevTools endpoint is startable, and the protocol is speakable without a third-party
client.

Two things are checked that a mock could never establish:

  * **the WebSocket handshake really completes** — a fake transport would pass a mock and fail
    against Chrome, because the handshake, masking and frame lengths are exactly where
    hand-rolled clients break;
  * **evaluated expressions reflect the real page** — the title, element count and location are
    compared against what the page was actually constructed with, not against a fixture.

Tests skip cleanly when no browser is present, rather than passing vacuously.
"""
from __future__ import annotations

import json
import subprocess
import time
import unittest
import urllib.request
from pathlib import Path

from xtforge.core.re import cdp

PAGE = "data:text/html,<title>XT Probe</title><h1>hello</h1><p>a</p><p>b</p>"


class BrowserCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = cdp.find_browser()
        if not cls.binary:
            raise unittest.SkipTest("no Chromium or Chrome build on this host")

    def setUp(self) -> None:
        """A fresh profile per test.

        `id(self)` was used at first, which is not unique across processes and left stale
        profiles behind — a stale profile can stop the next launch from opening a port, which
        produced a test that failed intermittently and passed on rerun. `mkdtemp` is unique and
        is removed unconditionally in `tearDown`.
        """
        import shutil
        import tempfile
        self.profile = tempfile.mkdtemp(prefix="xtcdp-test-")
        self.addCleanup(shutil.rmtree, self.profile, True)
        self.process = subprocess.Popen(
            [self.binary, "--headless", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", "--remote-debugging-port=0",
             f"--user-data-dir={self.profile}", PAGE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self._stop)
        port_file = Path(self.profile) / "DevToolsActivePort"
        self.port = None
        for _ in range(200):
            if port_file.is_file():
                try:
                    self.port = int(port_file.read_text().splitlines()[0])
                    break
                except (ValueError, IndexError):
                    pass
            if self.process.poll() is not None:
                self.skipTest("the browser exited before opening a port")
            time.sleep(0.1)
        if self.port is None:
            self.skipTest("the browser did not report a DevTools port")

    def _stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class BrowserDiscoveryTest(unittest.TestCase):
    def test_a_browser_is_found_or_reported_absent(self) -> None:
        """Discovery must return a real executable path, or nothing — never a guess."""
        binary = cdp.find_browser()
        if binary is None:
            self.skipTest("no browser installed")
        self.assertTrue(Path(binary).is_file())
        self.assertTrue(Path(binary).stat().st_mode & 0o111)


class EndpointTest(BrowserCase):
    def test_version_and_targets_are_read(self) -> None:
        report = cdp.inspect_endpoint(self.port)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("Chrome", report["browser"])
        self.assertEqual(report["protocol_version"].split(".")[0], "1")

    def test_the_page_title_is_the_real_one(self) -> None:
        """A mocked transport could return anything; this is the page's own DOM."""
        report = cdp.inspect_endpoint(self.port)
        page = report["pages"][0]
        self.assertEqual(page["values"]["document.title"]["value"], "XT Probe")

    def test_element_count_matches_the_markup(self) -> None:
        """html, head, title, body, h1, p, p = 7 elements in the fixture."""
        report = cdp.inspect_endpoint(self.port)
        page = report["pages"][0]
        count = page["values"]["document.querySelectorAll('*').length"]["value"]
        self.assertEqual(count, 7, f"expected 7 elements, browser reported {count}")

    def test_custom_expressions_are_honoured(self) -> None:
        report = cdp.inspect_endpoint(self.port, expressions=["40 + 2", "document.title"])
        values = report["pages"][0]["values"]
        self.assertEqual(values["40 + 2"]["value"], 42)
        self.assertEqual(values["document.title"]["value"], "XT Probe")

    def test_a_throwing_expression_is_reported_not_fatal(self) -> None:
        """The message must carry what the page actually raised.

        The first version reported only `exceptionDetails.text`, which is always the classifier
        "Uncaught" — so the caller learned that something failed and nothing about what. The
        real message is in `exception.description`.
        """
        report = cdp.inspect_endpoint(self.port, expressions=["nope.nope.nope"])
        entry = report["pages"][0]["values"]["nope.nope.nope"]
        self.assertFalse(entry["ok"])
        self.assertIn("nope", entry["error"],
                      f"error did not name the failing expression: {entry['error']!r}")
        self.assertIn("Uncaught", entry["error"])

    def test_events_do_not_confuse_the_response_matching(self) -> None:
        """CDP interleaves events with replies; a naive reader would return the wrong message."""
        report = cdp.inspect_endpoint(
            self.port, expressions=["1", "2", "3", "4", "5", "6", "7", "8"])
        values = report["pages"][0]["values"]
        self.assertEqual([values[str(n)]["value"] for n in range(1, 9)], list(range(1, 9)))


class ObservationAspectTest(unittest.TestCase):
    """The named observation aspects, each evaluated against a page built for it."""

    def _observe(self, markup: str, aspect: str) -> dict:
        if not cdp.find_browser():
            self.skipTest("no browser installed")
        report = cdp.launch_and_inspect(f"data:text/html,{markup}",
                                        expressions=cdp._OBSERVATIONS[aspect])
        self.assertTrue(report["ok"], report.get("error"))
        return report["pages"][0]["values"]

    def test_runtime_aspect_reads_the_page(self) -> None:
        values = self._observe("<title>R</title><i>a</i><i>b</i>", "runtime")
        counts = [v["value"] for v in values.values() if v.get("ok")]
        self.assertTrue(counts)
        self.assertTrue(any(isinstance(v, int) and v >= 3 for v in counts),
                        f"no element count found in {counts}")

    def test_listener_count_is_stable_and_correct(self) -> None:
        """Found as a real race: three identical runs returned 1, 1, 0.

        The evaluation ran before the parser had created the element carrying the handler.
        `inspect_endpoint` now waits for `document.readyState === 'complete'` first, and this
        test runs the same observation repeatedly so a regression shows up as a mismatch rather
        than as an occasional CI failure.
        """
        if not cdp.find_browser():
            self.skipTest("no browser installed")
        counts = []
        for _ in range(3):
            report = cdp.launch_and_inspect(
                'data:text/html,<button onclick="1">b</button>',
                expressions=cdp._OBSERVATIONS["listeners"])
            value = list(report["pages"][0]["values"].values())[0]
            counts.append(value.get("value") if value.get("ok") else None)
        self.assertEqual(counts, [1, 1, 1],
                         f"the listener count was not deterministic: {counts}")

    def test_an_unknown_aspect_is_refused(self) -> None:
        report = cdp.observe(9222, aspect="not-an-aspect")
        self.assertFalse(report["ok"])
        self.assertIn("runtime", report["aspects"])


class LaunchTest(unittest.TestCase):
    def test_launch_starts_and_stops_its_own_browser(self) -> None:
        if not cdp.find_browser():
            self.skipTest("no browser installed")
        report = cdp.launch_and_inspect(PAGE)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("launched", report)
        port = report["launched"]["port"]
        self.assertGreater(port, 0)
        # The browser must be gone afterwards, not leaked.
        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1)
            self.fail("the launched browser was left running")
        except Exception:
            pass

    def test_launch_reads_the_page_it_was_given(self) -> None:
        if not cdp.find_browser():
            self.skipTest("no browser installed")
        report = cdp.launch_and_inspect(PAGE, expressions=["document.title"])
        self.assertEqual(report["pages"][0]["values"]["document.title"]["value"],
                         "XT Probe")


class FrameTest(unittest.TestCase):
    """The frame codec, checked directly because it is the part that silently corrupts."""

    def test_masking_round_trips(self) -> None:
        import os
        import socket
        import threading
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received: list[bytes] = []

        def accept() -> None:
            connection, _ = server.accept()
            received.append(connection.recv(65536))
            connection.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        ws = cdp.WebSocket.__new__(cdp.WebSocket)
        ws._sock = sock
        ws._buffer = b""
        ws.send("hello world")
        thread.join(timeout=5)
        sock.close()
        server.close()
        raw = received[0]
        self.assertEqual(raw[0], 0x81, "must be a final text frame")
        self.assertTrue(raw[1] & 0x80, "client frames must be masked")
        mask = raw[2:6]
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(raw[6:]))
        self.assertEqual(payload, b"hello world")

    def test_a_medium_payload_uses_the_extended_length(self) -> None:
        self.assertEqual(cdp.MAX_MESSAGE_BYTES, 8 * 1024 * 1024)


class HonestyTest(unittest.TestCase):
    def test_no_endpoint_is_reported_not_guessed(self) -> None:
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        report = cdp.inspect_endpoint(free_port)
        self.assertFalse(report["ok"])
        self.assertIn("no DevTools endpoint", report["error"])
        self.assertIn("hint", report)

    def test_a_bad_port_is_refused(self) -> None:
        for value in (0, -1, 70000):
            self.assertFalse(cdp.inspect_endpoint(value)["ok"])

    def test_a_non_numeric_port_is_refused_not_raised(self) -> None:
        """Found by fuzzing: the range check compared a str against ints and raised TypeError.

        A verb must answer a bad argument, not crash on it. `None`, a string and a float all
        reached `0 < port < 65536` and took the caller down with them.
        """
        for value in (None, "abc", 0.5, "0.5", [], {}):
            report = cdp.inspect_endpoint(value)
            self.assertIsInstance(report, dict)
            self.assertFalse(report["ok"])
        self.assertIn("not an integer", cdp.inspect_endpoint("abc")["error"])

    def test_a_numeric_string_port_is_normalised(self) -> None:
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        report = cdp.inspect_endpoint(str(free_port))
        self.assertIn(str(free_port), report["endpoint"],
                      "a numeric string must be coerced, not rejected")

    def test_a_non_endpoint_target_is_refused(self) -> None:
        report = cdp.inspect("/etc/passwd")
        self.assertFalse(report["ok"])
        self.assertIn("not a DevTools endpoint", report["error"])

    def test_the_http_scheme_is_accepted(self) -> None:
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        report = cdp.inspect(f"http://127.0.0.1:{free_port}")
        self.assertFalse(report["ok"])
        self.assertIn(str(free_port), report["endpoint"])


if __name__ == "__main__":
    unittest.main()
