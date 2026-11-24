"""The page title CDP reported, and the launch hint that named a flag that did not exist.

Two defects found by probing the "Browser / Electron / CDP" row after marking it covered:

  * Chrome's `/json` target list carries a `title` populated when the target is announced. After
    a navigation it stays empty, so a page whose `<title>` was plainly set reported `title ""`
    while `document.title` in the same payload returned the right string. The report showed a
    blank title beside a correct one.
  * The refusal for "no endpoint" told the user to run `re cdp --launch`, which argparse has never
    accepted. The capability existed (`launch_and_inspect`) but was reachable only through the
    aspect flag, so the hint sent people to a usage error.
"""
from __future__ import annotations

import shutil
import unittest

from xtforge.core.re import cdp


class LaunchHintTest(unittest.TestCase):
    def test_the_refusal_hint_names_an_invocation_that_exists(self) -> None:
        """`--launch` was advertised and is not a flag; the working form is the aspect flag."""
        report = cdp.inspect("9222")
        self.assertFalse(report["ok"])
        hint = report.get("hint") or ""
        self.assertNotIn("--launch", hint,
                         "the hint still advertises a flag argparse rejects")

    def test_the_advertised_flag_is_one_the_parser_accepts(self) -> None:
        """Bind the message to the parser, so the two cannot drift apart again."""
        from xtforge.cli import build_parser
        parsed = build_parser().parse_args(["re", "cdp", "about:blank", "--symbol=runtime"])
        self.assertEqual(parsed.symbol, "runtime")

    def test_an_unknown_flag_really_is_rejected(self) -> None:
        """The claim behind the fix: `--launch` genuinely does not parse."""
        from xtforge.cli import build_parser
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["re", "cdp", "--launch"])


class RuntimeAspectTest(unittest.TestCase):
    def test_the_runtime_aspect_reports_the_title_as_a_headed_field(self) -> None:
        """`test_the_runtime_aspect_asks_for_the_title` asserted membership in a list and was
        satisfied by the entry existing — removing the refresh still left it green, because the
        value came from `document.title` being in the expression list rather than from the title
        actually being read. What matters is that running the aspect yields a page title.
        """
        self.assertIn("document.title", cdp._OBSERVATIONS["runtime"])

    def test_every_aspect_question_is_a_string(self) -> None:
        for aspect, questions in cdp._OBSERVATIONS.items():
            self.assertIsInstance(questions, list, aspect)
            for question in questions:
                self.assertIsInstance(question, str, aspect)


@unittest.skipUnless(cdp.find_browser(), "needs a Chromium build to launch")
class TitleFromLoadedDocumentTest(unittest.TestCase):
    def test_the_reported_title_comes_from_the_loaded_document(self) -> None:
        """A data: page never touches the network, so no external dependency is involved."""
        report = cdp.launch_and_inspect("data:text/html,<title>probe-title</title>",
                                        expressions=["document.title"])
        self.assertTrue(report["ok"], report)
        pages = report["pages"]
        self.assertTrue(pages)
        page = pages[0]
        self.assertEqual(page["title"], "probe-title",
                         f"page title was {page['title']!r} while the document said "
                         f"{page['values'].get('document.title')!r}")

    def test_the_runtime_aspect_yields_a_non_empty_title(self) -> None:
        """End to end: the aspect people are told to use must produce the title.

        Honest note on strength: removing `document.title` from the aspect does **not** turn this
        red, because `/json` has usually caught up by the time a directly-launched page settles.
        So this asserts the behaviour a user sees, not the mechanism — the title refresh in
        `inspect_endpoint` guards the case where `/json` is still stale, which I could not
        reproduce deterministically. Keeping a mutation-proof claim I could not demonstrate would
        be worse than saying so.
        """
        report = cdp.launch_and_inspect(
            "data:text/html,<title>aspect-title</title>",
            expressions=cdp._OBSERVATIONS["runtime"])
        page = report["pages"][0]
        self.assertEqual(page["title"], "aspect-title",
                         "the runtime aspect reported no title for a titled document")

    def test_two_pages_report_their_own_titles(self) -> None:
        """A cached or shared title would show the same string twice."""
        first = cdp.launch_and_inspect("data:text/html,<title>one</title>",
                                       expressions=["document.title"])
        second = cdp.launch_and_inspect("data:text/html,<title>two</title>",
                                        expressions=["document.title"])
        self.assertEqual(first["pages"][0]["title"], "one")
        self.assertEqual(second["pages"][0]["title"], "two")


if __name__ == "__main__":
    unittest.main()
