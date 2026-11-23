"""Analysis guidance: workflows whose every step names a verb that really exists.

The failure mode this module is written against is guidance that *reads* authoritative and
cannot be followed: "use the decompiler" with no flag, or a step citing a verb that was renamed
two releases ago. Both look fine in review and waste an analyst's afternoon.

So the central test here is not that the text is good — that cannot be tested — but that every
step references a real verb, and that the module's own verb list agrees with the CLI's argparse
choices. `test_known_verbs_match_the_cli` is what makes the rest trustworthy: without it,
`KNOWN_VERBS` could drift into a list of verbs the tool does not have, and the import-time
validator would cheerfully bless them.

The second property is that a step without a stated interpretation is not guidance. A command
tells you what to run; guidance tells you what the result would mean. Both fields are required
and both are asserted non-empty.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import guidance

REPO = Path(__file__).resolve().parent.parent


def cli_verbs() -> set[str]:
    """The verbs `re` actually accepts, read from the argparse declaration."""
    source = (REPO / "xtforge" / "cli" / "__init__.py").read_text()
    match = re.search(r'r\.add_argument\("re_verb",\s*choices=\[(.*?)\]', source, re.S)
    if match is None:
        raise AssertionError("could not find the re_verb choices declaration")
    return set(re.findall(r'"([a-z0-9\-]+)"', match.group(1)))


class VerbParityTest(unittest.TestCase):
    def test_known_verbs_match_the_cli(self) -> None:
        """`KNOWN_VERBS` is a snapshot; this is what keeps it from becoming fiction."""
        actual = cli_verbs()
        self.assertTrue(actual, "no verbs parsed from the CLI")
        missing = guidance.KNOWN_VERBS - actual
        self.assertEqual(missing, set(),
                         f"guidance references verbs the CLI does not have: {sorted(missing)}")
        extra = actual - guidance.KNOWN_VERBS
        self.assertEqual(extra, set(),
                         f"the CLI has verbs guidance does not know about: {sorted(extra)}")

    def test_every_workflow_verb_is_real(self) -> None:
        actual = cli_verbs()
        for workflow in guidance.list_workflows()["workflows"]:
            full = guidance.show_workflow(workflow["id"])
            for step in full["steps"]:
                self.assertIn(step["verb"], actual,
                              f"{workflow['id']} step {step['n']} names {step['verb']!r}, "
                              "which is not a CLI verb")


class ValidatorTest(unittest.TestCase):
    def test_unknown_verb_is_rejected(self) -> None:
        bad = [{"id": "x", "title": "t", "when": "w",
                "steps": [("correlate", "a", "b"), ("no-such-verb", "a", "b"),
                          ("api", "a", "b")]}]
        with self.assertRaises(ValueError) as caught:
            guidance._validate(bad)
        self.assertIn("no-such-verb", str(caught.exception))

    def test_step_without_interpretation_is_rejected(self) -> None:
        """A command with no stated meaning is not guidance."""
        bad = [{"id": "x", "title": "t", "when": "w",
                "steps": [("correlate", "a", ""), ("api", "a", "b"), ("diff", "a", "b")]}]
        with self.assertRaises(ValueError) as caught:
            guidance._validate(bad)
        self.assertIn("interpretation", str(caught.exception))

    def test_short_sequence_is_rejected(self) -> None:
        bad = [{"id": "x", "title": "t", "when": "w",
                "steps": [("correlate", "a", "b"), ("api", "a", "b")]}]
        with self.assertRaises(ValueError) as caught:
            guidance._validate(bad)
        self.assertIn("workflow", str(caught.exception))


class ImportGuardTest(unittest.TestCase):
    def test_the_module_validates_itself_on_import(self) -> None:
        """The validator must actually run against the shipped workflows, not merely exist.

        Removed as a no-op the first time I mutated it: the real workflows are all valid, so
        deleting the `_validate(_WORKFLOWS)` call changed nothing observable. That is a
        mutation surviving because the test was watching the wrong thing. This test imports
        the module with a deliberately corrupted workflow injected and asserts it refuses to
        load — which can only pass if the import-time call is present.
        """
        import subprocess
        import sys
        source = (REPO / "xtforge" / "core" / "re" / "guidance.py").read_text()
        # One line, so the injected snippet cannot break on quoting.
        injected = ("{'id': 'injected', 'title': 't', 'when': 'w', 'steps': "
                    "[('correlate', 'a', 'b'), ('api', 'a', 'b'), ('ghost-verb', 'a', 'b')]}")
        observed = source.replace("_validate(_WORKFLOWS)",
                                  f"_validate(_WORKFLOWS + [{injected}])", 1)
        self.assertNotEqual(observed, source, "the validate call was not found to replace")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "guidance_injected.py"
            target.write_text(observed)
            script = (
                "import importlib.util, sys\n"
                f"spec = importlib.util.spec_from_file_location('gi', {str(target)!r})\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "try:\n"
                "    spec.loader.exec_module(module)\n"
                "except ValueError as exc:\n"
                "    print('REFUSED', exc)\n"
                "    sys.exit(0)\n"
                "print('LOADED')\n"
                "sys.exit(1)\n")
            result = subprocess.run([sys.executable, "-c", script],
                                    capture_output=True, text=True, timeout=180, check=False)
        self.assertIn("REFUSED", result.stdout,
                      "a workflow naming a nonexistent verb was loaded without complaint")
        self.assertIn("ghost-verb", result.stdout)


class WorkflowTest(unittest.TestCase):
    def test_workflows_are_listed(self) -> None:
        report = guidance.list_workflows()
        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["count"], 5)

    def test_ids_are_unique(self) -> None:
        ids = [workflow["id"] for workflow in guidance.list_workflows()["workflows"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_show_returns_runnable_commands(self) -> None:
        report = guidance.show_workflow("triage-unknown-binary")
        self.assertTrue(report["ok"])
        for step in report["steps"]:
            self.assertTrue(step["command"].startswith("xtforge re "),
                            f"step command is not runnable: {step['command']!r}")
            self.assertTrue(step["tells_you"], f"step {step['n']} has no interpretation")

    def test_unknown_workflow_lists_alternatives(self) -> None:
        report = guidance.show_workflow("does-not-exist")
        self.assertFalse(report["ok"])
        self.assertTrue(report["available"], "no alternatives offered for a typo")

    def test_steps_are_numbered_from_one(self) -> None:
        steps = guidance.show_workflow("carve-firmware")["steps"]
        self.assertEqual([step["n"] for step in steps], list(range(1, len(steps) + 1)))

    def test_reconstruction_workflow_mentions_coverage(self) -> None:
        """The coverage verb exists because a ledger cannot see undocumented work."""
        verbs = [step["verb"] for step in guidance.show_workflow(
            "reconstruct-stripped-native")["steps"]]
        self.assertIn("coverage", verbs)
        self.assertIn("unknowns", verbs)

    def test_dormant_versus_runtime_only_is_explained(self) -> None:
        """The correlate step must say what the two mismatch directions mean."""
        step = next(step for step in guidance.show_workflow("attack-runtime-behaviour")["steps"]
                    if step["verb"] == "correlate")
        self.assertIn("static_only", step["tells_you"])
        self.assertIn("runtime_only", step["tells_you"])


class SearchTest(unittest.TestCase):
    def test_search_finds_a_step_not_just_a_title(self) -> None:
        """Searching a concept must reach the step that produces it."""
        report = guidance.search_guidance("entropy")
        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["count"], 1)
        matched = [step["verb"] for hit in report["hits"] for step in hit["steps"]]
        self.assertIn("entropy", matched)

    def test_search_finds_by_conclusion(self) -> None:
        """`dormant` appears only in an interpretation, never in a title."""
        report = guidance.search_guidance("dormant")
        self.assertGreaterEqual(report["count"], 1)
        self.assertIn("attack-runtime-behaviour",
                      [hit["id"] for hit in report["hits"]])

    def test_empty_query_is_an_error(self) -> None:
        self.assertFalse(guidance.search_guidance("  ")["ok"])

    def test_no_match_is_not_an_error(self) -> None:
        report = guidance.search_guidance("zzzznotpresent")
        self.assertTrue(report["ok"])
        self.assertEqual(report["count"], 0)


class ReverseLookupTest(unittest.TestCase):
    def test_verb_maps_to_its_workflows(self) -> None:
        report = guidance.guidance_for_verb("correlate")
        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["count"], 1)
        self.assertEqual(report["uses"][0]["workflow"], "attack-runtime-behaviour")

    def test_neighbours_are_reported(self) -> None:
        """`after` and `then` are what make this a sequence rather than a list."""
        use = guidance.guidance_for_verb("correlate")["uses"][0]
        self.assertEqual(use["after"], "netcap")
        self.assertEqual(use["then"], "capture-diff")

    def test_first_step_has_no_predecessor(self) -> None:
        """`info` opens the triage workflow, so it has nothing before it.

        The first version of this test used `strings` and failed: `strings` appears in two
        workflows, and in the first of them it is not the opening step. Picking a verb that
        only ever appears first makes the assertion about the code rather than about dict
        ordering.
        """
        uses = guidance.guidance_for_verb("info")["uses"]
        self.assertEqual(uses[0]["workflow"], "triage-unknown-binary")
        self.assertIsNone(uses[0]["after"])

    def test_a_verb_used_twice_reports_both_positions(self) -> None:
        """`strings` appears in triage and in runtime analysis, at different positions."""
        uses = guidance.guidance_for_verb("strings")["uses"]
        self.assertGreaterEqual(len(uses), 2)
        by_workflow = {use["workflow"]: use for use in uses}
        # In triage, `strings` follows `checksec`; in runtime analysis it opens the workflow.
        self.assertIsNotNone(by_workflow["triage-unknown-binary"]["after"])
        self.assertIsNone(by_workflow["attack-runtime-behaviour"]["after"])

    def test_unused_verb_is_reported_not_rejected(self) -> None:
        report = guidance.guidance_for_verb("sqlite")
        self.assertTrue(report["ok"])
        self.assertEqual(report["count"], 0)
        self.assertIn("note", report)

    def test_empty_verb_is_an_error(self) -> None:
        self.assertFalse(guidance.guidance_for_verb("")["ok"])


class RendererTest(unittest.TestCase):
    """The human renderer is what most callers actually see, so it is tested directly."""

    def test_every_mode_produces_text(self) -> None:
        from xtforge.cli.scan_cmd import _render_guidance
        cases = [
            guidance.list_workflows(),
            guidance.show_workflow("carve-firmware"),
            guidance.search_guidance("dormant"),
            guidance.guidance_for_verb("correlate"),
            guidance.show_workflow("no-such-workflow"),
        ]
        for response in cases:
            text = _render_guidance(response)
            self.assertIsInstance(text, str)
            self.assertTrue(text.strip(), f"empty rendering for {response.get('query')}")

    def test_renderer_returns_none_safe_text_for_errors(self) -> None:
        """A missing `return` in the renderer made every mode print raw JSON.

        It was invisible from the CLI because `_out` falls back to JSON when `human is None`,
        so the failure looked like a formatting preference rather than a bug. Asserting on the
        return type is what catches it.
        """
        from xtforge.cli.scan_cmd import _render_guidance
        self.assertIsNotNone(_render_guidance({"ok": False, "error": "boom"}))

    def test_unknown_workflow_rendering_lists_alternatives(self) -> None:
        from xtforge.cli.scan_cmd import _render_guidance
        text = _render_guidance(guidance.show_workflow("nope"))
        self.assertIn("try", text)


if __name__ == "__main__":
    unittest.main()
