"""Regression tests for xtforge test --pattern name filtering."""
from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from xtforge.core.build.test_runner import _selected_count, run_tests


class SelectedCountTests(unittest.TestCase):
    def test_unittest_ran_n_tests(self) -> None:
        self.assertEqual(_selected_count("unittest", "Ran 3 tests in 0.001s\n\nOK\n"), 3)

    def test_pytest_n_passed(self) -> None:
        self.assertEqual(_selected_count("pytest", "2 passed in 0.10s\n"), 2)

    def test_unrelated_text_is_unknown(self) -> None:
        self.assertIsNone(_selected_count("unittest", "building wheel..."))


class PatternMatchesNothingTests(unittest.TestCase):
    def test_zero_selected_is_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test_demo.py").write_text(
                textwrap.dedent(
                    """
                    import unittest

                    class Demo(unittest.TestCase):
                        def test_works(self):
                            self.assertTrue(True)
                    """
                ),
                encoding="utf-8",
            )
            result = run_tests(root, pattern="zzz_no_such_test")

        self.assertEqual(result["selected"], 0)
        self.assertTrue(result["no_tests_selected"])
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
