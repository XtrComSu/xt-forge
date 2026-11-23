import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xtforge.core.build import test_runner


class TestProjectTestRunner(unittest.TestCase):
    def test_unittest_discovers_tests_in_a_plain_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "test_smoke.py").write_text(
                "import unittest\n"
                "class Smoke(unittest.TestCase):\n"
                "    def test_example(self): self.assertEqual(2 + 2, 4)\n",
                encoding="utf-8",
            )
            with mock.patch.object(test_runner.importlib.util, "find_spec", return_value=None):
                result = test_runner.run_tests(root)

        self.assertTrue(result["ok"], result["output"])
        self.assertEqual(result["runner"], "unittest")
        self.assertIn("Ran 1 test", result["output"])
