"""Guard the cross-platform PATH setup advice printed by npx-xtforge.mjs."""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "bin" / "npx-xtforge.mjs"


class NpmPathAdviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_unsafe_setx_advice_is_gone(self):
        self.assertNotIn("setx PATH", self.source)

    def test_windows_uses_user_scope_environment_api(self):
        self.assertIn("GetEnvironmentVariable('PATH','User')", self.source)
        self.assertIn("SetEnvironmentVariable", self.source)
        self.assertIn("'User'", self.source)
        self.assertIn("-notlike", self.source)
        self.assertIn("current shell must be refreshed", self.source)

    def test_shell_advice_is_idempotent(self):
        for rc_file in (".zshrc", ".bashrc"):
            with self.subTest(rc_file=rc_file):
                self.assertIn(rc_file, self.source)
                pattern = re.compile(
                    r"grep -qF[^\n]*>> ~/" + re.escape(rc_file)
                )
                self.assertRegex(self.source, pattern)

    def test_node_syntax(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not available")
        result = subprocess.run(
            [node, "--check", str(SOURCE)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
