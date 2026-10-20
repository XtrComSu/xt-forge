"""The plugin's runtime test, run from the Python suite.

The plugin is TypeScript, so its real behaviour is proven by driving it the
way OpenCode does: call `setup` with a fake context, then use the commands
and hooks it registers. Those tests live next to the plugin
(`plugins/xt-native/test/`) and run on Node.

This bridge makes "the suite is green" mean the plugin works too, not just
the Python side. Node is optional: without it the test is skipped, and the
plugin source is still covered by `tests/test_plugin.py`.
"""
from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_DIR = ROOT / "plugins" / "xt-native" / "test"
NODE = shutil.which("node")


def _tests() -> list[str]:
    """Every plugin test file, newest layout included."""
    return sorted(str(p) for p in TEST_DIR.glob("*.test.mjs"))


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, cwd=str(ROOT),
                          timeout=300)


@unittest.skipUnless(NODE, "node is not installed")
class TestPluginRuntime(unittest.TestCase):
    def test_plugin_runtime(self):
        tests = _tests()
        self.assertTrue(tests, f"no plugin tests found in {TEST_DIR}")
        proc = _run([NODE, "--test", *tests])
        if proc.returncode != 0 and "bad option" in (proc.stderr or ""):
            # Node >= 23.6 strips types by default and dropped the flag.
            proc = _run([NODE, "--test", *tests])
        self.assertEqual(proc.returncode, 0,
                         f"plugin runtime test failed\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("fail 0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
