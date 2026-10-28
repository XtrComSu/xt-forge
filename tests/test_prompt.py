import unittest
import tempfile
from pathlib import Path

from xtforge.core import prompts as pmod
from xtforge.core.mem.flash import Flash


class TestPrompts(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.flash_dir = Path(self.tmpdir.name) / "flash"
        self.flash_dir.mkdir(parents=True, exist_ok=True)
        self.fl = Flash(self.flash_dir)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_hash_all(self):
        hashes = pmod.hash_all()
        self.assertIsInstance(hashes, dict)
        self.assertTrue(len(hashes) > 0)
        for k, v in hashes.items():
            self.assertEqual(len(v), 12)

    def test_build_agent_context_basic(self):
        ctx = pmod.build_agent_context(include_taste=False, include_flash=False, harness="generic")
        self.assertIn("system_instructions", ctx)
        self.assertIn("xtforge", ctx)

    def test_build_agent_context_flash_pinned(self):
        self.fl.set("pinned note for context", key="pin1", pin=True)
        self.fl.set("unpinned note", key="unpin1", pin=False)
        ctx = pmod.build_agent_context(
            include_taste=False,
            include_flash=True,
            flash_base=self.flash_dir,
            harness="generic"
        )
        self.assertIn("pinned note for context", ctx)
        self.assertNotIn("unpinned note", ctx)
        self.assertIn('<session_flash source="flash" type="pinned">', ctx)

    def test_build_agent_context_compact(self):
        self.fl.set("pinned note", key="p1", pin=True)
        ctx = pmod.build_agent_context(
            include_taste=False,
            include_flash=True,
            flash_base=self.flash_dir,
            harness="dsh",
            compact=True
        )
        self.assertNotIn("\n\n", ctx)
        self.assertIn('<harness type="dsh">', ctx)
        self.assertIn('<session_flash><p k="p1">pinned note</p></session_flash>', ctx)

    def test_build_agent_context_harness_dsh(self):
        ctx = pmod.build_agent_context(include_taste=False, include_flash=False, harness="dsh")
        self.assertIn('<harness_context type="dsh">', ctx)
        self.assertIn('mcp__memos__mem_put', ctx)
        self.assertIn('dsh-context', ctx)

    def test_token_budget_truncation(self):
        self.fl.set("A" * 200, key="long_pin", pin=True)
        ctx = pmod.build_agent_context(
            include_taste=False,
            include_flash=True,
            flash_base=self.flash_dir,
            harness="generic",
            token_budget=50  # ~200 chars limit
        )
        self.assertLessEqual(len(ctx), 250)
        self.assertIn("system_instructions", ctx)


if __name__ == "__main__":
    unittest.main()
