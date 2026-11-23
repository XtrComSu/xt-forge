"""Doctor reports five repair-oriented checks in JSON, never an exception."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.diagnostics import (  # noqa: E402
    MCP_NOT_REGISTERED, MCP_REGISTERED_DISABLED,
)

NAMES = {"launcher", "runtime", "native hub", "skills", "mcp"}
KEYS = {"name", "ok", "value", "detail", "repair"}


class DoctorRepairTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.home = self.base / "home"
        self.xt_home = self.base / "xthome"
        self.home.mkdir()
        self.xt_home.mkdir()  # deliberately empty
        self.config_dir = self.home / ".config" / "opencode"
        # Stripped environment: no inherited PATH, HOME or MCP config.
        self.env = {
            "HOME": str(self.home),
            "XT_HOME": str(self.xt_home),
            "XT_PREFIX": str(self.base / "prefix"),
            "PATH": str(self.base / "bin"),
        }

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def doctor(self) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "doctor", "--json"],
            cwd=str(ROOT), env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["checks"], data["repairs"])
        return data

    def item(self, name: str) -> dict:
        for entry in self.doctor()["checks"]:
            if entry["name"] == name:
                return entry
        self.fail(f"doctor did not report {name!r}")

    def test_all_five_items_have_the_required_keys(self) -> None:
        items = self.doctor()["checks"]
        self.assertEqual({entry["name"] for entry in items}, NAMES)
        for entry in items:
            self.assertTrue(KEYS <= set(entry), entry)
            self.assertIsInstance(entry["ok"], bool)
            for key in ("value", "detail", "repair"):
                self.assertIsInstance(entry[key], str)
            if entry["ok"]:
                self.assertEqual(entry["repair"], "")

    def test_runtime_reports_version_consistent_with_ok(self) -> None:
        entry = self.item("runtime")
        match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", entry["value"])
        self.assertIsNotNone(match, entry)
        assert match is not None
        expected = (int(match.group(1)), int(match.group(2))) >= (3, 11)
        self.assertEqual(entry["ok"], expected)
        self.assertIn("3.11", entry["detail"])

    def test_empty_xt_home_makes_skills_fail_with_a_repair(self) -> None:
        entry = self.item("skills")
        self.assertFalse(entry["ok"])
        self.assertIn("0", entry["value"])
        self.assertTrue(entry["repair"])
        self.assertIn(str(self.xt_home), entry["detail"])
        for target in (".dsh/skills", ".agents/skills", ".claude/skills",
                       ".config/opencode/skills"):
            self.assertIn(target, entry["detail"])

    def test_mcp_distinguishes_not_registered_from_disabled(self) -> None:
        absent = self.item("mcp")
        self.assertFalse(absent["ok"])
        self.assertIn(MCP_NOT_REGISTERED, absent["detail"])
        self.assertTrue(absent["repair"])

        self.config_dir.mkdir(parents=True)
        (self.config_dir / "opencode.json").write_text(json.dumps({
            "mcp": {"servers": {"xt-forge": {
                "type": "local", "command": [sys.executable], "disabled": True,
            }}},
        }), encoding="utf-8")
        disabled = self.item("mcp")
        self.assertFalse(disabled["ok"])
        self.assertIn(MCP_REGISTERED_DISABLED, disabled["detail"])
        self.assertTrue(disabled["repair"])

        self.assertNotEqual(absent["detail"], disabled["detail"])
        self.assertNotEqual(absent["repair"], disabled["repair"])
        self.assertNotEqual(MCP_NOT_REGISTERED, MCP_REGISTERED_DISABLED)

    def test_enabled_mcp_server_passes_without_a_repair(self) -> None:
        self.config_dir.mkdir(parents=True)
        (self.config_dir / "opencode.json").write_text(json.dumps({
            "mcp": {"servers": {"xt-forge": {
                "type": "local", "command": [sys.executable],
            }}},
        }), encoding="utf-8")
        entry = self.item("mcp")
        self.assertTrue(entry["ok"])
        self.assertEqual(entry["repair"], "")


if __name__ == "__main__":
    unittest.main()
