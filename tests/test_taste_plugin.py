"""Contract tests for shipping the OpenCode taste plugin.

The plugin is TypeScript and lives in the harness, so the tests split by
where the truth lives:

  - `plugins/xt-native/test/` (Node) drives the plugin itself: its commands,
    its hooks, the injected block, a fabricated completion claim, and the ten
    scripted sessions of the D2 acceptance (expected learnings, zero invented
    keys). `tests/test_plugin_runtime.py` runs those from this suite.
  - `tests/test_plugin.py` covers the installer: install, status, drift,
    uninstall.
  - **this file** covers the wiring around the plugin: `xtforge sync` ships
    it, the OpenCode config is written in the shape OpenCode v2 reads, and
    the doctor can see the result.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.diagnostics import _integration  # noqa: E402
from xtforge.core.plugin import manager  # noqa: E402

CANON = manager.source_dir() / "index.ts"


class PluginTestCase(unittest.TestCase):
    """Shared setup: a throwaway home with an OpenCode installed in it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tasteplugin-"))
        self.addCleanup(self._cleanup, self.tmp)
        self.home = self.tmp / "home"
        self.xt_home = self.tmp / "xt-home"
        self.home.mkdir()
        self.xt_home.mkdir()
        # An installed OpenCode: sync only wires the config when the harness
        # is actually present.
        (self.home / ".config" / "opencode").mkdir(parents=True)

    @staticmethod
    def _cleanup(path: Path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)

    def run_cli(self, *args, expect_ok: bool = True, home=None):
        env = dict(os.environ)
        env["XT_HOME"] = str(self.xt_home)
        env["HOME"] = str(home or self.home)
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", *args, "--json"],
            capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=120)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc


class TestSyncShipsThePlugin(PluginTestCase):
    """`xtforge sync` installs the plugin through the one installer."""

    def test_canon_exists(self):
        self.assertTrue(CANON.is_file(), f"missing plugin canon: {CANON}")
        self.assertIn("index.ts", manager.manifest())

    def test_sync_installs_the_plugin(self):
        self.run_cli("sync", home=self.home)
        installed = manager.target_dir(self.home) / "index.ts"
        self.assertTrue(installed.is_file())
        self.assertEqual(installed.read_text(encoding="utf-8"),
                         CANON.read_text(encoding="utf-8"))

    def test_sync_registers_the_plugin_in_the_config(self):
        self.run_cli("sync", home=self.home)
        config = manager.config_path(self.home)
        data = json.loads(config.read_text(encoding="utf-8"))
        registered = [e for e in data.get("plugins", [])
                      if isinstance(e, str) and "xt-native" in e]
        self.assertEqual(len(registered), 1)
        self.assertEqual(registered[0], str(manager.target_dir(self.home)))

    def test_sync_is_idempotent(self):
        self.run_cli("sync", home=self.home)
        second = json.loads(self.run_cli("sync", home=self.home).stdout)
        self.assertEqual(second["written"], 0)
        self.assertGreater(second["unchanged"], 0)

    def test_dry_run_touches_nothing(self):
        proc = self.run_cli("sync", "--dry-run", home=self.home)
        payload = json.loads(proc.stdout)
        self.assertGreater(payload["would_write"], 0)
        self.assertFalse((manager.target_dir(self.home) / "index.ts").exists())


class TestConfigShape(PluginTestCase):
    """The config is written the way OpenCode v2 reads it, and nothing else
    that was already there is touched."""

    def _config(self) -> Path:
        return self.home / ".config" / "opencode" / "opencode.json"

    def test_sync_never_removes_other_keys(self):
        self._config().write_text(json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "theme": "xt-code",
            "mcp": {"servers": {"github": {"type": "local",
                                           "command": ["/bin/true"]}}},
        }, indent=2), encoding="utf-8")
        self.run_cli("sync", home=self.home)
        data = json.loads(self._config().read_text(encoding="utf-8"))
        self.assertEqual(data["theme"], "xt-code")
        self.assertIn("github", data["mcp"]["servers"])
        self.assertEqual(data["$schema"], "https://opencode.ai/config.json")

    def test_sync_keeps_a_working_mcp_command(self):
        """A working config must not be rewritten with another machine's paths."""
        server = self.tmp / "server.py"
        server.write_text("# stub\n", encoding="utf-8")
        self._config().write_text(json.dumps({
            "mcp": {"servers": {"xt-forge": {"type": "local",
                                             "command": [sys.executable,
                                                         str(server)]}}},
        }, indent=2), encoding="utf-8")
        self.run_cli("sync", home=self.home)
        data = json.loads(self._config().read_text(encoding="utf-8"))
        self.assertEqual(data["mcp"]["servers"]["xt-forge"]["command"],
                         [sys.executable, str(server)])

    def test_sync_uses_the_v2_mcp_servers_shape(self):
        """OpenCode v2 reads mcp.servers; the deprecated flat form is avoided."""
        self._config().write_text(json.dumps({"mcp": {"servers": {}}}, indent=2),
                                  encoding="utf-8")
        self.run_cli("sync", home=self.home)
        data = json.loads(self._config().read_text(encoding="utf-8"))
        self.assertIn("xt-forge", data["mcp"]["servers"])
        self.assertNotIn("xt-forge", data["mcp"],
                         "the deprecated flat shape must not be written")
        server = data["mcp"]["servers"]["xt-forge"]
        self.assertEqual(server["type"], "local")
        self.assertTrue(server["command"][0])
        # Keys the v2 server schema does not accept.
        self.assertNotIn("enabled", server)
        self.assertNotIn("timeout", server)

    def test_sync_writes_a_fresh_config_in_the_v2_shape(self):
        self.run_cli("sync", home=self.home)
        data = json.loads(self._config().read_text(encoding="utf-8"))
        self.assertIn("xt-forge", data["mcp"]["servers"])
        self.assertIn("plugins", data)


class TestDoctorSeesThePlugin(PluginTestCase):
    def test_doctor_sees_the_installed_plugin(self):
        self.run_cli("sync", home=self.home)
        state = _integration(self.home)
        self.assertTrue(state["opencode_plugin_registered"])
        self.assertTrue(state["opencode_plugin_installed"])

    def test_doctor_reports_a_missing_plugin(self):
        state = _integration(self.home)
        self.assertFalse(state["opencode_plugin_installed"])
        self.assertIsNone(state["opencode_plugin_registered"])


class TestLiveInstall(unittest.TestCase):
    """The install on this machine must not drift from the source."""

    def test_live_install_is_current(self):
        home = Path(os.environ.get("HOME", "/root"))
        target = manager.target_dir(home)
        if not (target / "index.ts").is_file():
            self.skipTest("plugin is not installed in this home")
        res = manager.status(home=home)
        self.assertTrue(res["registered"])
        self.assertTrue(res["current"], res["drift"])


if __name__ == "__main__":
    unittest.main()
