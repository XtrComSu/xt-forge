"""Contract tests for the shipped OpenCode plugin (taste/goal/loop).

The plugin used to be a loose file in `~/.config/opencode/plugins/` that
nobody could review or reinstall. It is source in this repository now, and
`xtforge plugin install` puts it on a machine.

Acceptance:
  - install copies the source and registers it without touching anything else
  - install is idempotent
  - status detects drift between the installed copy and the source
  - uninstall takes it back off
  - the CLI speaks JSON
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

from xtforge.core.plugin import manager  # noqa: E402

CONFIG = {"$schema": "https://opencode.ai/config.json",
          "mcp": {"servers": {"xt-forge": {"type": "local"}}},
          "plugins": ["/somewhere/else"]}


class PluginCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="plugin-"))
        self.home = self.tmp / "home"
        self.cfg_dir = self.home / ".config" / "opencode"
        self.cfg_dir.mkdir(parents=True)
        self.cfg = self.cfg_dir / "opencode.json"
        self.cfg.write_text(json.dumps(CONFIG, indent=2), encoding="utf-8")
        self._old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._old_home

    def install(self, **kw):
        return manager.install(home=self.home, **kw)

    def status(self, **kw):
        return manager.status(home=self.home, **kw)


class TestInstall(PluginCase):
    def test_install_copies_the_source(self):
        res = self.install()
        target = Path(res["target"])
        self.assertTrue((target / "index.ts").is_file())
        self.assertTrue((target / "package.json").is_file())
        self.assertTrue((target / "installed.json").is_file())
        self.assertIn("index.ts", res["files"])

    def test_install_registers_the_plugin(self):
        res = self.install()
        data = json.loads(self.cfg.read_text())
        self.assertIn(res["target"], data["plugins"])
        self.assertTrue(res["registered"])
        self.assertTrue(res["config_changed"])

    def test_install_preserves_the_rest_of_the_config(self):
        self.install()
        data = json.loads(self.cfg.read_text())
        self.assertEqual(data["mcp"], CONFIG["mcp"])
        self.assertIn("/somewhere/else", data["plugins"])
        self.assertEqual(data["$schema"], CONFIG["$schema"])

    def test_install_is_idempotent(self):
        self.install()
        second = self.install()
        self.assertTrue(second["registered"])
        self.assertFalse(second["config_changed"])
        data = json.loads(self.cfg.read_text())
        self.assertEqual(data["plugins"].count(second["target"]), 1)

    def test_install_stamps_the_paths_the_plugin_needs(self):
        res = self.install()
        stamp = json.loads((Path(res["target"]) / "installed.json").read_text())
        self.assertEqual(stamp["plugin"], "xt-native")
        self.assertEqual(stamp["root"], str(ROOT))
        self.assertTrue(stamp["python"])
        self.assertIn("index.ts", stamp["files"])

    def test_install_backs_up_the_config_it_rewrites(self):
        self.install()
        backups = list(self.cfg_dir.glob("opencode.json.bak-*"))
        self.assertTrue(backups, "the config was rewritten without a backup")


class TestStatus(PluginCase):
    def test_status_before_install(self):
        res = self.status()
        self.assertFalse(res["installed"])
        self.assertFalse(res["registered"])

    def test_status_after_install_is_current(self):
        self.install()
        res = self.status()
        self.assertTrue(res["installed"])
        self.assertTrue(res["registered"])
        self.assertTrue(res["current"], res["drift"])

    def test_status_detects_a_modified_file(self):
        res = self.install()
        target = Path(res["target"])
        (target / "index.ts").write_text("// tampered\n", encoding="utf-8")
        res = self.status()
        self.assertFalse(res["current"])
        self.assertIn("index.ts", res["drift"]["modified"])

    def test_status_detects_a_missing_file(self):
        res = self.install()
        (Path(res["target"]) / "package.json").unlink()
        res = self.status()
        self.assertIn("package.json", res["drift"]["missing"])

    def test_status_detects_an_extra_file(self):
        res = self.install()
        (Path(res["target"]) / "stray.txt").write_text("x", encoding="utf-8")
        res = self.status()
        self.assertIn("stray.txt", res["drift"]["extra"])

    def test_status_reports_the_installed_version(self):
        self.install()
        res = self.status()
        self.assertTrue(res["version"])


class TestUninstall(PluginCase):
    def test_uninstall_unregisters(self):
        res = self.install()
        out = manager.uninstall(home=self.home)
        self.assertTrue(out["config_changed"])
        data = json.loads(self.cfg.read_text())
        self.assertNotIn(res["target"], data["plugins"])
        self.assertIn("/somewhere/else", data["plugins"])

    def test_uninstall_keeps_files_by_default(self):
        res = self.install()
        manager.uninstall(home=self.home)
        self.assertTrue((Path(res["target"]) / "index.ts").is_file())

    def test_uninstall_with_purge_removes_the_files(self):
        res = self.install()
        manager.uninstall(home=self.home, purge=True)
        self.assertFalse(Path(res["target"]).exists())


class TestCLI(PluginCase):
    def run_cli(self, *argv):
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", *argv],
            capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=60)
        return proc

    def test_status_is_json(self):
        proc = self.run_cli("plugin", "status", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["plugin"], "xt-native")
        self.assertIn("drift", payload)

    def test_install_then_status_through_the_cli(self):
        proc = self.run_cli("plugin", "install", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = json.loads(proc.stdout)
        self.assertTrue(res["registered"])
        proc = self.run_cli("plugin", "status", "--json")
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["current"], payload["drift"])


class TestSource(PluginCase):
    """The shipped source is the source of truth, and it is complete."""

    def test_source_exists(self):
        src = manager.source_dir()
        self.assertTrue((src / "index.ts").is_file())
        self.assertTrue((src / "package.json").is_file())

    def test_manifest_covers_the_shipped_files(self):
        files = manager.manifest()
        self.assertIn("index.ts", files)
        self.assertIn("package.json", files)
        self.assertNotIn(manager.STAMP_NAME, files)

    def test_the_manifest_is_only_the_runtime_surface(self):
        # Tests live in the canon but are not installed: the live copy only
        # has to load, not to prove itself.
        self.assertEqual(sorted(manager.manifest()), ["index.ts", "package.json"])

    def test_the_plugin_never_hardcodes_one_home_directory(self):
        text = (manager.source_dir() / "index.ts").read_text(encoding="utf-8")
        self.assertNotIn(str(Path.home()), text)
        self.assertIn("installed.json", text)


if __name__ == "__main__":
    unittest.main()
