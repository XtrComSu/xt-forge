from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class TestREProject(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.project = Path(self.scratch.name) / "example research"

    def xtforge(self, *args):
        env = dict(os.environ, XT_ROOTS=str(Path(self.scratch.name).resolve()), XT_PERM_MODE="ask")
        return subprocess.run([sys.executable, "-m", "xtforge.cli", *args],
                              cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)

    def scaffold_project(self):
        proc = self.xtforge("re", "init-project", str(self.project), "--name", "Example & Co", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_scaffold_contains_linked_showcase_and_preserves_existing_project(self):
        self.scaffold_project()
        readme = self.project / "README.md"
        original = readme.read_text(encoding="utf-8")
        self.assertIn("Example &amp; Co", original)
        for name in ("docs/assets/showcase.gif", "docs/assets/activity.svg",
                     "docs/REPORT.md", "CONTRIBUTING.md", "fixtures/demo.c"):
            self.assertIn(name, original)
            self.assertTrue((self.project / name).is_file(), name)
        self.assertEqual((self.project / "docs/assets/showcase.gif").read_bytes()[:6], b"GIF89a")
        self.assertTrue((self.project / ".github/ISSUE_TEMPLATE/finding.md").is_file())
        self.assertTrue((self.project / ".github/pull_request_template.md").is_file())
        readme.write_text("keep my changes\n", encoding="utf-8")
        repeat = self.xtforge("re", "init-project", str(self.project), "--json")
        self.assertNotEqual(repeat.returncode, 0)
        self.assertEqual(readme.read_text(encoding="utf-8"), "keep my changes\n")

    @unittest.skipUnless(shutil.which("git"), "Git required for activity verification")
    def test_activity_uses_local_commits_and_utc_dates(self):
        self.scaffold_project()
        svg = self.project / "docs/assets/activity.svg"
        update = [sys.executable, str(self.project / "scripts/update_activity.py")]
        no_git = subprocess.run(update, capture_output=True, cwd=self.project)
        self.assertNotEqual(no_git.returncode, 0)
        self.assertIn("No Git history", svg.read_text(encoding="utf-8"))
        subprocess.run(["git", "init", "-q"], cwd=self.project, check=True)
        subprocess.run(update, cwd=self.project, check=True, capture_output=True)
        self.assertIn("0 commits", svg.read_text(encoding="utf-8"))
        fixed = datetime.now(timezone.utc).date() - timedelta(days=1)
        yesterday_local = fixed - timedelta(days=1)
        same_utc_day = f"{yesterday_local}T21:15:00-04:00"
        old = f"{fixed - timedelta(days=364)}T12:00:00+00:00"
        for stamp in (old, same_utc_day, same_utc_day):
            env = dict(os.environ, GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "Recorded test evidence"],
                cwd=self.project, check=True, env=env,
            )
        subprocess.run(update, cwd=self.project, check=True, capture_output=True)
        rendered = svg.read_bytes()
        root = ET.fromstring(rendered)
        tags = [el.text for el in root.iter("{http://www.w3.org/2000/svg}title")]
        self.assertIn(f"{fixed}: 2 commits", tags)
        self.assertIn(b"2 commits across 1 active day", rendered)
        subprocess.run(update, cwd=self.project, check=True, capture_output=True)
        self.assertEqual(svg.read_bytes(), rendered)
