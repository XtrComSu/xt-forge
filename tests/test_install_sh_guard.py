"""Executable tests for install.sh's source-update guard.

WHY these run for real: install.ps1 can only be parse-checked on this platform,
so its guard is asserted as text. install.sh is bash, so the guard can actually be
executed, and executing it is the only way to know that a user's uncommitted edits
survive an install. A text assertion would pass just as happily on a script whose
quoting is broken and whose guard never fires.

Each test builds a throwaway git remote and checkout under a temp dir, points HOME
at it, and runs the resolve_root function extracted from install.sh — the function
that decides whether to fetch, whether to reset, and what to do when both are
unsafe. Extraction is by `sed` on the real file, so the code under test is the
shipped code rather than a copy that can drift.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(GIT_ENV)
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, env=env)


def _extract_resolve_root() -> str:
    """Pull resolve_root() out of install.sh verbatim.

    Keeps the test honest: if the function is renamed or restructured, the
    extraction fails loudly instead of silently testing a stale copy.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(r"^resolve_root\(\) \{.*?^\}", text, re.S | re.M)
    if not match:
        raise AssertionError("could not extract resolve_root() from install.sh")
    return match.group(0)


class InstallShGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolve_root = _extract_resolve_root()

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

        seed = self.tmp / "seed"
        seed.mkdir()
        (seed / "bin").mkdir()
        (seed / "VERSION").write_text("1.0\n")
        (seed / "bin" / "xtforge").write_text("#!/bin/sh\necho fake\n")
        (seed / "bin" / "xtforge").chmod(0o755)
        self.assertEqual(_git("init", "-q", "-b", "main", cwd=seed).returncode, 0)
        _git("add", "-A", cwd=seed)
        self.assertEqual(_git("commit", "-qm", "init", cwd=seed).returncode, 0)

        self.remote = self.tmp / "remote.git"
        self.assertEqual(_git("clone", "-q", "--bare", str(seed), str(self.remote),
                              cwd=self.tmp).returncode, 0)

        self.home = self.tmp / "home"
        self.home.mkdir()
        self.checkout = self.home / ".xt-forge-src"
        self.assertEqual(_git("clone", "-q", "--branch", "main", str(self.remote),
                              str(self.checkout), cwd=self.tmp).returncode, 0)

    def _run(self, *, remote_url: str | None = None, env_extra: dict | None = None
             ) -> subprocess.CompletedProcess:
        if remote_url is not None:
            _git("remote", "set-url", "origin", remote_url, cwd=self.checkout)
        script = (
            "set -euo pipefail\n"
            "BRANCH=main\n"
            f"REPO_URL={remote_url or str(self.remote)!r}\n"
            f"{self.resolve_root}\n"
            'ROOT="$(resolve_root)"\n'
            'echo "ROOT=$ROOT"\n'
        )
        env = dict(os.environ)
        env.update(GIT_ENV)
        env["HOME"] = str(self.home)
        env.pop("XT_FORCE_RESET", None)
        env.pop("XT_SKIP_FETCH", None)
        if env_extra:
            env.update(env_extra)
        # cwd must be a directory with no VERSION/bin/xtforge pair: resolve_root
        # short-circuits to `pwd` when it finds one, which would silently test the
        # repo in the working tree instead of the throwaway checkout under HOME.
        neutral = self.tmp / "neutral"
        neutral.mkdir(exist_ok=True)
        return subprocess.run(["bash", "-c", script], capture_output=True,
                              text=True, env=env, timeout=120, cwd=str(neutral))

    def test_clean_checkout_updates(self):
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(f"ROOT={self.checkout}", res.stdout)

    def test_local_edits_are_refused_and_preserved(self):
        """The headline guarantee: an install must never eat uncommitted work."""
        marker = "IMPORTANT USER EDIT"
        (self.checkout / "VERSION").write_text(f"1.0\n{marker}\n")

        res = self._run()
        self.assertNotEqual(res.returncode, 0,
                            "a dirty checkout must stop the install, not be reset over")
        self.assertIn("refusing to discard", res.stderr)
        self.assertIn(marker, (self.checkout / "VERSION").read_text(),
                      "the user's edit was discarded — this is the data-loss bug")

    def test_force_reset_discards_only_when_asked(self):
        marker = "IMPORTANT USER EDIT"
        (self.checkout / "VERSION").write_text(f"1.0\n{marker}\n")

        res = self._run(env_extra={"XT_FORCE_RESET": "1"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("XT_FORCE_RESET=1", res.stderr)
        self.assertNotIn(marker, (self.checkout / "VERSION").read_text(),
                         "XT_FORCE_RESET=1 was set, so the edit should be gone")

    def test_unreachable_remote_fails_loudly_instead_of_installing_stale(self):
        """A swallowed fetch error meant `reset --hard` reinstalled the old tree.

        The installer then reported success while shipping a build that was not
        what the user asked for, which is worse than failing.
        """
        res = self._run(remote_url=str(self.tmp / "gone.git"))
        self.assertNotEqual(res.returncode, 0,
                            "an unreachable origin must not be reported as a successful update")
        self.assertIn("could not fetch", res.stderr)
        self.assertNotIn("ROOT=", res.stdout,
                         "the installer must not continue with a stale checkout")

    def test_skip_fetch_builds_from_the_existing_tree_on_purpose(self):
        res = self._run(remote_url=str(self.tmp / "gone.git"),
                        env_extra={"XT_SKIP_FETCH": "1"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(f"ROOT={self.checkout}", res.stdout)


class InstallRegistersMcpTests(unittest.TestCase):
    """A fresh install must leave agents able to see xt-forge tools.

    `doctor` reported `mcp: not registered` after a clean install, because the
    installer never ran `sync`. Everything else was green, so the install looked
    finished while the entire MCP surface — the reason this tool exists for an
    agent — was dead until the user ran a second command nobody told them about.

    These are text assertions on install.sh and install.ps1 because the full
    install is a multi-minute build; the executable end-to-end check of the same
    guarantee lives in the release checklist. What they pin is that the sync call
    stays present, stays after the launcher exists, and stays skippable.
    """

    def setUp(self) -> None:
        self.sh = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        self.ps1 = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")

    def test_sh_runs_sync_after_installing_the_launcher(self):
        self.assertIn("xt-forge\" sync", self.sh,
                      "install.sh no longer runs sync, so MCP stays unregistered")
        sync_at = self.sh.find('"${LOCAL_BIN}/xt-forge" sync')
        version_at = self.sh.find('"${LOCAL_BIN}/xt-forge" version --json')
        self.assertGreater(sync_at, version_at,
                           "sync must run after the launcher exists, not before")

    def test_ps1_runs_sync_after_installing_the_launcher(self):
        self.assertIn("xt-forge.cmd\" sync", self.ps1,
                      "install.ps1 no longer runs sync, so MCP stays unregistered")
        sync_at = self.ps1.find("xt-forge.cmd\" sync")
        verify_at = self.ps1.find("version --json")
        self.assertGreater(sync_at, verify_at,
                           "sync must run after the launcher is verified")

    def test_both_installers_keep_an_escape_hatch(self):
        for name, text in (("install.sh", self.sh), ("install.ps1", self.ps1)):
            self.assertIn("XT_SKIP_SYNC", text,
                          f"{name} lost its XT_SKIP_SYNC override, so the sync step "
                          f"cannot be bypassed in an offline or locked-down install")

    def test_failure_to_sync_is_reported_not_swallowed(self):
        """A soft failure here hides a dead MCP surface, so it must be said out loud."""
        self.assertIn("sync did not complete", self.sh)
        self.assertIn("sync did not complete", self.ps1)


if __name__ == "__main__":
    unittest.main()
