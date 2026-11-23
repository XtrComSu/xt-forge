"""End-to-end checks for the portable (plain-POSIX-readlink) xtforge launcher."""

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_LAUNCHER = REPO_ROOT / "bin" / "xtforge"
MARKER = "XT_FORGE_POSIX_LAUNCHER_MARKER"


@unittest.skipUnless(shutil.which("bash"), "bash is unavailable")
class PosixLauncherTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

        # A minimal fake "repo" that mirrors the launcher's expected layout.
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        self.launcher = bin_dir / "xtforge"
        shutil.copy2(REAL_LAUNCHER, self.launcher)
        self.launcher.chmod(0o755)
        package = self.root / "xtforge"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "cli.py").write_text(f"print({MARKER!r})\n", encoding="utf-8")

        # wrapper1 -> wrapper2 -> bin/xtforge: an absolute link followed by a
        # RELATIVE one, so both flavours of symlink target are exercised.
        self.wrapper2 = self.root / "wrapper2"
        self.wrapper2.symlink_to("bin/xtforge")
        self.wrapper1 = self.root / "wrapper1"
        self.wrapper1.symlink_to(self.wrapper2)

    def _run_launcher(self, command, path_prefix=None):
        env = os.environ.copy()
        env["XT_FORCE_PYTHON"] = "1"  # no native binary in the fake repo
        env.pop("PYTHONHOME", None)
        if path_prefix is not None:
            env["PATH"] = os.pathsep.join([str(path_prefix), env.get("PATH", "")])
        # cwd is the fake repo root so its xtforge package wins over any
        # installed one (python -m puts cwd first on sys.path).
        return subprocess.run(
            [str(command)],
            cwd=str(self.root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )

    def _assert_marker(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(MARKER, result.stdout)

    def test_relative_and_absolute_symlink_chain(self):
        self._assert_marker(self._run_launcher(self.wrapper1))

    def test_plain_posix_readlink_shim(self):
        real_readlink = shutil.which("readlink")
        if not real_readlink:
            self.skipTest("readlink is unavailable")

        # A shim that rejects every option (so `readlink -f` would fail) and
        # only serves the plain one-argument form.
        shim_dir = self.root / "shim"
        shim_dir.mkdir()
        shim = shim_dir / "readlink"
        shim.write_text(
            "#!/usr/bin/env bash\n"
            "# POSIX-only readlink stand-in: one non-option argument only.\n"
            f"real={shlex.quote(real_readlink)}\n"
            '[ "$#" -eq 1 ] || exit 1\n'
            'case "$1" in -*) exit 1 ;; esac\n'
            'exec "$real" "$1"\n',
            encoding="utf-8",
        )
        shim.chmod(0o755)

        self._assert_marker(self._run_launcher(self.wrapper1, path_prefix=shim_dir))

    def test_invocation_by_name_via_path(self):
        # "$0" has no directory component in this case.
        self._assert_marker(
            self._run_launcher("xtforge", path_prefix=self.launcher.parent)
        )


if __name__ == "__main__":
    unittest.main()
