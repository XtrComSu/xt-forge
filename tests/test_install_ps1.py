"""Static checks for install.ps1.

PowerShell cannot run in this environment, so these tests PARSE install.ps1
instead of executing it. Each assertion prints its own pass/fail label.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_PS1 = REPO_ROOT / "install.ps1"


class InstallPs1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = INSTALL_PS1.read_text(encoding="utf-8")

    def check(self, label, condition, detail):
        print("[install.ps1] {}: {}".format(label, "OK" if condition else "FAIL"))
        self.assertTrue(condition, msg="{} -- {}".format(label, detail))

    def test_python_version_is_validated_before_installing(self):
        text = self.text
        mentions_version = "version_info" in text and "3.11" in text
        stops_on_old_version = bool(
            re.search(r'throw\s+"\[xt-forge\] Python 3\.11\+ is required; found Python', text)
        )
        before_install = 0 <= text.find("$PythonVersionExpr") < text.find("git clone")
        self.check(
            "text checks Python version (version_info / 3.11)",
            mentions_version,
            "expected both 'version_info' and '3.11' in install.ps1",
        )
        self.check(
            "text stops on failure naming the found version",
            stops_on_old_version,
            "expected a throw mentioning 'Python 3.11+ is required; found Python <version>'",
        )
        self.check(
            "Python check happens before any install step",
            before_install,
            "expected the Python validation block before 'git clone'",
        )

    def test_installed_command_verified_before_path_persistence(self):
        text = self.text
        invoke = bool(
            re.search(r'&\s+"\$LocalBin\\xt-forge\.cmd"\s+version\s+--json', text)
        )
        verify_pos = text.find('Write-Host "[xt-forge] Verifying install..."')
        persist_pos = text.find("[Environment]::SetEnvironmentVariable")
        self.check(
            "text invokes the installed command to verify it",
            invoke,
            'expected: & "$LocalBin\\xt-forge.cmd" version --json',
        )
        self.check(
            "verification precedes PATH persistence",
            0 <= verify_pos < persist_pos,
            "expected 'Verifying install...' before SetEnvironmentVariable",
        )
        self.check(
            "verification failure stops without touching PATH",
            "PATH was not modified" in text,
            "expected the verification failure message to say PATH was not modified",
        )

    def test_does_not_use_setx(self):
        self.check(
            'text does NOT contain "setx"',
            "setx" not in self.text.lower(),
            "setx is forbidden; use [Environment]::SetEnvironmentVariable instead",
        )

    def test_uses_environment_api_with_user_scope_and_is_idempotent(self):
        text = self.text
        get_ok = bool(
            re.search(
                r"\[Environment\]::GetEnvironmentVariable\(\s*['\"]PATH['\"]\s*,\s*['\"]User['\"]\s*\)",
                text,
                re.IGNORECASE,
            )
        )
        set_ok = bool(
            re.search(
                r"\[Environment\]::SetEnvironmentVariable\(\s*['\"]PATH['\"]\s*,[^)]*['\"]User['\"]\s*\)",
                text,
                re.IGNORECASE,
            )
        )
        idempotent = "$Parts -notcontains $LocalBin" in text
        preserves_entries = "$UserPath$Separator$LocalBin" in text
        self.check(
            "uses GetEnvironmentVariable with 'User'",
            get_ok,
            "expected [Environment]::GetEnvironmentVariable('PATH', 'User')",
        )
        self.check(
            "uses SetEnvironmentVariable with 'User'",
            set_ok,
            "expected [Environment]::SetEnvironmentVariable('PATH', ..., 'User')",
        )
        self.check(
            "PATH update is idempotent",
            idempotent,
            "expected a check that $LocalBin is not already in the User PATH",
        )
        self.check(
            "existing User PATH entries are preserved",
            preserves_entries,
            "expected the original $UserPath string to be kept verbatim when appending",
        )

    def test_updates_current_session_path(self):
        assignment = re.search(
            r'\$env:Path\s*=\s*"\$LocalBin;\$env:Path"', self.text
        )
        self.check(
            "updates $env:PATH for the current session",
            bool(assignment),
            'expected: $env:Path = "$LocalBin;$env:Path"',
        )

    def test_install_path_is_quoted(self):
        text = self.text
        quoted_local_bin = bool(re.search(r'"\$LocalBin[^"\r\n]*"', text))
        quoted_cmd_launcher = '`"$CmdLauncher`"' in text
        self.check(
            "quotes the install path in every use",
            quoted_local_bin,
            'expected " quoting around a $LocalBin-based directory in install.ps1',
        )
        self.check(
            "quotes the launcher path written into shims",
            quoted_cmd_launcher,
            "expected the cmd shim body to quote $CmdLauncher",
        )


    def test_local_changes_are_not_discarded_silently(self):
        """`reset --hard` on someone's checkout is data loss.

        These assertions are text-level because PowerShell cannot execute here,
        so they prove the guard is *present and ordered* before the reset — not
        that PowerShell executes it correctly. That limit is real and is why the
        shell installer's equivalent guard is also exercised for real in
        test_install_sh_guard.py.
        """
        text = self.text
        dirty_check = "status --porcelain" in text
        self.check(
            "checks for local changes before resetting",
            dirty_check,
            "expected `git status --porcelain` guarding the reset --hard",
        )
        force_escape = "XT_FORCE_RESET" in text
        self.check(
            "offers XT_FORCE_RESET to opt in to discarding",
            force_escape,
            "expected an XT_FORCE_RESET escape hatch naming the consequence",
        )
        reset_at = text.find('reset --hard "origin/$Branch"')
        check_at = text.find("status --porcelain")
        self.check(
            "the dirty check precedes the reset",
            check_at != -1 and reset_at != -1 and check_at < reset_at,
            "the status check must run before reset --hard or it protects nothing",
        )
        refuses = bool(re.search(r"refusing to discard them", text))
        self.check(
            "refuses rather than warns",
            refuses,
            "expected the installer to stop, not continue after warning",
        )


if __name__ == "__main__":
    unittest.main()
