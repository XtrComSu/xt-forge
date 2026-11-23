"""Source-level guards for the Windows launcher, bin/xtforge.cmd.

cmd.exe is not available in this environment, so these tests verify the
launcher BY PARSING its text. Each assertion is written to make a future
regression (CWD changes, stale ERRORLEVEL, missing Python version gate)
obvious from the failure message.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

LAUNCHER = Path(__file__).resolve().parents[1] / "bin" / "xtforge.cmd"
TEXT = LAUNCHER.read_text(encoding="utf-8")
LINES = TEXT.splitlines()


def code_lines():
    """Yield (line number, stripped text) for executable, non-rem lines."""
    for number, raw in enumerate(LINES, 1):
        stripped = raw.strip()
        if not stripped or stripped.lower() == "rem" or stripped.lower().startswith("rem "):
            continue
        yield number, stripped


def block_depths():
    """Map line number -> parenthesised-block depth at the start of the line."""
    depths = {}
    depth = 0
    for number, stripped in code_lines():
        in_quotes = False
        delta = 0
        for char in stripped:
            if char == '"':
                in_quotes = not in_quotes
            elif not in_quotes:
                if char == "(":
                    delta += 1
                elif char == ")":
                    delta -= 1
        depths[number] = depth
        depth = max(0, depth + delta)
    return depths


class TestWindowsLauncher(unittest.TestCase):
    def test_caller_directory_is_never_changed(self):
        offenders = [
            (number, text)
            for number, text in code_lines()
            if re.search(r"\b(pushd|popd|cd)\b", text, re.IGNORECASE)
        ]
        self.assertFalse(
            offenders,
            f"launcher must not change the caller's CWD; found directory-changing commands: {offenders}",
        )
        self.assertIn(
            "PYTHONPATH=%ROOT%;%PYTHONPATH%",
            TEXT,
            "launcher must keep prepending %ROOT% to PYTHONPATH so -m xtforge.cli works without pushd",
        )

    def test_python_version_gate(self):
        check_lines = [
            text
            for _, text in code_lines()
            if "-c" in text and "sys.exit" in text and "version_info" in text
        ]
        self.assertTrue(
            check_lines,
            "launcher must run a `<python> -c` gate using sys.version_info before using an interpreter",
        )
        self.assertIn(
            "(3,11)",
            check_lines[0].replace(" ", ""),
            "version gate must require Python >= (3,11): " + check_lines[0],
        )
        check_index = LINES.index(next(line for line in LINES if line in check_lines))
        cli_indexes = [i for i, line in enumerate(LINES) if "-m xtforge.cli" in line]
        self.assertTrue(
            cli_indexes and min(cli_indexes) > check_index,
            "the Python version check must appear before any `-m xtforge.cli` dispatch",
        )

    def test_exit_status_capture_precedes_status_exit(self):
        status_exit = re.compile(r"\bexit\s+/b\s+(%[^%\s]+%|![^!\s]+!)", re.IGNORECASE)
        capture = re.compile(
            r'set\s+"?[A-Za-z_][A-Za-z0-9_]*=%ERRORLEVEL%"?\s*$', re.IGNORECASE
        )
        lines = list(code_lines())
        depths = block_depths()
        seen = 0
        for position, (number, text) in enumerate(lines):
            match = status_exit.search(text)
            if not match:
                continue
            seen += 1
            self.assertEqual(
                depths[number],
                0,
                f"line {number}: `exit /b` returning a status is inside a parenthesised block, "
                f"where %ERRORLEVEL% would be expanded before the command ran: {text}",
            )
            if "!ERRORLEVEL!" in match.group(1).upper():
                continue  # delayed expansion is explicitly allowed
            self.assertGreater(position, 0, f"line {number}: status exit has no preceding capture")
            prev_number, prev_text = lines[position - 1]
            self.assertEqual(
                depths[prev_number],
                0,
                f"line {number}: the %ERRORLEVEL% capture must also be outside a parenthesised block",
            )
            self.assertRegex(
                prev_text,
                capture,
                f"line {number}: `exit /b` with a variable status must immediately follow a "
                f"`set VAR=%%ERRORLEVEL%%` capture; previous executable line was: {prev_text}",
            )
        self.assertGreater(
            seen, 0, "launcher must propagate the real status with `exit /b %RC%`-style exits"
        )

    def test_interpreter_candidate_order(self):
        markers = [
            ("%XT_PYTHON%", re.compile(r'set\s+"PYCMD="%XT_PYTHON%""', re.IGNORECASE)),
            ("python", re.compile(r'set\s+"PYCMD=python"', re.IGNORECASE)),
            ("py -3", re.compile(r'set\s+"PYCMD=py -3"', re.IGNORECASE)),
            ("python3", re.compile(r'set\s+"PYCMD=python3"', re.IGNORECASE)),
        ]
        positions = []
        for name, pattern in markers:
            hits = [(number, text) for number, text in code_lines() if pattern.search(text)]
            self.assertEqual(
                len(hits),
                1,
                f"expected exactly one assignment selecting candidate {name!r}, found {hits}",
            )
            positions.append(hits[0][0])
        self.assertEqual(
            positions,
            sorted(positions),
            f"candidate order must be %%XT_PYTHON%%, python, py -3, python3; got line numbers {positions}",
        )

    def test_no_suitable_interpreter_exits_two_with_stderr_message(self):
        exits = [(number, text) for number, text in code_lines() if re.search(r"exit\s+/b\s+2\b", text, re.IGNORECASE)]
        self.assertTrue(
            exits,
            "launcher must `exit /b 2` when no interpreter satisfies the version gate",
        )
        number = exits[0][0]
        nearby = [text for n, text in code_lines() if number - 6 <= n < number]
        self.assertTrue(
            any("no suitable" in text.lower() and "interpreter" in text.lower() for text in nearby),
            f"line {number}: the exit /b 2 path must explain that no suitable interpreter was found",
        )
        stderr_messages = [text for text in nearby if text.lower().startswith("echo") and ">&2" in text]
        self.assertTrue(
            stderr_messages,
            f"line {number}: the no-interpreter explanation must be echoed to stderr (>&2)",
        )


if __name__ == "__main__":
    unittest.main()
