"""Unified zero-guesswork test runner (`xtforge test [path]`).

Auto-detects the available runner for Python (`pytest` if installed, else
`python3 -m unittest discover`), Rust (`cargo test`), Go (`go test ./...`),
or Node (`npm test`) so agents never waste turns on missing `pytest` binaries.
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..route import guard


def detect_test_command(root: Path) -> tuple[str, list[str]]:
    if (root / "Cargo.toml").is_file() and shutil.which("cargo"):
        return "cargo", ["cargo", "test"]
    if (root / "go.mod").is_file() and shutil.which("go"):
        return "go", ["go", "test", "./..."]
    if (root / "package.json").is_file() and shutil.which("npm"):
        pkg_text = (root / "package.json").read_text(encoding="utf-8", errors="replace")
        if '"test"' in pkg_text:
            return "npm", ["npm", "test", "--silent"]

    # Python: prefer pytest ONLY if importable in the active interpreter or venv
    venv_pytest = root / ".venv" / "bin" / "pytest"
    if venv_pytest.is_file():
        return "pytest", [str(venv_pytest), "-q"]
    if importlib.util.find_spec("pytest") is not None:
        return "pytest", [sys.executable, "-m", "pytest", "-q"]
    tests = root / "tests"
    start = tests if tests.is_dir() else root
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(start)]
    if start == tests and (tests / "__init__.py").is_file():
        cmd.extend(["-t", str(root)])
    return "unittest", cmd


def _selected_count(runner: str, output: str) -> int | None:
    """Best-effort count of tests selected, from the runner's own output.

    None means "cannot determine" -- deliberately distinct from 0, which is a
    known-empty selection.
    """
    if runner == "unittest":
        match = re.search(r"\bRan\s+(\d+)\s+tests?\b", output)
        return int(match.group(1)) if match else None
    if runner == "pytest":
        if re.search(r"\bno tests ran\b", output, re.IGNORECASE):
            return 0
        match = re.search(r"\b(\d+)\s+passed\b", output, re.IGNORECASE)
        return int(match.group(1)) if match else None
    return None


def _apply_unittest_name_filter(cmd: list[str], pattern: str) -> None:
    """Append unittest's *name* filter (-k). Never use -p (a filename glob).

    `python -m unittest -p NAME` treats NAME as a filename pattern, so a test
    *name* filter silently selects no files and unittest still exits 0.

    Choice of placement: when the command already uses the `discover`
    subcommand, -k is simply appended to its options. For a direct module run
    (`python -m unittest pkg.test_mod`), unittest also accepts -k as a global
    option, so we append -k there as well -- but we must NOT insert `discover`
    in that case, because that would change *what* runs (a directory scan)
    instead of merely filtering the named module. Commands that do not run
    unittest at all are left untouched.
    """
    runs_unittest_module = any(
        token == "-m" and i + 1 < len(cmd) and cmd[i + 1] == "unittest"
        for i, token in enumerate(cmd)
    )
    if "discover" not in cmd and not runs_unittest_module:
        return
    cmd.extend(["-k", pattern])


def run_tests(path: str | Path = ".", *, pattern: str = "", timeout_s: int = 90) -> dict[str, Any]:
    canon = guard.read_guard(path)
    root = canon if canon.is_dir() else canon.parent
    runner, cmd = detect_test_command(root)
    if pattern:
        if runner == "pytest":
            cmd.extend(["-k", pattern])
        elif runner == "unittest":
            _apply_unittest_name_filter(cmd, pattern)
        elif runner == "go":
            cmd.extend(["-run", pattern])
        elif runner == "cargo":
            cmd.append(pattern)

    proc = subprocess.run(cmd, cwd=str(root), text=True, capture_output=True, timeout=timeout_s)
    combined = (proc.stdout + "\n" + proc.stderr).strip()
    selected = _selected_count(runner, combined)
    no_tests_selected = bool(pattern) and selected == 0
    return {
        "ok": proc.returncode == 0 and not no_tests_selected,
        "runner": runner,
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "output": combined[-4000:],
        "root": str(root),
        "selected": selected,
        "no_tests_selected": no_tests_selected,
    }
