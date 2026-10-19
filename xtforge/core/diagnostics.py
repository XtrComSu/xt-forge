"""Environment + integration probe shared by `xtforge doctor` and MCP `xt_doctor`.

`shutil.which` alone lies when a harness runs with a stripped PATH (opencode
launches through `su -c`, so it only inherits /system/bin). Probe the Termux
prefix explicitly and report how every xt-forge surface is wired.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..version import xt_home

PREFIX = Path(os.environ.get("XT_PREFIX", "/data/data/com.termux/files/usr"))
BIN = PREFIX / "bin"


def which(name: str) -> str | None:
    """PATH lookup with an explicit Termux-prefix fallback."""
    found = shutil.which(name)
    if found:
        return found
    candidate = BIN / name
    return str(candidate) if candidate.exists() else None


def _run_version(name: str, args: list[str]) -> str:
    path = which(name)
    if not path:
        return "absent"
    try:
        return subprocess.run([path, *args], capture_output=True, text=True,
                              timeout=5).stdout.strip() or "error"
    except Exception:
        return "error"


def opencode_version() -> str:
    return _run_version("opencode", ["--version"])


def _selected_theme(cfg: Path) -> str | None:
    """Theme name OpenCode will use, from tui.json (or None)."""
    tui = cfg / "tui.json"
    if not tui.is_file():
        return None
    try:
        name = json.loads(tui.read_text()).get("theme")
    except (ValueError, OSError):
        return None
    return name if isinstance(name, str) else None


def _integration(home: Path | None = None) -> dict[str, object]:
    home = home or Path(os.environ.get("HOME", str(Path.home())))
    cfg = home / ".config" / "opencode"
    site = next(iter(PREFIX.glob("lib/python3*/site-packages")), None)
    pth = next(iter(site.glob("xtforge*.pth")), None) if site else None

    def _count_commands() -> int:
        cdir = cfg / "commands"
        return len(list(cdir.glob("*.md"))) if cdir.is_dir() else 0

    plugin = None
    config = cfg / "opencode.jsonc"
    if config.is_file():
        try:
            text = config.read_text(encoding="utf-8")
            start, end = text.find("{"), text.rfind("}")
            data = json.loads(text[start:end + 1]) if start >= 0 and end > start else {}
            registered = data.get("plugin") or []
            plugin = bool(registered) if isinstance(registered, list) else None
        except (ValueError, OSError):
            plugin = None
    launcher = home / "bin" / "xtforge"
    return {
        "pythonpath_entry": str(pth) if pth else None,
        "launcher": str(launcher) if launcher.exists() else None,
        "opencode_commands": _count_commands(),
        "opencode_plugin_registered": plugin,
        "opencode_mcp_config": (cfg / "opencode.jsonc").is_file(),
        "theme": bool(list((cfg / "themes").glob("*.json"))),
        "theme_selected": _selected_theme(cfg),
        "agents_md": (home / "AGENTS.md").is_file(),
        "xt_home": str(xt_home()),
    }


def checks(home: Path | None = None) -> dict[str, object]:
    """Full doctor payload."""
    from .route import caps as capmod
    try:
        from . import calibrate as calmod
        calibration = calmod.status()
    except Exception as exc:
        calibration = {"error": str(exc)}
    boot_hook = None
    try:
        h = home or Path(os.environ.get("HOME", str(Path.home())))
        cand = h / ".termux" / "boot" / "xt-forge-calibrate.sh"
        boot_hook = str(cand) if cand.exists() else None
    except Exception:
        pass
    return {
        "python": sys.version.split()[0],
        "native": capmod.probe(),
        "clang": which("clang++") or "absent",
        "opencode": opencode_version() if which("opencode") else "absent",
        "termux_api": bool(which("termux-battery-status")),
        "bash": which("bash") or "absent",
        "integration": _integration(home),
        "calibration": calibration,
        "boot_hook": boot_hook,
    }
