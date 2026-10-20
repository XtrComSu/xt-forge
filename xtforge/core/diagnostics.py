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


def _config_file(cfg: Path) -> Path | None:
    """The config OpenCode reads: `.jsonc` first, then `.json`."""
    for name in ("opencode.jsonc", "opencode.json"):
        candidate = cfg / name
        if candidate.is_file():
            return candidate
    return None


def _load_config(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _plugin_state(cfg: Path) -> tuple[bool | None, bool]:
    """(is the xt-native plugin registered, is it installed on disk)."""
    installed = (cfg / "plugins" / "xt-native" / "index.ts").is_file()
    config = _config_file(cfg)
    if config is None:
        return None, installed
    data = _load_config(config)
    for key in ("plugins", "plugin"):
        entries = data.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            package = entry.get("package") if isinstance(entry, dict) else entry
            if isinstance(package, str) and "xt-native" in package:
                return True, installed
    return False, installed


def _plugin_detail() -> dict[str, object]:
    """What the plugin manager knows: installed, registered, current."""
    try:
        from .plugin import manager
        res = manager.status()
    except Exception as exc:                      # pragma: no cover - defensive
        return {"error": str(exc)}
    return {
        "installed": bool(res.get("installed")),
        "registered": bool(res.get("registered")),
        "current": bool(res.get("current")),
        "version": res.get("version"),
        "drift": res.get("drift", {}),
    }


def _integration(home: Path | None = None) -> dict[str, object]:
    home = home or Path(os.environ.get("HOME", str(Path.home())))
    cfg = home / ".config" / "opencode"
    site = next(iter(PREFIX.glob("lib/python3*/site-packages")), None)
    pth = next(iter(site.glob("xtforge*.pth")), None) if site else None

    def _count_commands() -> int:
        cdir = cfg / "commands"
        return len(list(cdir.glob("*.md"))) if cdir.is_dir() else 0

    plugin, plugin_installed = _plugin_state(cfg)
    launcher = home / "bin" / "xtforge"
    return {
        "pythonpath_entry": str(pth) if pth else None,
        "launcher": str(launcher) if launcher.exists() else None,
        "opencode_commands": _count_commands(),
        "opencode_plugin_registered": plugin,
        "opencode_plugin_installed": plugin_installed,
        "opencode_plugin": _plugin_detail(),
        "opencode_mcp_config": _config_file(cfg) is not None,
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
