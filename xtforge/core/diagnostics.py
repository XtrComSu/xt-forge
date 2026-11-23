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

# Where `xtforge skills install` puts the XTF-* workflow skills.
SKILL_TARGETS = (".dsh/skills", ".agents/skills", ".claude/skills",
                 ".config/opencode/skills")
MCP_NOT_REGISTERED = "xt-forge MCP server is not registered"
MCP_REGISTERED_DISABLED = "xt-forge MCP server is registered but disabled"


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


def _repair_item(name: str, ok: bool, value: str, detail: str,
                 repair: str) -> dict[str, object]:
    """One doctor report line; repair is empty only for a passing check."""
    return {"name": name, "ok": bool(ok), "value": str(value),
            "detail": str(detail), "repair": "" if ok else str(repair)}


def _launcher_check() -> tuple[bool, str, str, str]:
    names = ("xtforge", "xt-forge", "xtf")
    found = []
    for name in names:
        path = which(name)
        if path:
            try:
                found.append(f"{name}={Path(path).resolve()}")
            except (OSError, RuntimeError):
                found.append(f"{name}={path}")
    ok = bool(found)
    detail = f"PATH lookup for {', '.join(names)}, with {BIN} fallback"
    repair = ("Install xt-forge (`npx -y xt-forge init` or `pip install xt-forge`) "
              "or add its bin directory to PATH")
    return ok, ", ".join(found) if ok else "none", detail, repair


def _runtime_check() -> tuple[bool, str, str, str]:
    v = sys.version_info
    value = f"{v.major}.{v.minor}.{v.micro}"
    ok = (v.major, v.minor) >= (3, 11)
    detail = f"python3 at {sys.executable}; requires >= 3.11"
    repair = "Install Python 3.11+ and put python3 on PATH"
    return ok, value, detail, repair


def _native_hub_check() -> tuple[bool, str, str, str]:
    from .route import caps as capmod
    path = capmod.go_hub_path()
    ok = path.is_file() and os.access(path, os.X_OK)
    value = str(path)
    detail = ("xtforge-hub Go binary is executable" if ok else
              "xtforge-hub Go binary is missing or not executable; "
              "native analysis degrades to the Python backend")
    repair = (f"Build/install xtforge-hub at {path} with "
              "`cd native/xtforge-go && go build -o xtforge-hub ./cmd/xtforge-hub` "
              "to restore native analysis")
    return ok, value, detail, repair


def _skill_check() -> tuple[bool, str, str, str]:
    home = Path(os.environ.get("HOME", str(Path.home())))
    dirs = [xt_home() / "skills"] + [home / rel for rel in SKILL_TARGETS]
    found: set[str] = set()
    for d in dirs:
        try:
            found.update(p.name for p in d.glob("XTF-*")
                         if (p / "SKILL.md").is_file())
        except OSError:
            continue
    ok = bool(found)
    where = ", ".join(str(d) for d in dirs)
    return (ok, f"{len(found)} XTF-* skills", f"looked in: {where}",
            f"Run `xtforge skills install` to copy XTF-* skills into {where}")


def _mcp_check() -> tuple[bool, str, str, str]:
    home = Path(os.environ.get("HOME", str(Path.home())))
    cfg = home / ".config" / "opencode"
    config = _config_file(cfg)
    config_path = str(config) if config else str(cfg / "opencode.json")
    server: object = None
    if config is not None:
        mcp = _load_config(config).get("mcp")
        if isinstance(mcp, dict):
            servers = mcp.get("servers")
            server = (servers.get("xt-forge") if isinstance(servers, dict)
                      else mcp.get("xt-forge"))  # deprecated flat shape
    registered = isinstance(server, dict) and bool(server)
    disabled = registered and (server.get("disabled") is True or
                               server.get("enabled") is False)
    if not registered:
        return (False, "not registered", f"{MCP_NOT_REGISTERED} in {config_path}",
                f"Run `xtforge sync` to register the xt-forge MCP server in {config_path}")
    if disabled:
        return (False, "registered but disabled",
                f"{MCP_REGISTERED_DISABLED} in {config_path}",
                f"Set disabled=false (or enabled=true) for xt-forge in {config_path}, "
                "or run `xtforge sync`")
    return True, "registered", f"xt-forge MCP server is registered in {config_path}", ""


def _repair_checks() -> list[dict[str, object]]:
    """The five repair-oriented doctor lines; a failing probe is a report line."""
    probes = (("launcher", _launcher_check), ("runtime", _runtime_check),
              ("native hub", _native_hub_check), ("skills", _skill_check),
              ("mcp", _mcp_check))
    items = []
    for name, probe in probes:
        try:
            ok, value, detail, repair = probe()
        except Exception as exc:                      # pragma: no cover - defensive
            ok, value, detail, repair = (False, "unavailable",
                                         f"doctor probe failed: {exc}",
                                         "Check filesystem/PATH access and rerun doctor")
        items.append(_repair_item(name, ok, value, detail, repair))
    return items


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
    report = _repair_checks()
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
        # Added, not substituted: older doctor consumers keep their fields.
        "checks": report,
        "repairs": report,
    }
