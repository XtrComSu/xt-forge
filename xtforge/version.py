"""Filesystem layout + version resolution for xt-forge.

VERSION file at project root is the single source of truth:
    name=xt-forge
    version=0.3.0
    codename=Damascus
"""
from __future__ import annotations

import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def project_root() -> Path:
    return _ROOT


def _installed_metadata() -> dict[str, str]:
    """Version from the installed distribution's metadata, if present.

    A wheel does not carry the repo's `VERSION` file, so an installed copy must
    read its own metadata or it reports 0.0.0 - which is what happened on the
    first clean-install test.
    """
    try:
        from importlib.metadata import version as _v, metadata as _m
        data = {"version": _v("xt-forge")}
        try:
            data["name"] = _m("xt-forge").get("Name", "xt-forge").lower()
        except Exception:  # noqa: BLE001
            data["name"] = "xt-forge"
        return data
    except Exception:  # noqa: BLE001
        return {}


def _read_version_file() -> dict[str, str]:
    vf = _ROOT / "VERSION"
    data: dict[str, str] = {}
    if vf.exists():
        for line in vf.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    if not data.get("version"):
        # Running from an installed package (no repo root): fall back to the
        # distribution metadata so `xtforge version` is never a lie.
        data.update({k: v for k, v in _installed_metadata().items() if v})
    return data


def app_name() -> str:
    return _read_version_file().get("name", "xt-forge")


def version() -> str:
    return _read_version_file().get("version", "0.0.0")


def codename() -> str:
    return _read_version_file().get("codename", "unknown")


def version_str() -> str:
    return f"{version()}-{codename()}"


def xt_home() -> Path:
    env = os.environ.get("XT_HOME")
    base = Path(env) if env else Path.home() / ".xt-forge"
    base.mkdir(parents=True, exist_ok=True)
    return base


def db_path() -> Path:
    return xt_home() / "mem.db"


def taste_db_path() -> Path:
    """Taste state lives beside memory but is a separate store: taste is
    preference policy, not knowledge, and must be exportable on its own."""
    return xt_home() / "taste.db"


def flash_dir() -> Path:
    d = xt_home() / "flash"
    d.mkdir(parents=True, exist_ok=True)
    return d


def runs_dir() -> Path:
    d = xt_home() / "runs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_dir() -> Path:
    d = xt_home() / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_dir(run_id: str) -> Path:
    d = runs_dir() / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def artifacts_dir(run_id: str) -> Path:
    d = run_dir(run_id) / "artifacts"
    d.mkdir(parents=True, exist_ok=True)
    return d