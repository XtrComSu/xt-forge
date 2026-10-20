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