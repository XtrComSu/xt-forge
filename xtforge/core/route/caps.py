"""Capability probe: pick native binary when present, else the Python reference.

Result cached in $XT_HOME/cache/caps.json; `force_python` env overrides.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from ...version import cache_dir, project_root

NATIVE_DIR = project_root() / "native" / "build"
CAPS_FILE = "caps.json"
PROBE_TIMEOUT = 10


def native_path(name: str) -> Path:
    return NATIVE_DIR / name


def binary_works(name: str) -> bool:
    exe = native_path(name)
    if not exe.exists() or not os.access(exe, os.X_OK):
        return False
    try:
        r = subprocess.run([str(exe), "--help"], capture_output=True, timeout=PROBE_TIMEOUT)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def probe(force_python: bool | None = None, use_cache: bool = True) -> dict[str, Any]:
    if force_python is None:
        force_python = os.environ.get("XT_FORCE_PYTHON") == "1"
    try:
        from ..calibrate import current_boot_id
        boot_id = current_boot_id()
    except Exception:
        boot_id = "unknown-boot"
    if use_cache:
        cached = read_caps()
        if cached and cached.get("stamp"):
            age = time.time() - float(cached["stamp"])
            same_boot = cached.get("boot_id") in (None, boot_id)
            if age < 3600 and cached.get("force_python") == force_python and same_boot:
                return cached
            # else: reboot or stale -> fall through and reprobe
    caps: dict[str, Any] = {"ts": time.time(), "force_python": force_python,
                            "native_dir": str(NATIVE_DIR), "tools": {},
                            "boot_id": boot_id}
    for tool in ("xtscan", "xtdigest", "xtsqueeze"):
        caps["tools"][tool] = "python" if force_python or not binary_works(tool) else "native"
    caps["stamp"] = time.time()
    write_caps(caps)
    return caps


def caps_path() -> Path:
    return cache_dir() / CAPS_FILE


def read_caps() -> dict[str, Any] | None:
    p = caps_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def write_caps(caps: dict[str, Any]) -> None:
    from ...atomicio import atomic_write_json
    atomic_write_json(caps_path(), caps)


def backend(tool: str, caps: dict[str, Any] | None = None) -> str:
    caps = caps or probe()
    return caps.get("tools", {}).get(tool, "python")


def run_native(name: str, args: list[str], timeout: int = 60) -> dict[str, Any]:
    """Run a native tool and parse its JSON stdout."""
    exe = native_path(name)
    t0 = time.perf_counter()
    try:
        r = subprocess.run([str(exe), *args], capture_output=True,
                           timeout=timeout, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "err": f"native exec failed: {exc}", "ms": 0}
    ms = int((time.perf_counter() - t0) * 1000)
    if r.returncode not in (0, 3):
        return {"ok": False, "err": (r.stderr or r.stdout or "").strip()[:300],
                "ms": ms, "exit": r.returncode}
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        return {"ok": False, "err": f"native json parse failed: {exc}", "ms": ms}
    if isinstance(data, dict) and data.get("error") == "not_found":
        return {"ok": False, "err": "not_found", "ms": ms}
    return {"ok": True, "data": data, "ms": ms}


def pick(tool: str, native_args: list[str], py_fn: Callable[[], Any]) -> dict[str, Any]:
    """Native when available and healthy, else the Python reference."""
    caps = probe()
    if caps.get("tools", {}).get(tool) == "native":
        res = run_native(tool, native_args)
        if res.get("ok"):
            res["backend"] = "native"
            return res
        # Native failed unexpectedly: degrade to Python, record the reason.
        degraded = probe()
        degraded["tools"][tool] = "python"
        write_caps(degraded)
        return {"ok": True, "data": py_fn(), "ms": res.get("ms", 0),
                "backend": "python", "native_err": res.get("err")}
    t0 = time.perf_counter()
    return {"ok": True, "data": py_fn(),
            "ms": int((time.perf_counter() - t0) * 1000), "backend": "python"}