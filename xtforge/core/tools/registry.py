"""External tool registry: resolve binaries, capture versions, suggest installs.

Missing tools are data, never errors: every consumer can degrade with a hint.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capabilities: tuple[str, ...]
    install: str
    version_args: tuple[str, ...] = ("--version",)


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("readelf", ("elf", "sections", "symbols"), "pkg install binutils"),
    ToolSpec("objdump", ("elf", "disasm"), "pkg install binutils"),
    ToolSpec("nm", ("symbols",), "pkg install binutils"),
    ToolSpec("strings", ("strings",), "pkg install binutils"),
    ToolSpec("file", ("identify",), "pkg install file"),
    ToolSpec("unzip", ("archive",), "pkg install unzip", ("-v",)),
    ToolSpec("clang", ("compile",), "pkg install clang"),
    ToolSpec("gcc", ("compile",), "pkg install clang"),
    ToolSpec("r2", ("re", "disasm"), "pkg install radare2", ("-v",)),
    ToolSpec("apktool", ("apk",), "pkg install apktool"),
    ToolSpec("jadx", ("apk", "dex"), "download a jadx release (java required)"),
    ToolSpec("frida", ("dynamic",), "pip install frida-tools"),
    ToolSpec("gh", ("github",), "pkg install gh"),
    ToolSpec("adb", ("android",), "pkg install android-tools", ("version",)),
    ToolSpec("java", ("java",), "pkg install openjdk-17", ("-version",)),
    ToolSpec("python3", ("python",), "pkg install python"),
)


def search_path(path: str | None = None) -> str:
    """PATH plus well-known Termux/Android directories, de-duplicated."""
    parts: list[str] = []
    raw = path if path is not None else os.environ.get("PATH", "")
    parts.extend(p for p in raw.split(os.pathsep) if p)
    prefix = os.environ.get("PREFIX") or "/data/data/com.termux/files/usr"
    for extra in (f"{prefix}/bin", "/system/bin", "/system/xbin",
                  "/usr/local/bin", "/usr/bin"):
        if extra not in parts:
            parts.append(extra)
    return os.pathsep.join(parts)


def find(spec: ToolSpec, path: str | None = None) -> str | None:
    return shutil.which(spec.name, path=search_path(path))


def _version(binary: str, args: tuple[str, ...]) -> str | None:
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True,
                              timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    for line in out.splitlines():
        line = line.strip()
        if line:
            return line[:120]
    return None


def probe(spec: ToolSpec, path: str | None = None) -> dict[str, Any]:
    binary = find(spec, path)
    return {
        "name": spec.name,
        "present": binary is not None,
        "path": binary,
        "version": _version(binary, spec.version_args) if binary else None,
        "capabilities": list(spec.capabilities),
        "install": spec.install,
    }


def status(path: str | None = None) -> dict[str, Any]:
    tools = [probe(spec, path) for spec in TOOLS]
    present = [t["name"] for t in tools if t["present"]]
    missing = [t["name"] for t in tools if not t["present"]]
    return {
        "ok": True,
        "tools": tools,
        "summary": {
            "total": len(tools),
            "present": len(present),
            "missing": len(missing),
            "present_names": present,
            "missing_names": missing,
        },
    }
