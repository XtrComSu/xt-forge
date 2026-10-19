"""Phone tools (F6): battery, storage, memory, procs, net, termux-api wrappers.

Every field is optional; a missing source degrades that field only. Termux:API
absence yields {"ok":false,"err":"termux-api-missing"} rather than a crash.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .tools import envelope

API_MISSING = "termux-api-missing"
CMD_TIMEOUT = 8

_PREFIX_BIN = f"{os.environ.get('PREFIX', '/data/data/com.termux/files/usr')}/bin"
_path_parts = [p for p in os.environ.get("PATH", "").split(os.pathsep)
               if p and p != _PREFIX_BIN]
os.environ["PATH"] = os.pathsep.join([_PREFIX_BIN, *_path_parts])


def _which(cmd: str) -> str | None:
    return shutil.which(cmd)


def _run(cmd: list[str], timeout: int = CMD_TIMEOUT) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def phone_info() -> dict[str, Any]:
    t0 = time.perf_counter()
    info: dict[str, Any] = {}
    info["battery"] = _battery()
    info["storage"] = _storage()
    info["memory"] = _meminfo()
    info["cpu_count"] = os.cpu_count()
    info["uptime_s"] = _uptime()
    info["termux_version"] = os.environ.get("TERMUX_VERSION", "unknown")
    info["loadavg"] = os.getloadavg()
    temp = _temperature()
    if temp is not None:
        info["temperature_c"] = temp
    return envelope(True, info, ms=int((time.perf_counter() - t0) * 1000))


def _battery() -> dict[str, Any] | None:
    exe = _which("termux-battery-status")
    if not exe:
        return None
    code, out, _ = _run([exe])
    if code != 0:
        return None
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return None
    return {k: d.get(k) for k in ("percentage", "status", "temperature", "health", "plugged")}


def _storage() -> list[dict[str, Any]]:
    roots = ["$HOME", "/sdcard", "/data"]
    out = []
    for r in roots:
        p = Path(os.path.expandvars(r))
        try:
            st = os.statvfs(str(p))
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        out.append({"root": r, "total": total, "free": free,
                    "used": total - free,
                    "pct_used": round(100 * (total - free) / total, 1) if total else None})
    return out


def _meminfo() -> dict[str, Any] | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                kb = int(line.split()[1])
                return {"available_kb": kb, "available_mb": round(kb / 1024, 1)}
    except (OSError, ValueError, IndexError):
        return None
    return None


def _uptime() -> float | None:
    try:
        return round(float(Path("/proc/uptime").read_text().split()[0]), 1)
    except (OSError, ValueError, IndexError):
        return None


def _temperature() -> float | None:
    try:
        for zone in sorted(Path("/sys/class/thermal").glob("thermalzone*")):
            raw = (zone / "temp").read_text().strip()
            val = int(raw) / 1000.0
            if 20 < val < 100:
                return round(val, 1)
    except (OSError, ValueError):
        return None
    return None


def phone_procs(top: int = 10, by: str = "mem") -> dict[str, Any]:
    """Parse /proc. Android hides other UIDs' processes; reported explicitly."""
    t0 = time.perf_counter()
    procs: list[dict[str, Any]] = []
    own_uid = os.getuid()
    try:
        uids = sorted(p for p in Path("/proc").iterdir() if p.name.isdigit())
    except OSError:
        return envelope(False, err="proc_not_readable")
    total_mem = (_meminfo() or {}).get("available_kb", 0) * 1024 or 1
    for p in uids:
        try:
            status = (p / "status").read_text(errors="replace")
        except OSError:
            continue
        name = _proc_field(status, "Name")
        rss = _proc_kb(status, "VmRSS")
        uid = _proc_field(status, "Uid")
        if not name:
            continue
        procs.append({"pid": int(p.name), "name": name, "rss_kb": rss,
                      "uid": uid, "own": uid.split("\t")[0] == str(own_uid)})
    key = (lambda x: -x["rss_kb"]) if by == "mem" else (lambda x: x["pid"])
    procs.sort(key=key)
    top_list = procs[:top]
    return envelope(True, {"procs": top_list, "count": len(procs),
                           "restriction": "Android shows only processes of this UID"},
                    ms=int((time.perf_counter() - t0) * 1000))


def _proc_field(status: str, key: str) -> str:
    for line in status.splitlines():
        if line.startswith(key + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def _proc_kb(status: str, key: str) -> int:
    try:
        return int(_proc_field(status, key).split()[0])
    except (ValueError, IndexError):
        return 0


def phone_net() -> dict[str, Any]:
    t0 = time.perf_counter()
    addrs: list[str] = []
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True,
                             text=True, timeout=CMD_TIMEOUT).stdout
        for line in out.splitlines():
            m = re.search(r"inet6? ([0-9a-f.:]+/\d+)", line)
            if m:
                addrs.append(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    wifi = None
    exe = _which("termux-wifi-connectioninfo")
    if exe:
        code, out, _ = _run([exe])
        if code == 0:
            try:
                wifi = json.loads(out).get("supplicant_results", {}).get("SSID")
            except json.JSONDecodeError:
                wifi = None
    return envelope(True, {"addresses": addrs, "wifi_ssid": wifi},
                    ms=int((time.perf_counter() - t0) * 1000))


# ---- termux-api gated actions ----

def _api(name: str, args: list[str] | None = None) -> dict[str, Any]:
    exe = _which(name)
    if not exe:
        return envelope(False, err=API_MISSING)
    code, out, err = _run([exe, *(args or [])])
    if code != 0:
        return envelope(False, err=(err or out or "api_failed").strip()[:200])
    if out.strip().startswith(("{", "[")):
        try:
            return envelope(True, json.loads(out))
        except json.JSONDecodeError:
            pass
    return envelope(True, {"output": out.strip()})


def phone_clip_get() -> dict[str, Any]:
    return _api("termux-clipboard-get")


def phone_clip_set(text: str) -> dict[str, Any]:
    exe = _which("termux-clipboard-set")
    if not exe:
        return envelope(False, err=API_MISSING)
    try:
        r = subprocess.run([exe], input=text, capture_output=True,
                           text=True, timeout=CMD_TIMEOUT)
        if r.returncode != 0:
            return envelope(False, err=r.stderr.strip()[:200])
    except (OSError, subprocess.SubprocessError) as exc:
        return envelope(False, err=str(exc)[:200])
    return envelope(True, {"bytes": len(text.encode())})


def phone_notify(title: str, message: str, sound: bool = False) -> dict[str, Any]:
    exe = _which("termux-notification")
    if not exe:
        return envelope(False, err=API_MISSING)
    args = [exe, "-t", title, "-c", message]
    if sound:
        args += ["-s"]
    code, out, err = _run(args)
    if code != 0:
        return envelope(False, err=(err or out).strip()[:200])
    return envelope(True, {"notified": True})


def phone_wakelock(on: bool = True) -> dict[str, Any]:
    exe = _which("termux-wake-lock" if on else "termux-wake-unlock")
    if not exe:
        return envelope(False, err=API_MISSING)
    code, out, err = _run([exe])
    if code != 0:
        return envelope(False, err=(err or out).strip()[:200])
    return envelope(True, {"wakelock": "on" if on else "off"})


ADB_ALLOW = [
    ("getprop", re.compile(r"^getprop(\s+\S+)?$")),
    ("dumpsys battery", re.compile(r"^dumpsys\s+battery$")),
    ("pm list packages", re.compile(r"^pm\s+list\s+packages(\s+-f)?$")),
    ("wm size", re.compile(r"^wm\s+size$")),
    ("df", re.compile(r"^df\b.*$")),
]


def phone_adb(cmd: str) -> dict[str, Any]:
    """Read-only ADB subset; anything else is rejected."""
    exe = _which("adb")
    if not exe:
        return envelope(False, err="adb-missing")
    from . import guard
    reason = guard.check_command(cmd)
    if reason:
        return envelope(False, err=f"denied: {reason}")
    allowed = any(rx.match(cmd.strip()) for _name, rx in ADB_ALLOW)
    if not allowed:
        return envelope(False, err="adb command not in read-only allowlist")
    code, out, err = _run([exe, "shell", *cmd.split()], timeout=CMD_TIMEOUT + 5)
    if code != 0:
        return envelope(False, err=(err or out).strip()[:200])
    return envelope(True, {"output": out.strip()[:2000]})