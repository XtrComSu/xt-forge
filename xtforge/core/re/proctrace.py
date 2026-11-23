"""Inspect a live process: its memory map, loaded modules, and what it exec'd.

`re ptrace` used to be a pure alias for the Playwright trace reader, which meant a verb named
after the system call could not inspect a process at all. That is worse than a missing feature:
`re ptrace <pid>` returned "playwright trace: not a regular file" while looking like the
capability existed. This module gives the verb the meaning its name promises.

What is actually possible here, measured rather than assumed:

  * `/proc/<pid>/maps`, `/proc/<pid>/smaps`, `/proc/<pid>/cmdline`, `/proc/<pid>/exe` and
    `/proc/<pid>/fd` are readable for processes this user owns. That yields the mapped regions,
    the on-disk module set, the argv, and the open files — enough for the questions that
    matter ("which libraries did it load", "did it dlopen something from /tmp").
  * `ptrace(ATTACH)` is permitted for descendants (`/proc/sys/kernel/yama/ptrace_scope` is 1),
    and refused for unrelated processes (EPERM). So the module reports the attach *capability*
    honestly instead of claiming an attach that did not happen.

Deliberately not attempted: reading live memory. It requires a successful attach, which for an
arbitrary pid will fail on this host, and a feature that only works on your own children is
still useful — but only if it says so.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any

PROC = Path("/proc")
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SEIZE = 0x4206

# Paths that suggest something loaded from outside the normal system/library locations.
_SUSPICIOUS_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/", "/home/")
# Permissions in the maps line that mean the region is executable.
_EXEC_BITS = "x"


def _read(path: Path, limit: int = 1 << 20) -> str:
    try:
        with path.open("r", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _can_attach(pid: int) -> tuple[bool, str]:
    """Try a real `ptrace(SEIZE)` and report what the kernel said.

    SEIZE rather than ATTACH because it does not stop the target, so a probe leaves the process
    running. The trace is released immediately afterwards.
    """
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError as exc:
        return False, f"libc unavailable: {exc}"
    result = libc.ptrace(PTRACE_SEIZE, pid, None, None)
    if result == 0:
        libc.ptrace(PTRACE_DETACH, pid, None, None)
        return True, "seize succeeded"
    errno = ctypes.get_errno()
    return False, f"{os.strerror(errno)} (errno {errno})"


def _maps(pid: int) -> list[dict[str, Any]]:
    """Parse /proc/<pid>/maps into regions, with the backing file resolved."""
    regions: list[dict[str, Any]] = []
    for line in _read(PROC / str(pid) / "maps").splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        address_range, perms, offset, dev, inode = parts[:5]
        path = parts[5].strip() if len(parts) > 5 else ""
        start, _, end = address_range.partition("-")
        try:
            start_int, end_int = int(start, 16), int(end, 16)
        except ValueError:
            continue
        regions.append({
            "start": start_int,
            "end": end_int,
            "size": end_int - start_int,
            "perms": perms,
            "offset": int(offset, 16) if offset else 0,
            "path": path,
            "executable": _EXEC_BITS in perms,
        })
    return regions


def inspect_process(pid: int, *, limit: int = 400) -> dict[str, Any]:
    """Describe a live process: identity, modules, mappings and attach capability."""
    if not isinstance(pid, int) or pid <= 0:
        return {"ok": False, "error": f"process id must be a positive integer, got {pid!r}"}
    root = PROC / str(pid)
    if not root.is_dir():
        return {"ok": False, "pid": pid,
                "error": f"no such process: {root} does not exist (wrong pid, or it exited)"}

    cmdline = _read(root / "cmdline").split("\x00")
    argv = [part for part in cmdline if part]
    try:
        exe = os.readlink(root / "exe")
    except OSError:
        exe = ""
    try:
        cwd = os.readlink(root / "cwd")
    except OSError:
        cwd = ""
    status = {}
    for line in _read(root / "status").splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            status[key.strip()] = value.strip()

    regions = _maps(pid)
    modules: dict[str, int] = {}
    for region in regions:
        if region["path"].startswith("/") and region["executable"]:
            modules[region["path"]] = modules.get(region["path"], 0) + region["size"]
    suspicious = sorted(path for path in modules
                        if path.startswith(_SUSPICIOUS_PREFIXES))
    anonymous_exec = sum(region["size"] for region in regions
                         if region["executable"] and not region["path"])
    writable_executable = [region for region in regions
                           if "w" in region["perms"] and "x" in region["perms"]]

    fds: list[dict[str, str]] = []
    try:
        for entry in sorted((root / "fd").iterdir(), key=lambda item: item.name)[:limit]:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            fds.append({"fd": entry.name, "target": target})
    except OSError:
        pass

    attachable, attach_reason = _can_attach(pid)
    return {
        "ok": True,
        "pid": pid,
        "exe": exe,
        "argv": argv[:64],
        "cwd": cwd,
        "state": status.get("State", ""),
        "ppid": status.get("PPid", ""),
        "uid": status.get("Uid", ""),
        "threads": status.get("Threads", ""),
        "rss_kb": status.get("VmRSS", ""),
        "region_count": len(regions),
        "anonymous_exec_bytes": anonymous_exec,
        "writable_executable": [
            {"start": hex(region["start"]), "size": region["size"], "path": region["path"]}
            for region in writable_executable[:20]
        ],
        "module_count": len(modules),
        "modules": [{"path": path, "exec_bytes": size}
                    for path, size in sorted(modules.items())[:limit]],
        "suspicious_modules": suspicious[:20],
        "fd_count": len(fds),
        "fds": fds[:limit],
        "attachable": attachable,
        "attach_reason": attach_reason,
        "note": ("Read from /proc, which needs no privileges for processes this user owns. "
                 "`attachable` records whether ptrace(SEIZE) actually succeeded; on this host "
                 "that requires the target to be a descendant "
                 "(/proc/sys/kernel/yama/ptrace_scope = 1), so live memory reads are reported "
                 "as unavailable rather than silently returning nothing."),
    }


def list_processes(*, limit: int = 60, name: str | None = None) -> dict[str, Any]:
    """Enumerate processes, optionally filtered by a substring of the executable or argv."""
    needle = (name or "").lower()
    rows: list[dict[str, Any]] = []
    try:
        entries = sorted((entry for entry in PROC.iterdir() if entry.name.isdigit()),
                         key=lambda entry: int(entry.name))
    except OSError as exc:
        return {"ok": False, "error": f"cannot enumerate /proc: {exc}"}
    for entry in entries:
        pid = int(entry.name)
        argv = [part for part in _read(entry / "cmdline").split("\x00") if part]
        try:
            exe = os.readlink(entry / "exe")
        except OSError:
            exe = ""
        label = " ".join(argv) or exe
        # Filter on the FULL label, then truncate for display. Truncating first meant a process
        # whose matching text sat past 200 characters was silently excluded while a longer
        # unrelated cmdline that happened to contain the needle earlier was included — the
        # filter lied in both directions. Found because this suite's own launcher kept matching
        # "sleep" through a neighbour's command line.
        if needle and needle not in label.lower() and needle not in exe.lower():
            continue
        rows.append({"pid": pid, "exe": exe, "cmdline": label[:200]})
        if len(rows) >= limit:
            break
    return {"ok": True, "count": len(rows), "processes": rows,
            "filter": name or None}


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Verb entry point: a pid inspects that process, no argument lists them."""
    text = str(path).strip()
    if not text:
        return list_processes()
    try:
        return inspect_process(int(text))
    except ValueError:
        return {"ok": False, "error": f"not a process id: {text!r}",
                "hint": "use `xtforge re ptrace <pid>` or `xtforge re ptrace` to list"}
