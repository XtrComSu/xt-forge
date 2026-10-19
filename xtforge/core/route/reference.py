"""Pure-Python reference implementations for every native tool (F6).

These are the fallback used when the C++ binaries are unavailable, and they
are the oracle for the native-vs-python parity tests.
"""
from __future__ import annotations

import fnmatch
import os
import re
import time
from pathlib import Path
from typing import Any

DEFAULT_IGNORE = {"node_modules", ".git", "__pycache__", ".cache",
                  "dist", "build", ".venv"}


def _skip(name: str, extra: set[str] | None = None) -> bool:
    if name in DEFAULT_IGNORE:
        return True
    return bool(extra and name in extra)


def walk_py(root: str | Path, max_depth: int = 64, ignore: set[str] | None = None,
            limit: int | None = None) -> list[dict[str, Any]]:
    """Recursive listing mirroring xtscan --tree semantics."""
    out: list[dict[str, Any]] = []
    root = Path(root)
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            if _skip(e.name, ignore):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            is_dir = e.is_dir(follow_symlinks=False)
            out.append({"path": str(e.path), "dir": is_dir,
                        "size": 0 if is_dir else st.st_size,
                        "mtime": int(st.st_mtime)})
            if is_dir:
                stack.append((Path(e.path), depth + 1))
            if limit and len(out) >= limit:
                return out
    return out


def find_py(root: str | Path, name: str | None = None, regex: str | None = None,
            type_: str | None = None, min_size: int = -1, limit: int = 100,
            ignore: set[str] | None = None) -> list[dict[str, Any]]:
    rx = re.compile(regex) if regex else None
    out: list[dict[str, Any]] = []
    for e in walk_py(root, ignore=ignore):
        if name and not fnmatch.fnmatch(e["path"], name):
            continue
        if rx and not rx.search(e["path"]):
            continue
        if type_ == "d" and not e["dir"]:
            continue
        if type_ == "f" and e["dir"]:
            continue
        if min_size >= 0 and e["size"] < min_size:
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def grep_py(root: str | Path, pattern: str, glob: str | None = None,
            context: int = 1, limit: int = 100,
            ignore: set[str] | None = None) -> list[dict[str, Any]]:
    rx = re.compile(pattern)
    out: list[dict[str, Any]] = []
    for e in walk_py(root, ignore=ignore):
        if e["dir"]:
            continue
        if glob and not fnmatch.fnmatch(e["path"], glob):
            continue
        try:
            data = Path(e["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\0" in data[:4096]:
            continue
        lines = data.split("\n")
        for i, line in enumerate(lines):
            if rx.search(line):
                rec = {"path": e["path"], "line": i + 1, "text": line}
                if context > 0:
                    if i - context >= 0:
                        rec["before"] = "\n".join(
                            f"{j+1}:{lines[j]}" for j in range(max(0, i - context), i))
                    if i + context < len(lines):
                        rec["after"] = "\n".join(
                            f"{j+1}:{lines[j]}" for j in
                            range(i + 1, min(len(lines), i + 1 + context)))
                out.append(rec)
                if len(out) >= limit:
                    return out
    return out


def du_py(path: str | Path, top: int = 15, ignore: set[str] | None = None) -> list[dict[str, Any]]:
    p = Path(path)
    items: list[dict[str, Any]] = []
    if p.is_dir():
        for e in sorted(os.scandir(p), key=lambda e: e.name):
            if _skip(e.name, ignore):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            size = dir_size(e.path, ignore) if e.is_dir(follow_symlinks=False) else st.st_size
            items.append({"path": e.path, "size": size})
    else:
        items.append({"path": str(p), "size": p.stat().st_size})
    items.sort(key=lambda x: -x["size"])
    return items[:top]


def dir_size(path: str | Path, ignore: set[str] | None = None) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not _skip(d, ignore)]
        for f in files:
            try:
                total += os.stat(os.path.join(root, f), follow_symlinks=False).st_size
            except OSError:
                pass
    return total


def recent_py(root: str | Path, minutes: int = 60, limit: int = 50,
              ignore: set[str] | None = None) -> list[dict[str, Any]]:
    cutoff = time.time() - minutes * 60
    out = [e for e in walk_py(root, ignore=ignore)
           if not e["dir"] and e["mtime"] >= cutoff]
    out.sort(key=lambda x: -x["mtime"])
    return out[:limit]


def _mix(h: int, k: int) -> int:
    M = (1 << 64) - 1
    k = (k * 0xff51afd7ed558ccd) & M
    k ^= k >> 33
    k = (k * 0xc4ceb9fe1a85ec53) & M
    k ^= k >> 29
    h ^= k
    return (h * 0x100000001b3 + 0x165667b19e3779f9) & M


def digest_file_py(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_bytes()
    h = 0xcbf29ce484222325 ^ len(data)
    i = 0
    while i + 8 <= len(data):
        h = _mix(h, int.from_bytes(data[i:i + 8], "little"))
        i += 8
    tail = 0
    for b in data[i:]:
        tail = ((tail << 8) | b) & ((1 << 64) - 1)
    h = _mix(h, tail)
    return {"path": str(path), "digest": f"{h:016x}", "bytes": len(data),
            "lines": len(split_lines(data.decode("utf-8", "replace")))}


def split_lines(data: str) -> list[str]:
    """POSIX line semantics matching C++ std::getline: a trailing newline
    terminates the last line rather than starting an empty one."""
    if not data:
        return []
    lines = data.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def outline_py(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = split_lines(data)
    blank = comment = code = 0
    for l in lines:
        t = l.strip()
        if not t:
            blank += 1
        elif t.startswith("#") or t.startswith("//"):
            comment += 1
        else:
            code += 1
    return {"path": str(path), "total_lines": len(lines), "blank": blank,
            "comment": comment, "code": code}


def tree_py(root: str | Path, depth: int = 2, max_items: int = 200) -> dict[str, Any]:
    entries = walk_py(root, max_depth=depth, limit=max_items)
    return {"root": str(root), "entries": entries, "shown": len(entries)}