"""Bounded navigation shortcuts for common agent inspection tasks."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import guard, reference as ref, tools

ERROR_LINE = re.compile(r"\b(error|failed|failure|exception|traceback|fatal|assert)\b", re.I)
PRIORITY = ("README", "pyproject", "package.json", "tsconfig", "PROGRESS", "VERSION")


def _tokens(text: str) -> int:
    return (len(text) + 3) // 4


def _payload_tokens(data: dict[str, Any]) -> int:
    estimate = 0
    for _ in range(3):
        data["estimated_tokens"] = estimate
        estimate = _tokens(json.dumps(data, ensure_ascii=False))
    data["estimated_tokens"] = estimate
    return estimate


def _read(path: Path, limit: int) -> str:
    if guard.is_denied_name(str(path)):
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except (OSError, UnicodeError):
        return ""


def _project_files(base: Path) -> list[Path]:
    entries = ref.walk_py(base, max_depth=4, limit=1000)
    files = [Path(e["path"]) for e in entries
             if not e["dir"] and not guard.is_denied_name(e["path"])]
    return sorted(files, key=lambda p: (
        not any(p.name.lower().startswith(x.lower()) for x in PRIORITY),
        len(p.parts), str(p)))


def _directory_lines(base: Path, files: list[Path], budget: int) -> list[str]:
    lines = [f"ROOT {base}"]
    dirs = sorted({str(p.parent.relative_to(base)) for p in files})
    for directory in dirs[:80]:
        candidate = f"DIR {directory or '.'}"
        if _tokens("\n".join(lines + [candidate])) > budget:
            break
        lines.append(candidate)
    return lines


def _context_excerpts(base: Path, files: list[Path], lines: list[str],
                      budget: int, cap: int) -> list[str]:
    excerpts = []
    used = _tokens("\n".join(lines))
    for path in files:
        if len(excerpts) >= cap or used >= budget:
            break
        try:
            canon = guard.read_guard(path)
        except guard.Denied:
            continue
        text = _read(canon, min(6000, (budget - used) * 4))
        if not text or "\0" in text[:2000]:
            continue
        excerpt = f"FILE {canon.relative_to(base)}\n{text.strip()}"
        excerpt = excerpt[:max(0, (budget - used) * 4)]
        if not excerpt:
            break
        excerpts.append(excerpt)
        used += _tokens(excerpt)
    return excerpts


def route_context(root: str, token_budget: int = 1200,
                  file_limit: int = 12) -> dict[str, Any]:
    """Build a compact project map from names and bounded key-file excerpts."""
    try:
        base = guard.read_guard(root)
    except guard.Denied as exc:
        return tools.envelope(False, err=f"{exc.code}: {exc.reason}")
    if not base.is_dir():
        return tools.envelope(False, err="not_a_directory")
    budget = max(32, min(int(token_budget), 4000))
    files = _project_files(base)
    lines = _directory_lines(base, files, budget)
    cap = max(1, min(int(file_limit), 40))
    excerpts = _context_excerpts(base, files, lines, budget, cap)
    output = "\n".join(lines + excerpts)
    while _tokens(output) > budget and excerpts:
        excerpts.pop()
        output = "\n".join(lines + excerpts)
    if _tokens(output) > budget:
        output = ""
    data = {"root": str(base), "files": len(files), "context": output,
            "estimated_tokens": 0, "token_budget": budget}
    estimate = _payload_tokens(data)
    while estimate > budget and excerpts:
        excerpts.pop()
        data["context"] = "\n".join(lines + excerpts)
        estimate = _payload_tokens(data)
    if estimate > budget:
        data["context"] = ""
        estimate = _payload_tokens(data)
    data["estimated_tokens"] = estimate
    return tools.envelope(True, data)


def route_batch_peek(paths: list[str], token_budget: int = 1200,
                     lines_per_file: int = 30) -> dict[str, Any]:
    """Peek multiple files with one call and a shared character/token cap."""
    budget = max(32, min(int(token_budget), 4000))
    line_cap = max(1, min(int(lines_per_file), 200))
    output = []
    used = 0
    for raw in paths[:30]:
        try:
            path = guard.read_guard(raw)
        except guard.Denied as exc:
            output.append({"path": raw, "ok": False, "err": exc.code})
            continue
        if not path.is_file():
            output.append({"path": str(path), "ok": False, "err": "not_a_file"})
            continue
        text = _read(path, max(0, (budget - used) * 4))
        selected = "\n".join(text.splitlines()[:line_cap])
        item = {"path": str(path), "ok": True, "text": selected}
        candidate = output + [item]
        if _tokens(json.dumps(candidate, ensure_ascii=False)) > budget:
            remaining = max(0, budget * 4 - len(json.dumps(output, ensure_ascii=False)) - 64)
            item["text"] = selected[:remaining]
            candidate = output + [item]
            if _tokens(json.dumps(candidate, ensure_ascii=False)) > budget:
                break
        output.append(item)
        used = _tokens(json.dumps(output, ensure_ascii=False))
    data = {"files": output, "estimated_tokens": used, "token_budget": budget}
    while _payload_tokens(data) > budget and output:
        output.pop()
    data["estimated_tokens"] = _payload_tokens(data)
    return tools.envelope(True, data)


def _error_lines(lines: list[str], cap: int, budget: int) -> tuple[list[str], bool, int]:
    matches = [i for i, line in enumerate(lines) if ERROR_LINE.search(line)]
    priority = [(i + 1, lines[i]) for i in matches]
    nearby = [(j + 1, lines[j]) for i in matches
              for j in (i - 1, i + 1) if 0 <= j < len(lines)]
    kept: list[str] = []
    truncated = False
    for number, line in dict.fromkeys(priority + nearby):
        if len(kept) >= cap:
            truncated = True
            break
        item = f"{number}: {line}"
        if _tokens("\n".join(kept + [item])) > budget:
            if ERROR_LINE.search(line) and not kept:
                kept.append(item[:budget * 4])
            truncated = True
            break
        kept.append(item)
    return kept, truncated, len(matches)


def route_errors(path: str, max_lines: int = 40,
                 token_budget: int = 800) -> dict[str, Any]:
    """Extract bounded error/failure lines and nearby trace context."""
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return tools.envelope(False, err=f"{exc.code}: {exc.reason}")
    if not canon.is_file():
        return tools.envelope(False, err="not_a_file")
    text = _read(canon, 2_000_000)
    if "\0" in text[:4096]:
        return tools.envelope(False, err="binary_file")
    cap = max(1, min(int(max_lines), 200))
    budget = max(32, min(int(token_budget), 4000))
    kept, truncated, matches = _error_lines(text.splitlines(), cap, budget)
    data = {"path": str(canon), "lines": kept, "matches": matches,
            "estimated_tokens": _tokens("\n".join(kept)), "token_budget": budget}
    return tools.envelope(True, data, truncated=truncated)
