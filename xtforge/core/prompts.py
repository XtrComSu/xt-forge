"""Prompt loading (R11): one function, every prompt hashed into the run log.

No runtime prompt may be constructed anywhere else.
"""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..version import project_root

PROMPT_DIR = project_root() / "prompts"
_VAR = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
UNKNOWN = object()


class PromptError(RuntimeError):
    pass


def prompt_path(name: str) -> Path:
    """Resolve a prompt reference.

    Accepts a bare name ("verifier"), a path relative to prompts/
    ("phases/design"), a project-relative path ("prompts/phases/design"),
    or an absolute path.
    """
    rel = name[:-3] if name.endswith(".md") else name
    candidates = [
        PROMPT_DIR / f"{rel}.md",
        project_root() / f"{rel}.md",
        Path(rel) if Path(rel).is_absolute() else None,
    ]
    for c in candidates:
        if c is not None and c.exists():
            return c
    raise PromptError(f"prompt not found: {name} (tried {[str(c) for c in candidates if c]})")


@lru_cache(maxsize=64)
def _load(name: str) -> str:
    return prompt_path(name).read_text(encoding="utf-8")


def prompt_hash(name: str) -> str:
    return hashlib.sha256(_load(name).encode("utf-8")).hexdigest()[:12]


def variables(name: str) -> list[str]:
    return sorted(set(_VAR.findall(_load(name))))


def render(name: str, **values: Any) -> str:
    """Substitute {{vars}}. Missing vars raise; extra vars are ignored."""
    text = _load(name)
    needed = set(variables(name))
    missing = needed - set(values)
    if missing:
        raise PromptError(f"prompt {name} missing vars: {sorted(missing)}")
    return _VAR.sub(lambda m: str(values.get(m.group(1), "")), text)


def render_with_hashes(name: str, **values: Any) -> tuple[str, dict[str, str]]:
    """Returns (rendered_text, {prompt_name: hash}) for the run log."""
    return render(name, **values), {name: prompt_hash(name)}


def hash_all() -> dict[str, str]:
    """Hash every shipped prompt, for the run header."""
    out: dict[str, str] = {}
    for p in sorted(PROMPT_DIR.rglob("*.md")):
        rel = p.relative_to(PROMPT_DIR).with_suffix("").as_posix()
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
    return out


def clear_cache() -> None:
    _load.cache_clear()