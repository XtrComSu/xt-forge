"""Scaffold a portable reverse-engineering research repository."""
from __future__ import annotations

from contextlib import suppress
from html import escape
from importlib.resources import files
from pathlib import Path

from ..route import guard

_TEMPLATE_FILES = {
    "README.md": "README.md",
    "CONTRIBUTING.md": "CONTRIBUTING.md",
    "gitignore.txt": ".gitignore",
    "finding.md": ".github/ISSUE_TEMPLATE/finding.md",
    "pull_request_template.md": ".github/pull_request_template.md",
    "REPORT.md": "docs/REPORT.md",
    "showcase.gif": "docs/assets/showcase.gif",
    "activity.svg": "docs/assets/activity.svg",
    "demo.c": "fixtures/demo.c",
    "update_activity.py": "scripts/update_activity.py",
}


def init_project(path: str, *, name: str | None = None) -> dict:
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise FileExistsError(f"project destination already exists: {raw}")
    dest = guard.check_allowed(raw, write=True)
    guard.check_write_mode()
    name = (dest.name if name is None else name).strip()
    if not name or not name.isprintable():
        raise ValueError("project name must be a nonempty single line of printable text")

    template = files(__package__).joinpath("project_template")
    payload = {target: template.joinpath(source).read_bytes()
               for source, target in _TEMPLATE_FILES.items()}
    readme = payload["README.md"].decode("utf-8")
    payload["README.md"] = readme.replace("{{PROJECT_NAME}}", escape(name), 1).encode("utf-8")
    folders = sorted({parent for rel in payload for parent in Path(rel).parents
                      if parent != Path(".")}, key=lambda part: (len(part.parts), part.parts))

    # Claim the destination before creating anything inside it.
    dest.mkdir()
    created = []
    try:
        for folder in folders:
            directory = dest / folder
            directory.mkdir()
            created.append((directory, True))
        for rel, data in payload.items():
            target = dest / rel
            with target.open("xb") as fp:
                created.append((target, False))
                fp.write(data)
    except OSError:
        for target, is_dir in reversed(created):
            with suppress(OSError):
                target.rmdir() if is_dir else target.unlink()
        with suppress(OSError):
            dest.rmdir()
        raise

    return {"ok": True, "path": str(dest), "name": name, "files": sorted(payload)}
