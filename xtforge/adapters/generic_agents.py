#!/usr/bin/env python3
"""Render AGENTS.md for generic harnesses from the template (idempotent)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from xtforge.atomicio import atomic_write_text  # noqa: E402
from xtforge.version import app_name, project_root, version_str, xt_home  # noqa: E402

TEMPLATE = ROOT / "adapters" / "generic" / "AGENTS.md.tpl"


def bin_path() -> Path:
    """Absolute launcher path — harness shells lack ~/bin and Termux's PATH."""
    home = Path(os.environ.get("HOME") or Path.home())
    return home / "bin" / app_name()


def render(target_root: Path | None = None) -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("<app>", app_name())
    text = text.replace("<version>", version_str())
    text = text.replace("<root>", str(target_root or project_root()))
    text = text.replace("<xt_home>", str(xt_home()))
    text = text.replace("<bin>", str(bin_path()))
    return text


def main() -> int:
    target_root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else project_root()
    out = target_root / "AGENTS.md"
    versioned = render(target_root)
    current = out.read_text(encoding="utf-8") if out.exists() else None
    if current == versioned:
        print(f"AGENTS.md unchanged: {out}")
        return 0
    atomic_write_text(out, versioned)
    print(f"wrote {out} ({app_name()} {version_str()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())