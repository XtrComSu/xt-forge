"""Shared CLI helpers: JSON output, store/flash construction."""
from __future__ import annotations

import json
import sys
from typing import Any


def _store(args):
    from ..core.mem.store import Store
    from ..version import db_path
    return Store(args.db or str(db_path()))


def _flash(args):
    from ..core.mem.flash import Flash
    return Flash(base=args.flash_base)


def _out(args, obj: Any, human: str | None = None, code: int = 0) -> int:
    if getattr(args, "json", False):
        print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    else:
        print(human if human is not None else json.dumps(
            obj, ensure_ascii=False, indent=2, default=str))
    return code


def _read_file_arg(args, dest: str) -> str | None:
    """Read a text value from `--<dest>` (a path, or '-' for stdin).

    Long notes, multi-line bodies and anything containing quotes or shell
    metacharacters cannot survive being passed as one inline argv value
    through a shell. Reading from a file (or stdin) removes the shell from
    the path, so the bytes stored are exactly the bytes written.

    Returns the file contents, or None when the option was not supplied.
    Raises OSError with a readable message when the path cannot be read.
    """
    src = getattr(args, dest, None)
    if not src:
        return None
    if src == "-":
        import sys
        return sys.stdin.read()
    try:
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as e:
        raise OSError(f"cannot read --{dest.replace('_', '-')} {src}: {e}") from e
