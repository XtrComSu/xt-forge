#!/usr/bin/env python3
"""Backwards-compatible entrypoint delegating to `xtforge.adapters.mcp_server`."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xtforge.adapters.mcp_server import *  # noqa: F401,F403
from xtforge.adapters.mcp_server import _handle, _handle_meta_call, _version, main  # noqa: F401


if __name__ == "__main__":
    raise SystemExit(main())
