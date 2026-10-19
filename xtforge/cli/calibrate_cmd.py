"""`xtforge calibrate` — reboot-aware memory recalibration."""
from __future__ import annotations

import json

from .common import _out


def cmd_calibrate(args):
    from ..core import calibrate as calmod

    if getattr(args, "calibrate_status", False):
        return _out(args, calmod.status(), json.dumps(calmod.status(), indent=2))
    res = calmod.calibrate(force=getattr(args, "force", False))
    human = (
        f"calibrate {'skipped (fresh)' if res.get('skipped') else 'done'} "
        f"in {res.get('ms', 0)}ms boot={str(res.get('boot_id'))[:8]} "
        f"reboot={res.get('reboot')}"
    )
    return _out(args, res, human)
