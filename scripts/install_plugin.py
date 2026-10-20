#!/usr/bin/env python3
"""Install (or check) the xt-native OpenCode plugin from this repo.

The plugin is plain TypeScript with no build step: OpenCode loads `index.ts`
directly. Shipping therefore means "the source of truth lives in the repo and
the installed copy matches it" — this script makes that checkable.

    python3 scripts/install_plugin.py            # install to the default path
    python3 scripts/install_plugin.py --check    # fail if the copy has drifted
    python3 scripts/install_plugin.py --target DIR --json

`--check` is the regression gate: it exits non-zero when the installed plugin
differs from the repo, so a stale install cannot pass unnoticed.

The implementation lives in `xtforge.core.plugin.manager`, which is also what
`xtforge plugin install|status` calls: one writer, one set of rules.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core.plugin import manager  # noqa: E402


def version() -> str:
    """The repo version, from the single source of truth."""
    for line in (ROOT / "VERSION").read_text(encoding="utf-8").splitlines():
        if line.startswith("version="):
            return line.split("=", 1)[1].strip()
    return ""


def check(target: Path) -> dict:
    res = manager.status(target=target)
    drift = sorted({*res["drift"]["missing"], *res["drift"]["modified"],
                     *res["drift"]["extra"]})
    return {
        "ok": bool(res["current"]),
        "target": str(target),
        "expected": manager.manifest(),
        "installed": {name: manager._sha256(target / name)
                      for name in manager.PAYLOAD
                      if (target / name).is_file()},
        "drift": drift,
    }


def install(target: Path) -> dict:
    res = manager.install(target=target)
    return {
        "ok": True,
        "target": str(target),
        "installed": res["files"],
        "removed": res["removed"],
        "registered": res["registered"],
        "config": res["config"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=str(manager.target_dir()),
                        help="install directory (default: the OpenCode plugin path)")
    parser.add_argument("--check", action="store_true",
                        help="verify the installed copy matches the repo; exit 1 on drift")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    target = Path(args.target).expanduser()

    result = check(target) if args.check else install(target)
    result["version"] = version()
    result["mode"] = "check" if args.check else "install"

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if args.check:
            state = "ok" if result["ok"] else "DRIFT"
            print(f"plugin {state}: {target}")
            for name in result["drift"]:
                print(f"  differs: {name}")
        else:
            print(f"installed {', '.join(result['installed'])} -> {target}")
            if result["removed"]:
                print(f"  removed stale: {', '.join(result['removed'])}")

    return 0 if (result.get("ok", True) or not args.check) else 1


if __name__ == "__main__":
    sys.exit(main())
