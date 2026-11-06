"""Session checkpointing engine (fork and rewind).

Allows agents and workflows to snapshot active state (.xt-forge mem.db, taste.db, flash/)
and rewind context cleanly if an exploratory hypothesis fails.
"""
from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from ..version import xt_home


def _resolve_base(base_dir: Path | None = None) -> Path:
    if base_dir:
        return Path(base_dir)
    return xt_home()


def _checkpoints_dir(base: Path) -> Path:
    d = base / "checkpoints"
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_checkpoint(name: str | None = None, base_dir: Path | None = None) -> dict[str, Any]:
    """Snapshot the current XT-Forge state into a durable checkpoint."""
    base = _resolve_base(base_dir)
    cp_dir = _checkpoints_dir(base)

    cp_id = f"cp_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    target = cp_dir / cp_id
    target.mkdir(parents=True, exist_ok=True)

    items_copied: list[str] = []

    # Copy mem.db
    mem_file = base / "mem.db"
    if mem_file.is_file():
        shutil.copy2(mem_file, target / "mem.db")
        items_copied.append("mem.db")

    # Copy taste.db
    taste_file = base / "taste.db"
    if taste_file.is_file():
        shutil.copy2(taste_file, target / "taste.db")
        items_copied.append("taste.db")

    # Copy flash directory
    flash_src = base / "flash"
    if flash_src.is_dir():
        flash_dst = target / "flash"
        shutil.copytree(flash_src, flash_dst)
        items_copied.append("flash")

    manifest = {
        "id": cp_id,
        "name": name or cp_id,
        "timestamp": int(time.time()),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "items": items_copied,
    }

    (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "id": cp_id,
        "name": manifest["name"],
        "checkpoint_dir": str(target),
        "items": items_copied,
    }


def restore_checkpoint(checkpoint_id: str, base_dir: Path | None = None) -> dict[str, Any]:
    """Rewind the current XT-Forge state from a checkpoint snapshot."""
    base = _resolve_base(base_dir)
    cp_dir = _checkpoints_dir(base)
    source = cp_dir / checkpoint_id

    if not source.is_dir():
        return {"ok": False, "err": f"checkpoint not found: {checkpoint_id}"}

    manifest_file = source / "manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_file.is_file():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}

    restored_items: list[str] = []

    # Restore mem.db
    src_mem = source / "mem.db"
    if src_mem.is_file():
        shutil.copy2(src_mem, base / "mem.db")
        restored_items.append("mem.db")

    # Restore taste.db
    src_taste = source / "taste.db"
    if src_taste.is_file():
        shutil.copy2(src_taste, base / "taste.db")
        restored_items.append("taste.db")

    # Restore flash directory cleanly
    src_flash = source / "flash"
    if src_flash.is_dir():
        dst_flash = base / "flash"
        if dst_flash.is_dir():
            shutil.rmtree(dst_flash)
        shutil.copytree(src_flash, dst_flash)
        restored_items.append("flash")

    return {
        "ok": True,
        "id": checkpoint_id,
        "name": manifest.get("name", checkpoint_id),
        "restored_items": restored_items,
    }


def list_checkpoints(base_dir: Path | None = None) -> list[dict[str, Any]]:
    """List all saved session checkpoints."""
    base = _resolve_base(base_dir)
    cp_dir = _checkpoints_dir(base)

    results: list[dict[str, Any]] = []
    if not cp_dir.is_dir():
        return results

    for entry in sorted(cp_dir.iterdir(), reverse=True):
        if entry.is_dir():
            m_path = entry / "manifest.json"
            if m_path.is_file():
                try:
                    data = json.loads(m_path.read_text(encoding="utf-8"))
                    results.append(data)
                    continue
                except Exception:
                    pass
            results.append({"id": entry.name, "name": entry.name, "timestamp": 0})

    return results


def delete_checkpoint(checkpoint_id: str, base_dir: Path | None = None) -> dict[str, Any]:
    """Delete a checkpoint snapshot."""
    base = _resolve_base(base_dir)
    cp_dir = _checkpoints_dir(base)
    target = cp_dir / checkpoint_id

    if not target.is_dir():
        return {"ok": False, "err": f"checkpoint not found: {checkpoint_id}"}

    shutil.rmtree(target)
    return {"ok": True, "id": checkpoint_id}
