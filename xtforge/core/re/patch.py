"""Safe, verified atomic binary patcher.

Creates timestamped or suffix-isolated binary copies with original byte verification
to test bypasses or logic changes without destroying the original binary.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..route import guard


class PatchError(ValueError):
    """Raised when patch boundaries or original byte verification fails."""


def apply_patch(
    target: str | Path,
    offset: int,
    patch_bytes: bytes,
    original_bytes: bytes | None = None,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Apply atomic byte replacement on a binary copy with verification."""
    canon = guard.read_guard(target)
    if not canon.is_file():
        raise PatchError(f"target is not a regular file: {target}")

    try:
        data = bytearray(canon.read_bytes())
    except OSError as exc:
        raise PatchError(f"cannot read target file: {exc}") from exc

    if offset < 0 or offset + len(patch_bytes) > len(data):
        raise PatchError(
            f"patch offset 0x{offset:x} (len {len(patch_bytes)}) is out of file bounds ({len(data)} bytes)"
        )

    # Verify original bytes if specified
    if original_bytes is not None:
        actual = bytes(data[offset : offset + len(original_bytes)])
        if actual != original_bytes:
            raise PatchError(
                f"original byte mismatch at 0x{offset:x}: expected {original_bytes.hex()}, found {actual.hex()}"
            )

    # Apply replacement
    data[offset : offset + len(patch_bytes)] = patch_bytes

    if out_path:
        dest = Path(out_path).resolve()
    else:
        dest = canon.parent / f"{canon.stem}-patch{canon.suffix}"

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(bytes(data))
    except OSError as exc:
        raise PatchError(f"cannot write patched binary to {dest}: {exc}") from exc

    return {
        "ok": True,
        "source": str(canon),
        "out_path": str(dest),
        "offset": hex(offset),
        "bytes_patched": len(patch_bytes),
        "hex_patch": patch_bytes.hex(),
    }
