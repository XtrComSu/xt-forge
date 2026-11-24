"""Static inspection of HarmonyOS application packages (`.hap`).

Excluded from the breadth matrix as "requires HarmonyOS .hap packaging knowledge; not in this
engine's lane". The first half is true and is not a reason to exclude: a `.hap` is a ZIP
container with a documented manifest layout, so knowing the layout is the work, and this engine
already reads ZIP-based packages (APK, JAR, VSIX, wheels) the same way. The second half is
circular — "not in our lane" is what the audit is deciding, not evidence.

What is answered statically: bundle and module identity, target device types, declared
permissions (the security-relevant part), exported abilities and extension abilities with their
entry points, and the ArkTS bytecode files present. Nothing here needs the SDK, a device, or the
DevEco toolchain, because none of those are required to read a manifest.

Deliberately not claimed: decompiling `.abc` (ArkTS bytecode). Its format is versioned and
undocumented in the detail required; the files are listed with their sizes so they can be
extracted, and `re disasm-native` remains the honest answer for the native `.so` files a `.hap`
carries.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 20000
# Module types defined by the HarmonyOS bundle layout. Unknown types are reported by their raw
# value rather than mapped onto a nearest guess.
_MODULE_TYPES = {"entry": "entry", "feature": "feature", "har": "shared", "shared": "shared"}
_DEVICE_TYPES = {"phone", "tablet", "tv", "wearable", "car", "2in1", "default"}


def _read_entry(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > MAX_ENTRY_BYTES:
        raise ValueError(f"{name} is {info.file_size} bytes, over the {MAX_ENTRY_BYTES} limit")
    # read() with a size cap rather than trusting the declared length alone.
    with archive.open(info) as handle:
        return handle.read(MAX_ENTRY_BYTES + 1)[:MAX_ENTRY_BYTES]


def _json_entry(archive: zipfile.ZipFile, name: str) -> dict[str, Any] | None:
    try:
        raw = _read_entry(archive, name)
    except (KeyError, ValueError, OSError, zipfile.BadZipFile):
        return None
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def inspect_hap(path: str | Path) -> dict[str, Any]:
    """Read a `.hap` archive's manifest without the HarmonyOS SDK."""
    target = Path(str(path))
    if not target.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    try:
        archive = zipfile.ZipFile(target)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"ok": False, "error": f"not a readable ZIP archive: {exc}",
                "hint": "a .hap is a ZIP containing module.json"}

    with archive:
        names = archive.namelist()[:MAX_ENTRIES]
        module = _json_entry(archive, "module.json")
        pack = _json_entry(archive, "pack.info")
        if module is None and pack is None:
            return {"ok": False, "path": str(target),
                    "error": "no module.json or pack.info in the archive",
                    "entries": len(names),
                    "hint": "this is a ZIP but does not look like a HarmonyOS package"}

        # Identity: pack.info holds the bundle-level view, module.json the module's own.
        bundle_name = None
        version = None
        if pack:
            summary = pack.get("summary") or {}
            app = summary.get("app") if isinstance(summary, dict) else None
            if isinstance(app, dict):
                bundle_name = app.get("bundleName")
                version = app.get("version")
        if module:
            bundle_name = bundle_name or module.get("bundleName")
            if version is None:
                version = {"name": module.get("versionName"), "code": module.get("versionCode")}

        abilities: list[dict[str, Any]] = []
        for key in ("abilities", "extensionAbilities"):
            for entry in (module or {}).get(key) or []:
                if not isinstance(entry, dict):
                    continue
                abilities.append({
                    "name": entry.get("name"),
                    "kind": "ability" if key == "abilities" else "extension",
                    "src_entry": entry.get("srcEntry"),
                    "exported": entry.get("exported"),
                    "skills": entry.get("skills"),
                    "permissions": entry.get("permissions"),
                })

        requested: list[dict[str, Any]] = []
        for entry in (module or {}).get("requestPermissions") or []:
            if isinstance(entry, dict):
                requested.append({"name": entry.get("name"),
                                  "reason": entry.get("reason"),
                                  "used_scene": entry.get("usedScene")})
            elif isinstance(entry, str):
                requested.append({"name": entry})

        device_types = (module or {}).get("deviceTypes") or []
        unknown_devices = [item for item in device_types if item not in _DEVICE_TYPES]

        # ArkTS bytecode and native libraries are listed, not decoded.
        bytecode = [{"path": name, "size": archive.getinfo(name).file_size}
                    for name in names if name.endswith(".abc")][:200]
        native = [{"path": name, "size": archive.getinfo(name).file_size}
                  for name in names if name.endswith(".so")][:200]

        module_type = (module or {}).get("type")
        report: dict[str, Any] = {
            "ok": True, "path": str(target),
            "format": "hap",
            "size_bytes": target.stat().st_size,
            "entry_count": len(names),
            "bundle_name": bundle_name,
            "version": version,
            "module_name": (module or {}).get("name"),
            "module_type": _MODULE_TYPES.get(module_type, module_type),
            "device_types": device_types,
            "ability_count": len(abilities),
            "abilities": abilities[:60],
            "permission_count": len(requested),
            "permissions": requested[:80],
            "bytecode_files": bytecode,
            "native_files": native,
            "note": ("ArkTS bytecode (.abc) is listed but not decompiled — its format is "
                     "versioned and not documented in the detail a decoder would need; native "
                     "libraries can be extracted and read with `re disasm-native`"),
        }
        if unknown_devices:
            # Say the value is unrecognised rather than dropping it: it may be a newer target.
            report["unrecognised_device_types"] = unknown_devices
        if module_type and module_type not in _MODULE_TYPES:
            report["unrecognised_module_type"] = module_type
        return report


def inspect(path: str | Path, **_: Any) -> dict[str, Any]:
    return inspect_hap(path)
