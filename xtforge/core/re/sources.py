"""One place that decides where an answer comes from.

Four verbs — `info`, `sections`, `needed`, `symbols` — each grew its own format reader
(ELF, PE) and answered "unrecognized binary format" for anything else, while
`re overview` parsed the same files without complaint. The same defect was fixed four
times, once per verb, which is the signal that the dispatch belonged somewhere shared.

The rule is: a format-specific Python reader wins where one exists, because it reports
more detail than the generic view; otherwise the native engine answers, because it reads
every format this tool claims to support. Anything neither can read is reported as such,
with the formats that do work named.

Keeping the decision here means adding a format is one change, not five.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

# Formats with a dedicated Python reader. These return richer detail than the hub's
# generic section/segment view, so they keep priority.
PYTHON_READERS = ("elf", "pe")


def _hub():
    from . import sysimage

    return sysimage


def hub_overview(path: str | Path) -> dict[str, Any] | None:
    """The native engine's view of a file, or None when it cannot read it."""
    try:
        result = _hub().overview(str(path))
    except Exception:
        return None
    if not isinstance(result, dict) or not result.get("ok"):
        return None
    return result


def hub_format(path: str | Path) -> str | None:
    """The format the native engine reports, without keeping the whole overview."""
    result = hub_overview(path)
    return (result or {}).get("format")


def _images(overview: dict[str, Any]) -> list[dict[str, Any]]:
    images = overview.get("images") or []
    return [image for image in images if isinstance(image, dict)]


def sections_from_hub(path: str | Path, overview: dict[str, Any] | None = None) -> list[dict[str, Any]] | None:
    """Section table in the shape `re sections` publishes, or None when unavailable."""
    overview = overview if overview is not None else hub_overview(path)
    if overview is None:
        return None
    rows: list[dict[str, Any]] = []
    for index, region in enumerate(_images(overview)[0].get("sections") or [] if _images(overview) else []):
        rows.append({
            "index": index,
            "name": region.get("name", ""),
            "type": "native",
            "type_id": 0,
            "flags": "0x0",
            "addr": hex(region.get("address", 0)),
            "offset": hex(region.get("offset", 0)),
            "size": region.get("size", 0),
            "file_size": region.get("file_size", 0),
        })
    return rows or None


def needed_from_hub(path: str | Path, overview: dict[str, Any] | None = None) -> list[str] | None:
    """Dependencies in first-seen order, de-duplicated across slices of a fat binary."""
    overview = overview if overview is not None else hub_overview(path)
    if overview is None:
        return None
    dependencies: list[str] = []
    seen: set[str] = set()
    for image in _images(overview):
        for dependency in image.get("dependencies") or []:
            if dependency not in seen:
                seen.add(dependency)
                dependencies.append(dependency)
    return dependencies


def named_functions_from_hub(path: str | Path, limit: int = 200) -> list[dict[str, Any]]:
    """Functions the engine could name. Not a symbol table, and callers must say so."""
    try:
        result = _hub().functions(str(path), limit=limit)
    except Exception:
        return []
    if not isinstance(result, dict) or not result.get("ok"):
        return []
    named: list[dict[str, Any]] = []
    for image in _images(result):
        for function in image.get("functions") or []:
            name = function.get("name")
            if name:
                named.append({"name": name,
                              "address": hex(function.get("address", 0)),
                              "source": function.get("name_source") or function.get("source")})
    return named


def info_from_hub(path: str | Path, overview: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Header-level metadata for formats without a dedicated Python reader."""
    overview = overview if overview is not None else hub_overview(path)
    if overview is None:
        return None
    images = _images(overview)
    if not images:
        # A container holding no images of its own — an archive. Report its members
        # rather than claiming the file is unrecognised.
        archive = overview.get("archive") or []
        members = archive if isinstance(archive, list) else (archive.get("members") or [])
        if not members:
            return None
        return {
            "ok": True, "path": str(path), "format": overview.get("format"),
            "machine": None, "class": None, "endianness": None,
            "type": overview.get("format"), "entry": None,
            "section_headers": 0, "program_headers": 0, "needed_count": 0,
            "members": len(members),
            "member_names": [m.get("name") for m in members[:20] if isinstance(m, dict)],
            "engine": "xtforge-hub",
        }
    image = images[0]
    entry = image.get("entry_point")
    return {
        "ok": True, "path": str(path), "format": overview.get("format"),
        "member": overview.get("member"),
        "machine": image.get("arch"), "class": f"{image.get('bits', 0)}-bit",
        "endianness": "little", "type": overview.get("format"),
        "entry": hex(entry) if isinstance(entry, int) else None,
        "section_headers": len(image.get("sections") or []),
        "program_headers": len(image.get("segments") or []),
        "needed_count": len(image.get("dependencies") or []),
        "size": None, "engine": "xtforge-hub",
    }


def unsupported(verb: str, path: str | Path, formats: tuple[str, ...] = PYTHON_READERS) -> dict[str, Any]:
    """A refusal that names what does work, so the caller is not left guessing."""
    message = f"{verb} is available for {' and '.join(f.upper() for f in formats)}"
    known = hub_format(path)
    if known:
        message += f"; {path} is {known}"
    return {"ok": False, "error": message, "err": message}
