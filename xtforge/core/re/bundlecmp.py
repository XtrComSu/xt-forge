"""Compare two whole application bundles, not just two binaries.

`re diff` compares one binary to another and `re fn-match` matches functions across a strip.
Neither answers the question a release engineer actually asks: *what changed between version
1.2 and 1.3 of this app?* The answer spans four layers that have to be read together, because
a change in one is often only explicable by a change in another:

  * **metadata** — package name, version, permissions, SDK range. A new permission with no
    code change is a supply-chain finding; a code change with no version bump is a release
    process finding.
  * **resources** — added, removed, or modified assets.
  * **native code** — shared objects, fingerprinted per file.
  * **DEX/bytecode** — held byte-for-byte rather than parsed, since decoding Dalvik is a
    different job; a hash change is enough to say "code changed here".

The unit of comparison is the file, keyed by its path inside the bundle, with content hashed.
That is deliberately boring: it makes the output checkable against `unzip -l` and `diff -r`,
which is how the tests validate it. Anything cleverer would be unverifiable.

Handles both shapes: a directory tree (an unzipped `.app` or a built `assets/` folder) and a
zip (`.apk`, `.ipa`, `.aab`, `.jar`, `.whl`). A zip and a directory can be compared to each
other, which is the common case when someone hands you a build next to an extracted reference.
"""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Any

MAX_ENTRIES = 20000
MAX_HASH_BYTES = 64 * 1024 * 1024

# A modification smaller than this is reported with its byte offsets so the caller can see
# whether a "changed" file is a real edit or a timestamp/reproducibility artefact.
_BYTE_DIFF_SAMPLE = 8

_METADATA_NAMES = ("androidmanifest.xml", "info.plist", "manifest.mf", "package.json")
_DEX_SUFFIXES = (".dex", ".odex", ".vdex", ".art")
_NATIVE_SUFFIXES = (".so", ".dylib", ".dll", ".node")
_RESOURCE_SUFFIXES = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".9.png", ".xml", ".json",
                      ".txt", ".strings", ".stringsdict", ".car", ".ttf", ".otf", ".wav",
                      ".mp3", ".mp4", ".bin", ".dat", ".arsc")


def _category(name: str) -> str:
    """Classify a bundle entry so the diff can be grouped by what kind of thing changed."""
    lowered = name.lower()
    base = lowered.rsplit("/", 1)[-1]
    if base in _METADATA_NAMES or lowered.endswith(".plist"):
        return "metadata"
    if lowered.endswith(_DEX_SUFFIXES):
        return "bytecode"
    if lowered.endswith(_NATIVE_SUFFIXES):
        return "native"
    if lowered.endswith(_RESOURCE_SUFFIXES):
        return "resource"
    if base.endswith(".class") or base.endswith(".jar"):
        return "bytecode"
    return "other"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_tree(root: Path) -> dict[str, dict[str, Any]]:
    """Walk a directory bundle into {relative path: {size, sha256}}."""
    entries: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
            if size > MAX_HASH_BYTES:
                entries[relative] = {"size": size, "sha256": None,
                                     "note": f"larger than {MAX_HASH_BYTES} bytes, not hashed"}
                continue
            entries[relative] = {"size": size, "sha256": _digest(path.read_bytes())}
        except OSError as exc:
            entries[relative] = {"size": None, "sha256": None, "note": f"unreadable: {exc}"}
        if len(entries) >= MAX_ENTRIES:
            break
    return entries


def _read_zip(path: Path) -> dict[str, dict[str, Any]]:
    """Read a zip bundle into {name: {size, sha256}}, skipping directory entries."""
    entries: dict[str, dict[str, Any]] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                try:
                    if info.file_size > MAX_HASH_BYTES:
                        entries[name] = {
                            "size": info.file_size, "sha256": None,
                            "note": f"larger than {MAX_HASH_BYTES} bytes, not hashed"}
                        continue
                    entries[name] = {"size": info.file_size,
                                     "sha256": _digest(archive.read(info))}
                except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                    entries[name] = {"size": info.file_size, "sha256": None,
                                     "note": f"unreadable: {exc}"}
                if len(entries) >= MAX_ENTRIES:
                    break
    except zipfile.BadZipFile:
        return {}
    return entries


def _load(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    """Read either shape, returning the entry map and which shape it was."""
    if path.is_dir():
        return _read_tree(path), "directory"
    if zipfile.is_zipfile(path):
        return _read_zip(path), "zip"
    return {}, "unknown"


def _byte_differences(a_path: Path, b_path: Path, name: str) -> dict[str, Any]:
    """For a changed file, say WHERE it changed — not just that it did.

    A release comparison that says "libfoo.so changed" is barely more useful than `cmp`. The
    first differing offsets and their bytes distinguish a rebuilt binary (differences
    scattered through the file) from a one-byte patch (a single offset) from a
    reproducibility artefact (differences confined to the BuildID or timestamp region).
    """
    try:
        if a_path.is_dir() and b_path.is_dir():
            data_a = (a_path / name).read_bytes()
            data_b = (b_path / name).read_bytes()
        elif not a_path.is_dir() and not b_path.is_dir():
            with zipfile.ZipFile(a_path) as archive:
                data_a = archive.read(name)
            with zipfile.ZipFile(b_path) as archive:
                data_b = archive.read(name)
        else:
            return {}
    except (OSError, KeyError, zipfile.BadZipFile, RuntimeError):
        return {}

    offsets: list[int] = []
    limit = min(len(data_a), len(data_b))
    for index in range(limit):
        if data_a[index] != data_b[index]:
            offsets.append(index)
            if len(offsets) >= _BYTE_DIFF_SAMPLE:
                break
    return {
        "size_delta": len(data_b) - len(data_a),
        "first_diff_offsets": offsets,
        "first_diff_offsets_hex": [hex(offset) for offset in offsets],
        "bytes_a": [data_a[offset] for offset in offsets],
        "bytes_b": [data_b[offset] for offset in offsets],
        "identical_prefix": not offsets,
    }


def compare_bundles(path_a: str | Path, path_b: str | Path) -> dict[str, Any]:
    """Compare two application bundles layer by layer.

    Returns added/removed/modified entries grouped by category (metadata, bytecode, native,
    resource, other), with byte-level evidence for modified files where both sides are
    readable. A metadata change is called out separately because a permission or version
    change is the finding most often missed when only code is diffed.
    """
    a, b = Path(path_a), Path(path_b)
    for candidate in (a, b):
        if not candidate.exists():
            return {"ok": False, "error": f"not found: {candidate}"}

    entries_a, kind_a = _load(a)
    entries_b, kind_b = _load(b)
    if kind_a == "unknown" or kind_b == "unknown":
        return {"ok": False,
                "error": "one side is neither a directory nor a zip",
                "kind_a": kind_a, "kind_b": kind_b}
    if not entries_a and not entries_b:
        return {"ok": False, "error": "both bundles are empty",
                "kind_a": kind_a, "kind_b": kind_b}

    names_a, names_b = set(entries_a), set(entries_b)
    added = sorted(names_b - names_a)
    removed = sorted(names_a - names_b)

    modified: list[dict[str, Any]] = []
    unchanged: list[str] = []
    for name in sorted(names_a & names_b):
        entry_a, entry_b = entries_a[name], entries_b[name]
        if entry_a.get("sha256") is None or entry_b.get("sha256") is None:
            # Unhashed (too large or unreadable): compare by size and say so.
            if entry_a.get("size") != entry_b.get("size"):
                modified.append({"path": name, "category": _category(name),
                                 "reason": "size changed (content not hashed)",
                                 "size_a": entry_a.get("size"),
                                 "size_b": entry_b.get("size")})
            continue
        if entry_a["sha256"] == entry_b["sha256"]:
            unchanged.append(name)
            continue
        detail: dict[str, Any] = {"path": name, "category": _category(name),
                                  "reason": "content changed",
                                  "size_a": entry_a.get("size"),
                                  "size_b": entry_b.get("size")}
        detail.update(_byte_differences(a, b, name))
        modified.append(detail)

    def group(names: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name in names:
            out.setdefault(_category(name), []).append(name)
        return out

    metadata_changes = [
        entry for entry in modified
        if entry["category"] == "metadata"
    ] + [{"path": name, "category": "metadata", "reason": "added"} for name in added
         if _category(name) == "metadata"] + [
        {"path": name, "category": "metadata", "reason": "removed"} for name in removed
        if _category(name) == "metadata"]

    total = len(names_a | names_b)
    signature_changed = bool(added or removed or modified)
    return {
        "ok": True,
        "bundle_a": str(a),
        "bundle_b": str(b),
        "kind_a": kind_a,
        "kind_b": kind_b,
        "entries_a": len(entries_a),
        "entries_b": len(entries_b),
        "added_count": len(added),
        "removed_count": len(removed),
        "modified_count": len(modified),
        "unchanged_count": len(unchanged),
        "added": added[:200],
        "removed": removed[:200],
        "modified": modified[:200],
        "added_by_category": group(added),
        "removed_by_category": group(removed),
        "modified_by_category": group([entry["path"] for entry in modified]),
        "metadata_changes": metadata_changes,
        "identical": not signature_changed,
        "changed_fraction": round(
            (len(added) + len(removed) + len(modified)) / total, 4) if total else 0.0,
        "note": ("Comparison is per-file by content hash, so it is checkable against "
                 "`unzip -l` and `diff -r`. Bytecode is hashed rather than parsed: a "
                 "changed DEX is reported as changed, and decoding Dalvik is a separate "
                 "verb."),
    }


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return compare_bundles(path, **kwargs)
