"""Keyed archives, JVM build metadata, and desktop application bundles.

Three artifact families REA exposes that share one property: each describes *how*
something was built or packaged rather than what its bytes do. They belong together
because they answer the supply-chain question ("what is this and where did it come
from") that an analyst asks before the disassembly question.

  inspect_keyed_archive            NSKeyedArchiver plists: the object graph,
                                   decoded, not just the raw plist
  inspect_jvm_metadata             Maven pom.xml / Gradle module / NuGet nuspec:
                                   coordinates, dependencies, plugins
  inspect_desktop_bundle           macOS .app bundles: Info.plist, executable,
                                   and the URL schemes / entitlements it declares

Each returns {"ok": bool, ...} and never raises on malformed input.

Two things regularly produce wrong output here:

  * An NSKeyedArchiver plist is a *graph* encoded as a flat array of objects plus
    UID references. Printing the plist as-is shows `$objects` as a list of dicts and
    "$top" as `{'root': UID(1)}` — the UIDs are opaque. The archive is only readable
    after the UIDs are resolved into real values, and a naive resolver recurses
    forever on a self-referential graph.
  * A `.app` bundle's `Info.plist` may be binary or XML, and its
    `CFBundleExecutable` names a file *inside* `Contents/MacOS` — the bundle
    directory itself has no executable bit. Looking for an executable at the bundle
    root finds nothing on every real app.
"""
from __future__ import annotations

import json
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 64 * 1024 * 1024
MAX_RESOLVE = 20000

_PLIST_MAGIC = b"bplist00"


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


# --------------------------------------------------------------- keyed archive
def _ib_scalar(value: Any) -> Any:
    """A connection's value, flattened to something a report can print.

    An outlet points at another archived object, so the raw value is a resolved dict several
    levels deep. Printing that whole subtree into a connection line produces a wall of text where
    the class name is the only part that answers the question, so the class is what is kept.
    """
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        if value.get("$classname"):
            return {"$classname": value["$classname"]}
        return {"_type": "dict", "_keys": len(value)}
    if isinstance(value, (list, tuple)):
        return {"_type": "array", "_count": len(value)}
    return str(type(value).__name__)


def decode_interface_builder(path: str | Path, *, max_depth: int = 12) -> dict[str, Any]:
    """Decode an Interface Builder document (`.nib`, or a `.storyboard`/`.xib` compiled to one).

    A compiled nib *is* an `NSKeyedArchiver` plist, so the object graph is the same decode this
    module already performs; what a nib adds is the meaning of the graph. Interface Builder stores
    its UI as a tree of `IB*` / `NS*` class instances whose keys name the connection being made — a
    window template, its content view, an outlet ("this controller's `tableView` property points at
    that view") and an action ("this button sends `save:` to that object"). That is the thing worth
    reporting: for an analyst looking at a packaged iOS or macOS app, the connections say which
    code touches which control, and an outlet named `adminPanel` on a hidden view is a finding.

    The archive is decoded first and the connections are derived from it rather than from a
    separate parse, because a second parser for the same container is a second thing to be wrong.
    """
    archive = inspect_keyed_archive(path, max_depth=max_depth)
    if not archive.get("ok"):
        # Report the archive's own diagnosis; a nib that will not decode is a plist problem, not a
        # separate one, and inventing a nib-specific error message would hide that.
        archive["kind"] = "interface-builder"
        archive["note"] = ("a compiled nib is an NSKeyedArchiver plist, so a decode failure here is "
                           "the same failure the keyed-archive reader reports")
        return archive

    entries = archive.get("objects")
    if not isinstance(entries, list):
        entries = [{"index": 0, "object": archive.get("roots")}]
    # Each slot in `$objects` IS one object, and the table is already flat.
    #
    # The obvious implementation recursed into each resolved object to find nested class
    # instances, which double-counts: `resolve` inlines a referenced object at the referrer, so
    # ViewController's outlet arrived as a full NSTableView copy *and* again at its own slot. The
    # connection count came out 3 for a nib with 2 connections. Reading one slot per object avoids
    # the problem entirely, and it is also what the format actually says: references are UIDs into
    # the same flat table, so there is nothing nested to descend into.
    objects: list[dict[str, Any]] = []
    for slot in entries:
        if not isinstance(slot, dict) or "index" not in slot:
            continue
        node = slot.get("object")
        if not isinstance(node, dict):
            continue
        classname = node.get("$classname")
        if not classname:
            continue
        entry: dict[str, Any] = {"index": slot["index"], "classname": classname}
        for key, value in node.items():
            if not isinstance(key, str) or key.startswith("$"):
                continue
            lowered = key.lower()
            if "outlet" in lowered or "connection" in lowered:
                entry.setdefault("connections", {})[key] = _ib_scalar(value)
            elif "action" in lowered or "selector" in lowered:
                entry.setdefault("actions", {})[key] = _ib_scalar(value)
            elif "name" in lowered or "identifier" in lowered or "title" in lowered:
                entry.setdefault("labels", {})[key] = _ib_scalar(value)
        objects.append(entry)

    classes, seen = [], set()
    for entry in objects:
        if entry["classname"] not in seen:
            seen.add(entry["classname"])
            classes.append(entry["classname"])
    connections = []
    for entry in objects:
        if entry.get("connections") or entry.get("actions"):
            public = {key: value for key, value in entry.items() if key != "_source"}
            connections.append(public)
    return {
        "ok": True,
        "path": archive.get("path"),
        "kind": "interface-builder",
        "format": archive.get("format"),
        "archiver": archive.get("archiver"),
        "object_count": archive.get("object_count"),
        "class_count": len(classes),
        "classes": classes,
        "root_names": archive.get("root_names"),
        # The part that makes this a nib decoder rather than a plist decoder.
        "connection_count": len(connections),
        "connections": connections[:100],
        "note": ("outlets and actions are derived from Interface Builder's connection keys; a "
                 "connection on a control that is never shown is still reported, because presence "
                 "in the graph is the finding"),
    }


def inspect_keyed_archive(path: str | Path | bytes, *, max_depth: int = 12) -> dict[str, Any]:
    """Decode an NSKeyedArchiver plist into a plain object graph.

    The archive's shape: `$objects` is a flat list, `$top` names the roots by UID, and
    every reference is a `plistlib.UID`. Resolving them yields the original object
    graph. Classes are recorded separately (`$class` -> `$classname`), so the report
    includes the class chain — which is what tells you whether an archived object is a
    dictionary, an NSMutableString, or a custom app class.

    Accepts a path or the bytes themselves, matching `inspect_electron_fuses`. Without this, a
    caller holding an archive in memory had to write it to disk, and — worse — passing bytes read as
    a *path* failure: `decode_interface_builder(<plist bytes>)` answered `not a regular file:
    b'<?xml version="1.0"…'`, which describes a missing file to someone who passed no filename.
    """
    if isinstance(path, (bytes, bytearray)):
        raw = bytes(path)
        label = "<bytes>"
    else:
        label = str(path)
        try:
            raw = _read(path)
        except (OSError, ValueError, Denied) as exc:
            return {"ok": False, "path": label, "error": str(exc)}

    try:
        document = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError, OSError) as exc:
        return {"ok": False, "path": label,
                "error": f"not a readable plist: {exc}",
                "format": "binary" if raw[:8] == _PLIST_MAGIC else "xml"}

    if not isinstance(document, dict) or "$archiver" not in document:
        return {"ok": False, "path": label,
                "format": "binary" if raw[:8] == _PLIST_MAGIC else "xml",
                "error": "plist is not an NSKeyedArchiver archive "
                         "(no $archiver key)",
                "top_level_keys": sorted(document)[:20] if isinstance(document, dict)
                else None}

    objects = document.get("$objects") or []
    top = document.get("$top") or {}
    if not isinstance(objects, list):
        return {"ok": False, "path": label, "error": "$objects is not an array"}

    classes: dict[int, list[str]] = {}
    for index, entry in enumerate(objects):
        if isinstance(entry, dict) and "$classname" in entry:
            chain = [entry["$classname"]]
            chain.extend(str(name) for name in (entry.get("$classes") or [])[1:])
            classes[index] = chain

    seen: set[int] = set()

    def resolve(value: Any, depth: int) -> Any:
        """Follow UIDs into the object array, guarding against cycles and depth."""
        if depth > max_depth:
            return {"_truncated": "max depth reached"}
        if isinstance(value, plistlib.UID):
            index = value.data
            if not 0 <= index < len(objects):
                return {"_invalid_uid": index}
            if index in seen:
                return {"_cycle": index}
            seen.add(index)
            try:
                return resolve(objects[index], depth + 1)
            finally:
                # Removing on exit keeps sibling references resolvable: the same
                # UID legitimately appears many times in a flat archive, and only a
                # reference that is still on the stack is a real cycle.
                seen.discard(index)
        if isinstance(value, dict):
            class_ref = value.get("$class")
            class_name = None
            if isinstance(class_ref, plistlib.UID):
                class_name = (classes.get(class_ref.data) or [None])[0]
            if "NS.keys" in value and "NS.objects" in value:
                # An archived dictionary: parallel key/object arrays.
                keys = [resolve(k, depth + 1) for k in (value.get("NS.keys") or [])]
                values = [resolve(v, depth + 1) for v in (value.get("NS.objects") or [])]
                mapping = {}
                for key, item in zip(keys, values):
                    mapping[str(key)] = item
                return {"_class": class_name, "dict": mapping}
            if "NS.objects" in value and "NS.keys" not in value:
                return {"_class": class_name,
                        "array": [resolve(v, depth + 1)
                                  for v in (value.get("NS.objects") or [])]}
            out = {}
            for key, item in value.items():
                if key in ("$class", "$classes"):
                    continue
                out[str(key)] = resolve(item, depth + 1)
            if class_name:
                out["_class"] = class_name
            return out
        if isinstance(value, list):
            return [resolve(item, depth + 1) for item in value]
        return value

    roots = {str(name): resolve(uid, 0) for name, uid in top.items()}
    used_classes = sorted({chain[0] for chain in classes.values()})
    return {
        "ok": True,
        "path": label,
        "format": "binary" if raw[:8] == _PLIST_MAGIC else "xml",
        "archiver": document.get("$archiver"),
        "version": document.get("$version"),
        "object_count": len(objects),
        "class_count": len(classes),
        "classes": used_classes,
        "roots": roots,
        # The flat table, with each entry resolved. Interface Builder stores the whole document
        # here and names only the entry points in `$top`, so a caller that needs every object
        # (a nib decoder does) cannot get it from `roots`.
        "objects": [{"index": index, "object": resolve(entry, 0)}
                    for index, entry in enumerate(objects)],
        "root_names": sorted(roots),
    }


# ------------------------------------------------------------- JVM / NuGet
def inspect_jvm_metadata(path: str | Path) -> dict[str, Any]:
    """Read Maven `pom.xml`, Gradle module metadata, or a NuGet `.nuspec`.

    These three describe the same facts in different spellings, so one reader answers
    all of them: coordinates (group/artifact/version), declared dependencies, and the
    build plugins that would run. That is the supply-chain question — a dependency
    with a suspicious repository or a plugin that fetches code at build time.

    Namespaces are stripped before matching. Maven declares
    xmlns="http://maven.apache.org/POM/4.0.0", so a naive `root.find("groupId")`
    returns None on every real pom — the namespace makes the tag
    `{http://maven.apache.org/POM/4.0.0}groupId`, and every coordinate reads as
    missing on a perfectly valid file.
    """
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    text = raw.decode("utf-8", "replace").strip()
    kind = None
    lowered = text[:400].lower()
    if "<project" in lowered and ("maven" in lowered or "<groupId" in lowered
                                  or "<artifactId" in lowered):
        kind = "maven"
    elif "nuspec" in lowered or ('<package' in lowered and '<metadata' in lowered):
        kind = "nuget"
    elif '"formatVersion"' in text or '"component"' in lowered:
        kind = "gradle-module"

    if kind == "gradle-module":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            return {"ok": False, "path": str(path), "kind": kind,
                    "error": f"invalid JSON: {exc}"}
        component = document.get("component") or {}
        return {
            "ok": True, "path": str(path), "kind": kind,
            "format_version": document.get("formatVersion"),
            "coordinates": {
                "group": component.get("group"),
                "module": component.get("module"),
                "version": component.get("version"),
            },
            "variants": [v.get("name") for v in (document.get("variants") or [])][:40],
            "dependencies": _gradle_dependencies(document),
        }

    if kind is None:
        return {"ok": False, "path": str(path),
                "error": "unrecognized build metadata (not Maven pom, NuGet nuspec "
                         "or Gradle module metadata)",
                "preview": text[:120]}

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return {"ok": False, "path": str(path), "kind": kind,
                "error": f"invalid XML: {exc}"}

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    def find_text(element: ET.Element, name: str) -> str | None:
        for child in element:
            if local(child.tag) == name and (child.text or "").strip():
                return child.text.strip()
        return None

    def children(element: ET.Element, name: str) -> list[ET.Element]:
        return [child for child in element if local(child.tag) == name]

    result: dict[str, Any] = {"ok": True, "path": str(path), "kind": kind,
                              "namespaces": sorted({
                                  child.tag.split("}")[0].lstrip("{")
                                  for child in root.iter() if "}" in child.tag})[:4]}

    if kind == "maven":
        parent = next(iter(children(root, "parent")), None)
        coordinates = {
            "group": find_text(root, "groupId")
            or (find_text(parent, "groupId") if parent is not None else None),
            "artifact": find_text(root, "artifactId"),
            "version": find_text(root, "version")
            or (find_text(parent, "version") if parent is not None else None),
            "packaging": find_text(root, "packaging"),
            "name": find_text(root, "name"),
        }
        result["coordinates"] = coordinates
        if parent is not None:
            result["parent"] = {"group": find_text(parent, "groupId"),
                                "artifact": find_text(parent, "artifactId"),
                                "version": find_text(parent, "version")}

        dependencies = []
        repositories = []
        plugins = []
        for section in children(root, "dependencies"):
            for dep in children(section, "dependency"):
                dependencies.append({
                    "group": find_text(dep, "groupId"),
                    "artifact": find_text(dep, "artifactId"),
                    "version": find_text(dep, "version"),
                    "scope": find_text(dep, "scope") or "compile",
                    "optional": (find_text(dep, "optional") or "").lower() == "true",
                })
        for section in children(root, "repositories"):
            for repo in children(section, "repository"):
                repositories.append({"id": find_text(repo, "id"),
                                     "url": find_text(repo, "url")})
        build = next(iter(children(root, "build")), None)
        if build is not None:
            for section in children(build, "plugins"):
                for plugin in children(section, "plugin"):
                    entry = {"group": find_text(plugin, "groupId"),
                             "artifact": find_text(plugin, "artifactId"),
                             "version": find_text(plugin, "version")}
                    executions = [find_text(e, "phase")
                                  for s in children(plugin, "executions")
                                  for e in children(s, "execution")]
                    if any(executions):
                        entry["phases"] = [p for p in executions if p]
                    plugins.append(entry)
        result.update({
            "dependency_count": len(dependencies),
            "dependencies": dependencies[:300],
            "repositories": repositories,
            "plugins": plugins[:60],
        })
        # A dependency resolved from a non-Central repository is worth surfacing.
        odd = [r for r in repositories
               if r.get("url") and "repo.maven.apache.org" not in r["url"]
               and "repo1.maven.org" not in r["url"]]
        if odd:
            result["custom_repositories"] = odd

    else:  # nuget nuspec
        metadata = next(iter(children(root, "metadata")), root)
        result["coordinates"] = {
            "id": find_text(metadata, "id"),
            "version": find_text(metadata, "version"),
            "authors": find_text(metadata, "authors"),
            "description": find_text(metadata, "description"),
            "project_url": find_text(metadata, "projectUrl"),
        }
        dependencies = []
        for section in children(metadata, "dependencies"):
            for group in children(section, "group"):
                for dep in children(group, "dependency"):
                    dependencies.append({
                        "id": dep.get("id"),
                        "version": dep.get("version"),
                        "target_framework": group.get("targetFramework"),
                    })
            for dep in children(section, "dependency"):
                dependencies.append({"id": dep.get("id"),
                                     "version": dep.get("version")})
        result.update({"dependency_count": len(dependencies),
                       "dependencies": dependencies[:300]})
    return result


def _gradle_dependencies(document: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for variant in document.get("variants") or []:
        for dep in variant.get("dependencies") or []:
            out.append({"group": dep.get("group"), "module": dep.get("module"),
                        "version": (dep.get("version") or {}).get("requires"),
                        "variant": variant.get("name")})
    return out[:300]


# ---------------------------------------------------------- desktop bundle
def inspect_desktop_bundle(path: str | Path) -> dict[str, Any]:
    """Describe a macOS `.app` bundle: identity, executable, declared capabilities.

    Accepts either the `.app` directory or its `Contents/Info.plist`. Reports the
    bundle identifier, version, the executable's real path and size, declared URL
    schemes (which is how an app is launched by other software), document types, and
    whether it is sandboxed or hardened.

    `CFBundleExecutable` names a file inside `Contents/MacOS`, so the bundle directory
    itself is never executable — looking for an executable at the bundle root fails on
    every real application.
    """
    target = Path(path)
    try:
        canon = guard.read_guard(target)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    info = None
    bundle_root = None
    if canon.is_dir():
        candidates = [canon / "Contents" / "Info.plist", canon / "Info.plist"]
        info = next((c for c in candidates if c.is_file()), None)
        bundle_root = canon
        if info is None:
            return {"ok": False, "path": str(canon),
                    "error": "no Contents/Info.plist — not a macOS application bundle",
                    "entries": sorted(p.name for p in canon.iterdir())[:30]}
    elif canon.is_file():
        info = canon
        # .../Foo.app/Contents/Info.plist -> Foo.app
        for parent in canon.parents:
            if parent.suffix == ".app":
                bundle_root = parent
                break
    else:
        return {"ok": False, "path": str(canon), "error": "not a file or directory"}

    try:
        raw = info.read_bytes()
        document = plistlib.loads(raw)
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        return {"ok": False, "path": str(info), "error": f"unreadable Info.plist: {exc}"}
    if not isinstance(document, dict):
        return {"ok": False, "path": str(info), "error": "Info.plist is not a dictionary"}

    result: dict[str, Any] = {
        "ok": True,
        "path": str(canon),
        "bundle": str(bundle_root) if bundle_root else None,
        "info_plist": str(info),
        "plist_format": "binary" if raw[:8] == _PLIST_MAGIC else "xml",
        "identifier": document.get("CFBundleIdentifier"),
        "name": document.get("CFBundleName"),
        "display_name": document.get("CFBundleDisplayName"),
        "version": document.get("CFBundleShortVersionString"),
        "build": document.get("CFBundleVersion"),
        "minimum_system": document.get("LSMinimumSystemVersion"),
        "kind": document.get("CFBundlePackageType"),
        "executable_name": document.get("CFBundleExecutable"),
    }

    executable = None
    if bundle_root and document.get("CFBundleExecutable"):
        candidate = bundle_root / "Contents" / "MacOS" / str(document["CFBundleExecutable"])
        if candidate.is_file():
            executable = candidate
    if executable is not None:
        result["executable"] = str(executable)
        result["executable_size"] = executable.stat().st_size
    elif document.get("CFBundleExecutable"):
        result["warning"] = ("CFBundleExecutable is declared but the file is not in "
                             "Contents/MacOS")

    # URL schemes: how other software launches this app.
    schemes = []
    for entry in document.get("CFBundleURLTypes") or []:
        if not isinstance(entry, dict):
            continue
        for scheme in entry.get("CFBundleURLSchemes") or []:
            schemes.append({"scheme": scheme,
                            "name": entry.get("CFBundleURLName")})
    if schemes:
        result["url_schemes"] = schemes[:60]

    documents = []
    for entry in document.get("CFBundleDocumentTypes") or []:
        if isinstance(entry, dict):
            documents.append({"name": entry.get("CFBundleTypeName"),
                              "role": entry.get("CFBundleTypeRole"),
                              "extensions": (entry.get("CFBundleTypeExtensions")
                                             or [])[:20]})
    if documents:
        result["document_types"] = documents[:40]

    # Security-relevant switches.
    result["sandboxed"] = "App Sandbox"
    entitlements = document.get("com.apple.security.app-sandbox")
    if isinstance(entitlements, bool):
        result["sandboxed"] = entitlements
    result["high_resolution_capable"] = bool(document.get("NSHighResolutionCapable"))
    result["allows_arbitrary_loads"] = bool(document.get("NSAllowsArbitraryLoads"))
    if document.get("NSAppleEventsUsageDescription"):
        result["sends_apple_events"] = True

    helpers = []
    if bundle_root:
        for pattern in ("Contents/Library/LoginItems/*.app",
                        "Contents/XPCServices/*.xpc",
                        "Contents/Frameworks/*.framework"):
            for found in sorted(bundle_root.glob(pattern))[:20]:
                helpers.append(found.name)
    if helpers:
        result["nested_components"] = helpers[:40]
    return result


# ---------------------------------------------------------------------- entry
def inspect(path: str | Path) -> dict[str, Any]:
    """Detect which of these three the target is, and read it."""
    try:
        canon = guard.read_guard(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if canon.is_dir() or canon.suffix == ".app" or canon.name == "Info.plist":
        if canon.is_dir() and not (canon / "Contents").is_dir() and canon.suffix != ".app":
            return {"ok": False, "path": str(canon),
                    "error": "directory is not an application bundle"}
        return inspect_desktop_bundle(canon)

    try:
        raw = _read(canon)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(canon), "error": str(exc)}

    head = raw[:8]
    stripped = raw.lstrip()[:400].lower()
    if head == _PLIST_MAGIC or stripped.startswith(b"<?xml") or \
            stripped.startswith(b"<plist") or stripped.startswith(b"<!doctype plist"):
        # Distinguish a keyed archive from an ordinary plist.
        archive = inspect_keyed_archive(canon)
        if archive.get("ok"):
            return archive
        return {"ok": False, "path": str(canon),
                "error": archive.get("error"),
                "hint": "the file is a plist but not an NSKeyedArchiver archive; "
                        "use `re formats plist` for a plain plist"}
    if stripped.startswith(b"<") or stripped.startswith(b"{"):
        jvm = inspect_jvm_metadata(canon)
        if jvm.get("ok"):
            return jvm
    return {"ok": False, "path": str(canon),
            "error": "unrecognized format (not a keyed archive, JVM/NuGet metadata "
                     "or a desktop bundle)"}
