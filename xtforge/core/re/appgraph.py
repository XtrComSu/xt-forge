"""Application graph: project an app bundle into features, surfaces and entry points.

WHY: "what does this app actually DO" is a different question from "what is in this binary".
An APK with 4 dex files, a manifest and six native libraries answers nothing on its own.
The graph answers: which permissions are requested, which components are exported, which
native libraries back which ABI, where the code entry points are, and — for a Flutter or
Unity or React Native app — which runtime is really running the show.

This is deliberately an *inventory* graph, not an inferred feature graph. Each node is
something read out of the bundle. It does not guess "this is a banking trojan because it
has SMS permissions"; that is a judgement, and a tool that makes it silently is worse than
one that shows the evidence and lets the analyst judge.

What it reads:

  Android (.apk/.aab)  manifest XML (binary, decoded in place), dex files, native libs per
                       ABI, asset tree, signature blocks, and the runtime markers that
                       identify Flutter / Unity / React Native / Cordova
  Apple (.ipa/.app)    Info.plist, Mach-O binaries, frameworks, embedded provisioning
  Managed (.dll/.exe)  assembly references and the il2cpp indirection, if present

The manifest is Android binary XML (chunked, string-pool backed), not text. Decoding it
matters: a naive regex over the raw bytes finds permission strings — which is what the older
`inspect_apk` does — but it cannot tell an exported component from a private one, because
`android:exported` is a *typed attribute value* in a resource map, not a substring.
"""
from __future__ import annotations

import plistlib
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_ENTRIES = 20000
MAX_MANIFEST = 16 * 1024 * 1024

# Android binary XML chunk types (frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h)
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_FIRST_CHUNK_TYPE = 0x0100
RES_XML_LAST_CHUNK_TYPE = 0x017F
UTF8_FLAG = 0x00000100
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# android:exported and friends are identified by resource ID, because the attribute name
# string is often absent from the pool in obfuscated manifests.
ATTR_EXPORTED = 0x01010010
ATTR_NAME = 0x01010003
ATTR_LABEL = 0x01010001
ATTR_PERMISSION = 0x01010006
ATTR_DEBUGGABLE = 0x0101000F
ATTR_ALLOW_BACKUP = 0x0101002D

COMPONENT_TAGS = ("activity", "service", "receiver", "provider", "activity-alias")

RUNTIME_MARKERS = {
    "flutter": ("libflutter.so", "libapp.so", "flutter_assets/"),
    "unity": ("libunity.so", "libil2cpp.so", "assets/bin/Data/"),
    "react-native": ("libhermes.so", "index.android.bundle", "libreact_native"),
    "cordova": ("assets/www/cordova.js", "assets/www/cordova_plugins.js"),
    "xamarin": ("libmonodroid.so", "assemblies/", "libxamarin-app.so"),
    "cocos": ("libcocos2d", "assets/src/"),
    "unreal": ("libUE4.so", "libUnreal.so", "assets/UE4Game/"),
}


class GraphError(Exception):
    """Raised when a bundle cannot be read as an application."""


# --------------------------------------------------------------------------- binary XML

def _string_pool(blob: bytes, start: int, size: int) -> list[str]:
    """Decode a ResStringPool chunk into its strings.

    Two encodings live here: UTF-16LE (the default) and UTF-8, signalled by
    UTF8_FLAG in the pool flags. A UTF-8 pool stores *two* length fields per string
    (character count then byte count), so reading it as UTF-16 yields mojibake that still
    looks like text — which is how a decoder silently produces garbage names.
    """
    if size < 28:
        return []
    _type, header_size, _chunk_size, string_count, _style_count, flags, strings_start, \
        _styles_start = struct.unpack_from("<HHIIIIII", blob, start)
    if header_size < 28 or header_size > size:
        return []
    offsets = []
    for index in range(string_count):
        position = start + header_size + index * 4
        if position + 4 > len(blob):
            break
        (offset,) = struct.unpack_from("<I", blob, position)
        offsets.append(offset)
    utf8 = bool(flags & UTF8_FLAG)
    base = start + strings_start
    strings: list[str] = []
    for offset in offsets:
        cursor = base + offset
        try:
            if utf8:
                # char length, then byte length, each 1 or 2 bytes.
                _chars, cursor = _read_len8(blob, cursor)
                byte_len, cursor = _read_len8(blob, cursor)
                strings.append(blob[cursor:cursor + byte_len].decode("utf-8", "replace"))
            else:
                char_len, cursor = _read_len16(blob, cursor)
                strings.append(blob[cursor:cursor + char_len * 2].decode(
                    "utf-16-le", "replace"))
        except (struct.error, IndexError):
            strings.append("")
    return strings


def _read_len8(blob: bytes, cursor: int) -> tuple[int, int]:
    first = blob[cursor]
    if first & 0x80:
        return ((first & 0x7F) << 8) | blob[cursor + 1], cursor + 2
    return first, cursor + 1


def _read_len16(blob: bytes, cursor: int) -> tuple[int, int]:
    (first,) = struct.unpack_from("<H", blob, cursor)
    if first & 0x8000:
        (second,) = struct.unpack_from("<H", blob, cursor + 2)
        return ((first & 0x7FFF) << 16) | second, cursor + 4
    return first, cursor + 2


def decode_manifest(blob: bytes) -> dict[str, Any]:
    """Decode Android binary XML (AndroidManifest.xml) into tags and attributes.

    Returns the components with their attributes resolved, because the questions that
    matter — is this exported, does it have a permission guard — are attribute lookups, not
    substring matches.
    """
    if len(blob) < 8:
        raise GraphError("manifest is shorter than an XML chunk header")
    (chunk_type, header_size, total) = struct.unpack_from("<HHI", blob, 0)
    if chunk_type != RES_XML_TYPE:
        raise GraphError(f"not Android binary XML (chunk type 0x{chunk_type:04x})")

    strings: list[str] = []
    resource_ids: list[int] = []
    elements: list[dict[str, Any]] = []

    cursor = header_size
    limit = min(total, len(blob))
    while cursor + 8 <= limit:
        (ctype, chsize, csize) = struct.unpack_from("<HHI", blob, cursor)
        if csize < 8 or cursor + csize > limit:
            break
        if ctype == RES_STRING_POOL_TYPE:
            strings = _string_pool(blob, cursor, csize)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            count = (csize - chsize) // 4
            for index in range(count):
                (rid,) = struct.unpack_from("<I", blob, cursor + chsize + index * 4)
                resource_ids.append(rid)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            element = _decode_start_element(blob, cursor, chsize, strings, resource_ids)
            if element:
                elements.append(element)
        cursor += csize

    return _project_manifest(elements)


def _decode_start_element(blob: bytes, cursor: int, header_size: int,
                          strings: list[str], resource_ids: list[int]) -> dict | None:
    """Decode one START_ELEMENT chunk.

    Layout after the chunk header: lineNumber, comment, ns, name,
    attributeStart, attributeSize, attributeCount, idIndex, classIndex, styleIndex.
    """
    try:
        # ResXMLTree_node (line 4, comment 4) then ResXMLTree_attrExt:
        # ns 4, name 4, attributeStart 2, attributeSize 2, attributeCount 2,
        # idIndex 2, classIndex 2, styleIndex 2 — 20 bytes, per AOSP ResourceTypes.h.
        (_line, _comment, _ns, name_index, attr_start, attr_size,
         attr_count, _id_index, _class_index,
         _style_index) = struct.unpack_from("<IIIIHHHHHH", blob, cursor + 8)
    except struct.error:
        return None
    if name_index >= len(strings):
        return None
    tag = strings[name_index]
    # `attributeStart` is measured from the START of ResXMLTree_attrExt, which begins
    # right after the 16-byte ResXMLTree_node (8-byte chunk header + line + comment).
    # Reading it from the chunk start lands 16 bytes early and every attribute decodes as
    # a neighbour's bytes — tags still appear, so the failure looks like "no attributes".
    base = cursor + header_size + attr_start
    attributes: dict[str, Any] = {}
    by_id: dict[int, Any] = {}
    for index in range(attr_count):
        position = base + index * attr_size
        if position + 20 > len(blob):
            break
        (ns_i, name_i, raw_i, _vsize, _res0, vtype, vdata) = struct.unpack_from(
            "<IIIHBBI", blob, position)
        attr_name = strings[name_i] if name_i < len(strings) else ""
        value = _typed_value(strings, raw_i, vtype, vdata)
        res_id = resource_ids[name_i] if name_i < len(resource_ids) else 0
        if attr_name:
            attributes[attr_name] = value
        if res_id:
            by_id[res_id] = value
    return {"tag": tag, "attrs": attributes, "by_id": by_id}


def _typed_value(strings: list[str], raw_index: int, vtype: int, data: int) -> Any:
    """Resolve an attribute's value, preferring the typed value over the raw string.

    A manifest can carry a `raw` presentation string that disagrees with its typed data —
    by author error or by deliberate obfuscation. Returning `raw` first means a manifest
    can claim `android:exported="false"` in the string while the typed boolean says true,
    and the reader would report the safe-looking answer. The typed value is what the
    platform actually uses, so it wins.
    """
    if vtype == TYPE_INT_BOOLEAN:
        return bool(data)
    if vtype == TYPE_STRING:
        index = data if data < len(strings) else raw_index
        return strings[index] if 0 <= index < len(strings) else ""
    if vtype == TYPE_INT_HEX:
        return f"0x{data:x}"
    if vtype == TYPE_INT_DEC:
        return data
    # Unknown type: the raw string, if the pool has one, is the only readable form.
    if raw_index != 0xFFFFFFFF and raw_index < len(strings):
        return strings[raw_index]
    return data


def _project_manifest(elements: list[dict]) -> dict[str, Any]:
    """Turn decoded elements into the manifest model an analyst wants."""
    package = version_name = version_code = ""
    permissions: list[str] = []
    features: list[str] = []
    components: list[dict] = []
    application: dict[str, Any] = {}
    sdk_min = sdk_target = None
    deep_links: list[str] = []

    for element in elements:
        tag, attrs, by_id = element["tag"], element["attrs"], element["by_id"]
        if tag == "manifest":
            package = attrs.get("package", "")
            version_name = attrs.get("versionName", "")
            code = attrs.get("versionCode", "")
            version_code = str(code) if code != "" else ""
        elif tag == "uses-permission" or tag == "uses-permission-sdk-23":
            name = by_id.get(ATTR_NAME) or attrs.get("name")
            if name:
                permissions.append(str(name))
        elif tag == "uses-feature":
            name = by_id.get(ATTR_NAME) or attrs.get("name")
            if name:
                features.append(str(name))
        elif tag == "application":
            application = {
                "debuggable": by_id.get(ATTR_DEBUGGABLE, attrs.get("debuggable")),
                "allowBackup": by_id.get(ATTR_ALLOW_BACKUP, attrs.get("allowBackup")),
                "label": by_id.get(ATTR_LABEL) or attrs.get("label"),
            }
        elif tag in COMPONENT_TAGS:
            name = by_id.get(ATTR_NAME) or attrs.get("name") or ""
            exported = by_id.get(ATTR_EXPORTED)
            if exported is None:
                exported = attrs.get("exported")
            permission = by_id.get(ATTR_PERMISSION) or attrs.get("permission")
            components.append({
                "kind": tag,
                "name": str(name),
                "exported": bool(exported) if exported is not None else None,
                "permission": str(permission) if permission else None,
            })
        elif tag == "uses-sdk":
            sdk_min = attrs.get("minSdkVersion", sdk_min)
            sdk_target = attrs.get("targetSdkVersion", sdk_target)
        elif tag == "data":
            value = attrs.get("scheme") or attrs.get("host") or attrs.get("path")
            if value:
                deep_links.append(str(value))

    # An unguarded exported component is the finding an analyst wants surfaced, not buried.
    risky = [entry for entry in components
             if entry["exported"] and not entry["permission"]]
    return {
        "package": package,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": sdk_min,
        "target_sdk": sdk_target,
        "permissions": sorted(set(permissions)),
        "features": sorted(set(features)),
        "components": components,
        "component_counts": {kind: sum(1 for c in components if c["kind"] == kind)
                             for kind in COMPONENT_TAGS},
        "exported_without_permission": risky,
        "application": application,
        "deep_link_schemes": sorted(set(deep_links)),
        "tag_count": len(elements),
    }


# --------------------------------------------------------------------------- Android

def _detect_runtimes(names: list[str]) -> list[dict[str, Any]]:
    found = []
    for runtime, markers in RUNTIME_MARKERS.items():
        hits = [marker for marker in markers
                if any(marker in name for name in names)]
        if hits:
            found.append({"runtime": runtime, "markers": hits,
                          "confidence": "high" if len(hits) > 1 else "medium"})
    return sorted(found, key=lambda entry: -len(entry["markers"]))


def inspect_application(path: str | Path, *, limit: int = 200) -> dict[str, Any]:
    """Project an application bundle into its components, code and runtime."""
    try:
        canon = guard.read_guard(path)
    except Denied as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}
    if not canon.is_file():
        return {"ok": False, "path": str(path), "error": "not a regular file"}

    suffix = canon.suffix.lower()
    if zipfile.is_zipfile(canon):
        return _graph_zip(canon, limit=limit)
    if suffix in (".plist",):
        return _graph_plist(canon, limit=limit)
    if suffix in (".dll", ".exe") or canon.read_bytes()[:2] == b"MZ":
        return _graph_managed(canon, limit=limit)
    return {"ok": False, "path": str(canon),
            "error": f"unrecognised application container ({suffix or 'no suffix'}); "
                     f"expected a zip-based bundle (.apk/.ipa/.aab), a .plist, or a "
                     f"managed assembly"}


def _graph_zip(canon: Path, *, limit: int) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(canon, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        return {"ok": False, "path": str(canon), "error": f"cannot read archive: {exc}"}
    with archive:
        names = archive.namelist()[:MAX_ENTRIES]
        platforms: list[str] = []
        manifest: dict[str, Any] | None = None
        manifest_error = ""
        if "AndroidManifest.xml" in names:
            platforms.append("android")
            try:
                blob = archive.read("AndroidManifest.xml")[:MAX_MANIFEST]
                manifest = decode_manifest(blob)
            except (GraphError, KeyError, zipfile.BadZipFile, struct.error) as exc:
                manifest_error = str(exc)
        if any(name.startswith("Payload/") or name == "Info.plist" for name in names):
            platforms.append("apple")

        dex = [name for name in names if name.endswith(".dex")]
        libs = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        abis = sorted({name.split("/")[1] for name in libs if name.count("/") >= 2})
        assets = [name for name in names
                  if name.startswith(("assets/", "res/raw/", "Payload/"))
                  and not name.endswith("/")]
        runtimes = _detect_runtimes(names)

        result: dict[str, Any] = {
            "ok": True,
            "path": str(canon),
            "kind": "application-graph",
            "container": "zip",
            "platforms": platforms or ["unknown"],
            "entry_count": len(names),
            "dex_files": dex[:limit],
            "dex_count": len(dex),
            "native_libraries": libs[:limit],
            "native_library_count": len(libs),
            "abis": abis,
            "asset_count": len(assets),
            "runtimes": runtimes,
            "primary_runtime": runtimes[0]["runtime"] if runtimes else None,
            "manifest": manifest,
        }
        if manifest and manifest.get("exported_without_permission"):
            result["risk_flags"] = [
                f"{entry['kind']} {entry['name']} is exported with no permission guard"
                for entry in manifest["exported_without_permission"][:limit]
            ]
        if manifest_error:
            result["manifest_error"] = manifest_error
        if not platforms:
            result["note"] = ("no AndroidManifest.xml and no Apple payload found; this is a "
                              "zip archive but not a recognised application bundle")
        return result


def _graph_plist(canon: Path, *, limit: int) -> dict[str, Any]:
    raw = canon.read_bytes()
    try:
        data = plistlib.loads(raw)
    except Exception as exc:  # noqa: BLE001 - plistlib raises several types
        return {"ok": False, "path": str(canon), "error": f"cannot parse plist: {exc}"}
    if not isinstance(data, dict):
        return {"ok": False, "path": str(canon), "error": "plist root is not a dictionary"}
    schemes = []
    for entry in data.get("CFBundleURLTypes", []) or []:
        schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    return {
        "ok": True,
        "path": str(canon),
        "kind": "application-graph",
        "container": "plist",
        "platforms": ["apple"],
        "bundle_id": data.get("CFBundleIdentifier"),
        "bundle_name": data.get("CFBundleName"),
        "version": data.get("CFBundleShortVersionString"),
        "min_os": data.get("MinimumOSVersion"),
        "executable": data.get("CFBundleExecutable"),
        "url_schemes": schemes[:limit],
        "document_types": [
            entry.get("CFBundleTypeName") for entry in data.get("CFBundleDocumentTypes", []) or []
            if entry.get("CFBundleTypeName")][:limit],
    }


def _graph_managed(canon: Path, *, limit: int) -> dict[str, Any]:
    """A .NET assembly: list its references and look for the il2cpp indirection."""
    from . import managed as managed_module
    try:
        report = managed_module.inspect_managed_assembly(canon)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "path": str(canon), "error": str(exc)}
    if not report.get("ok"):
        return {"ok": False, "path": str(canon),
                "error": report.get("error") or "not a managed assembly"}
    return {
        "ok": True,
        "path": str(canon),
        "kind": "application-graph",
        "container": "managed-assembly",
        "platforms": ["managed"],
        "assembly": report.get("assembly_name"),
        "references": (report.get("references") or [])[:limit],
        "reference_count": len(report.get("references") or []),
        "uses_il2cpp": any("il2cpp" in str(ref).lower()
                           for ref in report.get("references") or []),
    }


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_application(path, **kwargs)
