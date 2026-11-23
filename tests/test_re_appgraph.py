"""Tests for the application graph reader.

The fixture is a real APK whose `AndroidManifest.xml` is genuine **Android binary XML**:
chunked, string-pool backed, with a resource map. It is built here from the AOSP layout in
`ResourceTypes.h` rather than by hand-writing bytes, so the test exercises the decoder
against the actual format instead of against a shape I found convenient.

That mattered. Building the fixture found a real bug in the reader: `ResXMLTree_attrExt`
was read as `<IIIIHHH` (22 bytes) when the struct is `ns 4, name 4, attributeStart 2,
attributeSize 2, attributeCount 2, idIndex 2, classIndex 2, styleIndex 2` — **20 bytes**.
Reading 22 bytes per element put every attribute two bytes late. The symptoms were subtle:
tags and their names decoded fine, so the manifest "worked", while every attribute came
back empty — no package name, no permissions, no exported flags. A reader that returns zero
permissions looks like an app that requests none.

The other trap is `attributeStart`. It is an offset from the start of the attrExt struct,
not from the chunk. Reading it from the chunk start is 16 bytes early and silently returns a
neighbouring element's attributes.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from xtforge.core.re import appgraph


def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = b""
    for text in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    header = 28
    strings_start = header + 4 * len(strings)
    return (struct.pack("<HHIIIIII", 0x0001, header, strings_start + len(data),
                        len(strings), 0, 0, strings_start, 0)
            + b"".join(struct.pack("<I", offset) for offset in offsets) + data)


def _attr(ns: int, name: int, raw: int, vtype: int, data: int) -> bytes:
    return struct.pack("<IIIHBBI", ns, name, raw, 8, 0, vtype, data)


def _start(name_index: int, attrs: list[bytes]) -> bytes:
    ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_index, 20, 20, len(attrs), 0, 0, 0)
    assert len(ext) == 20, "attrExt must be 20 bytes"
    body = struct.pack("<II", 1, 0xFFFFFFFF) + ext + b"".join(attrs)
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body


STRINGS = ["manifest", "package", "versionName", "versionCode", "uses-permission", "name",
           "application", "activity", "exported", "service", "android.permission.INTERNET",
           "com.example.app", "1.2.3", "42", ".MainActivity", ".SyncService",
           "android.permission.SEND_SMS", "debuggable", "true", "uses-sdk",
           "minSdkVersion", "targetSdkVersion", "provider", "com.example.Provider"]
IDX = {text: number for number, text in enumerate(STRINGS)}
NM = 0xFFFFFFFF
ATTR_NAME = 0x01010003
ATTR_EXPORTED = 0x01010010
ATTR_DEBUGGABLE = 0x0101000F


def build_manifest(exported_activity: int = 1) -> bytes:
    elements = [
        _start(IDX["manifest"], [
            _attr(NM, IDX["package"], IDX["com.example.app"], 3, IDX["com.example.app"]),
            _attr(NM, IDX["versionName"], IDX["1.2.3"], 3, IDX["1.2.3"]),
            _attr(NM, IDX["versionCode"], IDX["42"], 0x10, 42)]),
        _start(IDX["uses-permission"], [
            _attr(NM, IDX["name"], IDX["android.permission.INTERNET"], 3,
                  IDX["android.permission.INTERNET"])]),
        _start(IDX["uses-permission"], [
            _attr(NM, IDX["name"], IDX["android.permission.SEND_SMS"], 3,
                  IDX["android.permission.SEND_SMS"])]),
        _start(IDX["uses-sdk"], [
            _attr(NM, IDX["minSdkVersion"], NM, 0x10, 21),
            _attr(NM, IDX["targetSdkVersion"], NM, 0x10, 33)]),
        _start(IDX["application"], [_attr(NM, IDX["debuggable"], IDX["true"], 0x12, NM)]),
        _start(IDX["activity"], [
            _attr(NM, IDX["name"], IDX[".MainActivity"], 3, IDX[".MainActivity"]),
            _attr(NM, IDX["exported"], NM, 0x12, exported_activity)]),
        _start(IDX["service"], [
            _attr(NM, IDX["name"], IDX[".SyncService"], 3, IDX[".SyncService"])]),
    ]
    resource_map = [0] * len(STRINGS)
    resource_map[IDX["name"]] = ATTR_NAME
    resource_map[IDX["exported"]] = ATTR_EXPORTED
    resource_map[IDX["debuggable"]] = ATTR_DEBUGGABLE
    body = (_string_pool(STRINGS)
            + struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(resource_map))
            + b"".join(struct.pack("<I", rid) for rid in resource_map)
            + b"".join(elements))
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def build_apk(directory: Path, *, manifest: bytes | None = None,
              extra: dict[str, bytes] | None = None) -> Path:
    target = directory / "app.apk"
    payload = manifest if manifest is not None else build_manifest()
    contents = {
        "AndroidManifest.xml": payload,
        "classes.dex": b"dex\n035\x00" + bytes(100),
        "classes2.dex": b"dex\n035\x00" + bytes(100),
        "lib/arm64-v8a/libapp.so": b"\x7fELF" + bytes(200),
        "lib/arm64-v8a/libflutter.so": b"\x7fELF" + bytes(200),
        "lib/armeabi-v7a/libapp.so": b"\x7fELF" + bytes(200),
        "assets/flutter_assets/AssetManifest.json": b"{}",
    }
    contents.update(extra or {})
    with zipfile.ZipFile(target, "w") as archive:
        for name, blob in contents.items():
            archive.writestr(name, blob)
    return target


class ManifestDecodeTest(unittest.TestCase):
    def test_package_and_version(self) -> None:
        model = appgraph.decode_manifest(build_manifest())
        self.assertEqual(model["package"], "com.example.app")
        self.assertEqual(model["version_name"], "1.2.3")
        self.assertEqual(model["version_code"], "42")

    def test_all_permissions_are_found(self) -> None:
        """Zero permissions is also what a broken decoder returns, so assert the list."""
        model = appgraph.decode_manifest(build_manifest())
        self.assertEqual(model["permissions"],
                         ["android.permission.INTERNET", "android.permission.SEND_SMS"])

    def test_sdk_range_is_read_as_integers(self) -> None:
        """minSdkVersion is a typed int, not a string; both must survive."""
        model = appgraph.decode_manifest(build_manifest())
        self.assertEqual(model["min_sdk"], 21)
        self.assertEqual(model["target_sdk"], 33)

    def test_component_names_are_resolved(self) -> None:
        model = appgraph.decode_manifest(build_manifest())
        names = [entry["name"] for entry in model["components"]]
        self.assertIn(".MainActivity", names)
        self.assertIn(".SyncService", names)

    def test_exported_flag_is_read_from_the_resource_map(self) -> None:
        """`android:exported` is identified by resource ID, not only by name."""
        model = appgraph.decode_manifest(build_manifest(exported_activity=1))
        activity = next(entry for entry in model["components"]
                        if entry["kind"] == "activity")
        self.assertIs(activity["exported"], True)

    def test_unexported_activity_is_not_flagged(self) -> None:
        model = appgraph.decode_manifest(build_manifest(exported_activity=0))
        activity = next(entry for entry in model["components"]
                        if entry["kind"] == "activity")
        self.assertIs(activity["exported"], False)

    def test_exported_without_permission_is_surfaced(self) -> None:
        model = appgraph.decode_manifest(build_manifest(exported_activity=1))
        risky = model["exported_without_permission"]
        self.assertEqual(len(risky), 1)
        self.assertEqual(risky[0]["name"], ".MainActivity")

    def test_component_counts(self) -> None:
        model = appgraph.decode_manifest(build_manifest())
        self.assertEqual(model["component_counts"]["activity"], 1)
        self.assertEqual(model["component_counts"]["service"], 1)
        self.assertEqual(model["component_counts"]["provider"], 0)

    def test_application_flags(self) -> None:
        model = appgraph.decode_manifest(build_manifest())
        self.assertIs(model["application"]["debuggable"], True)

    def test_text_xml_is_rejected(self) -> None:
        """A plain-text manifest must not be parsed as binary XML."""
        with self.assertRaises(appgraph.GraphError):
            appgraph.decode_manifest(b'<?xml version="1.0"?><manifest/>')

    def test_truncated_manifest_does_not_raise(self) -> None:
        blob = build_manifest()
        for cut in (8, 20, 100, len(blob) // 2):
            try:
                appgraph.decode_manifest(blob[:cut])
            except appgraph.GraphError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"cut={cut} raised {type(exc).__name__}: {exc}")

    def test_empty_input_is_rejected(self) -> None:
        with self.assertRaises(appgraph.GraphError):
            appgraph.decode_manifest(b"")


class ApplicationGraphTest(unittest.TestCase):
    def test_android_apk_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = appgraph.inspect_application(build_apk(Path(tmp)))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["platforms"], ["android"])
        self.assertEqual(report["manifest"]["package"], "com.example.app")

    def test_dex_files_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = appgraph.inspect_application(build_apk(Path(tmp)))
        self.assertEqual(report["dex_count"], 2)

    def test_abis_are_derived_from_library_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = appgraph.inspect_application(build_apk(Path(tmp)))
        self.assertEqual(report["abis"], ["arm64-v8a", "armeabi-v7a"])

    def test_flutter_is_detected_from_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = appgraph.inspect_application(build_apk(Path(tmp)))
        self.assertEqual(report["primary_runtime"], "flutter")
        flutter = next(entry for entry in report["runtimes"]
                       if entry["runtime"] == "flutter")
        self.assertEqual(flutter["confidence"], "high")
        self.assertIn("libflutter.so", flutter["markers"])

    def test_unity_is_detected_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = build_apk(Path(tmp), extra={
                "lib/arm64-v8a/libil2cpp.so": b"\x7fELF" + bytes(64),
                "assets/bin/Data/Managed/etc": b"x",
                "lib/arm64-v8a/libunity.so": b"\x7fELF" + bytes(64)})
            report = appgraph.inspect_application(target)
        runtimes = {entry["runtime"] for entry in report["runtimes"]}
        self.assertIn("unity", runtimes)

    def test_risk_flags_are_present_for_exported_components(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = appgraph.inspect_application(build_apk(Path(tmp)))
        self.assertIn("risk_flags", report)
        self.assertIn(".MainActivity", report["risk_flags"][0])

    def test_zip_without_an_app_container_is_not_claimed_as_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("readme.txt", b"hello")
            report = appgraph.inspect_application(target)
        self.assertTrue(report["ok"])
        self.assertEqual(report["platforms"], ["unknown"])
        self.assertIn("note", report)

    def test_apple_plist(self) -> None:
        import plistlib
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "Info.plist"
            target.write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.ios",
                "CFBundleName": "Example",
                "MinimumOSVersion": "15.0",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example", "ex"]}],
            }))
            report = appgraph.inspect_application(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["platforms"], ["apple"])
        self.assertEqual(report["bundle_id"], "com.example.ios")
        self.assertEqual(report["url_schemes"], ["example", "ex"])

    def test_broken_plist_reports_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.plist"
            target.write_bytes(b"not a plist at all")
            report = appgraph.inspect_application(target)
        self.assertFalse(report["ok"])

    def test_missing_file(self) -> None:
        report = appgraph.inspect_application("/nonexistent/app.apk")
        self.assertFalse(report["ok"])

    def test_unknown_container_is_rejected(self) -> None:
        report = appgraph.inspect_application("/bin/ls")
        self.assertFalse(report["ok"])

    def test_result_is_json_serialisable(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as tmp:
            report = appgraph.inspect_application(build_apk(Path(tmp)))
        json.dumps(report)

    def test_random_zip_never_raises(self) -> None:
        import random
        random.seed(4242)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(8):
                target = root / f"r{index}.apk"
                with zipfile.ZipFile(target, "w") as archive:
                    archive.writestr(
                        "AndroidManifest.xml",
                        bytes(random.randrange(256)
                              for _ in range(random.randint(0, 600))))
                try:
                    appgraph.inspect_application(target)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
