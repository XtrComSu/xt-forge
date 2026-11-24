"""Android binary manifest decoding, checked against the real APK on this host.

The defect this replaces was not a parsing bug in the ordinary sense. `inspect_apk` scanned the
raw manifest bytes for `android\\.permission\\.[A-Z0-9_]+` and returned every match. On the real
APK that returned **nothing at all**, because an Android manifest's string pool is UTF-16LE and
those bytes never appear contiguously. The Go hub had the same scanner and returned **five**
permissions for a manifest that declares four, because
`android.permission.BIND_QUICK_SETTINGS_TILE` also appears as the value of a *service* attribute —
a restriction the app places on callers, not a permission it requests.

So the same idea under-reported in one implementation and over-reported in the other, and both
looked plausible. Neither could ever see a component, an exported flag, or any attribute whose
value is typed as an integer or a boolean, because those have no string in the file to match.

The tests below assert against the real package where possible, and against independent byte
structure where not. The cross-implementation check is the strongest one available: two decoders,
written separately in two languages, must produce identical answers.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

from xtforge.core.re import axml, runtimes

APK = Path.home() / "XT-OSS-Exynos9611/flash/XtStatus.apk"
ROOT = Path(__file__).resolve().parent.parent


def python_manifest() -> dict:
    return axml.inspect_manifest(APK)


@unittest.skipUnless(APK.is_file(), "needs a real APK on this host")
class RealPackageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = python_manifest()

    def test_the_manifest_decodes(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))

    def test_package_identity_is_read(self) -> None:
        self.assertEqual(self.report["package"], "os.xt.status")
        self.assertEqual(self.report["version_name"], "1.2")

    def test_version_code_is_the_typed_integer_not_a_pool_string(self) -> None:
        """`versionCode` has no string in the file: it exists only as a typed 4-byte value.

        This is the assertion a byte scanner cannot satisfy even in principle.
        """
        raw = zipfile.ZipFile(APK).read("AndroidManifest.xml")
        self.assertNotIn(b"1.2", raw.replace(b"1\x00.\x002", b""),
                         "versionName should not appear as plain UTF-8")
        self.assertEqual(self.report["version_code"], "3")

    def test_permissions_are_exactly_the_declared_ones(self) -> None:
        """Four, and notably not BIND_QUICK_SETTINGS_TILE, which the Go scraper added."""
        expected = [
            "android.permission.BLUETOOTH",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
        ]
        self.assertEqual(self.report["permissions"], expected)
        self.assertNotIn("android.permission.BIND_QUICK_SETTINGS_TILE",
                         self.report["permissions"],
                         "a service's required permission was reported as requested")

    def test_the_service_permission_is_still_reported_on_the_service(self) -> None:
        """Dropping it from `permissions` must not drop it from the component."""
        services = self.report["components"]["service"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["permission"],
                         "android.permission.BIND_QUICK_SETTINGS_TILE")

    def test_components_and_export_state(self) -> None:
        components = self.report["components"]
        self.assertEqual(len(components["activity"]), 2)
        self.assertEqual(len(components["service"]), 1)
        names = [c["name"] for c in components["activity"]]
        self.assertIn(".StatusActivity", names)
        for component in components["activity"] + components["service"]:
            self.assertTrue(component["exported"], component["name"])
            self.assertEqual(component["exported_source"], "declared")

    def test_intent_filters_are_attributed_to_their_component(self) -> None:
        by_name = {c["name"]: c for c in self.report["components"]["activity"]}
        self.assertEqual(by_name[".StatusActivity"]["intent_filters"], 1)
        self.assertEqual(by_name[".CmfBudsActivity"]["intent_filters"], 2)
        self.assertIn("android.intent.category.LAUNCHER",
                      by_name[".StatusActivity"]["categories"])

    def test_uses_sdk_is_read(self) -> None:
        self.assertEqual(self.report["uses_sdk"].get("minSdkVersion"), "34")
        self.assertEqual(self.report["uses_sdk"].get("targetSdkVersion"), "36")

    def test_the_python_fallback_reports_permissions(self) -> None:
        """The function that returned `permissions: []` for this package."""
        report = runtimes.inspect_apk(APK)
        self.assertEqual(len(report["permissions"]), 4,
                         f"the fallback reported {report['permissions']}")
        self.assertEqual(report["package"], "os.xt.status")
        self.assertIn("activity", report["components"])


@unittest.skipUnless(APK.is_file(), "needs a real APK on this host")
class ResourceTableTest(unittest.TestCase):
    def test_arsc_resolves_a_string_reference(self) -> None:
        """`label="@string/app_name"` holds only an id; the text lives in resources.arsc."""
        raw = zipfile.ZipFile(APK).read("resources.arsc")
        resources = axml.parse_arsc(raw)
        self.assertTrue(resources, "no resources resolved")
        self.assertIn("0x7f020000", {f"{key:#010x}" for key in resources})
        self.assertIn("app_name=XT Status",
                      next(value for key, value in resources.items() if key == 0x7F020000))

    def test_the_reference_in_the_manifest_is_the_one_resolved(self) -> None:
        """Bind the two: the id the manifest carries must be a key in the table."""
        raw_manifest = zipfile.ZipFile(APK).read("AndroidManifest.xml")
        resources = axml.parse_arsc(zipfile.ZipFile(APK).read("resources.arsc"))
        parsed = axml.parse_manifest(raw_manifest, resources)
        application = parsed["tree"]["children"][-1]
        self.assertEqual(application["tag"], "application")
        label = application["attributes"].get("label")
        self.assertIsInstance(label, str)
        self.assertIn("app_name", label, f"label did not resolve to a string: {label!r}")

    def test_a_non_table_is_not_mistaken_for_one(self) -> None:
        self.assertEqual(axml.parse_arsc(b"\x00" * 64), {})
        self.assertEqual(axml.parse_arsc(b""), {})


class MalformedInputTest(unittest.TestCase):
    def test_wrong_magic(self) -> None:
        with self.assertRaises(axml.AxmlError):
            axml.parse_manifest(b"\x01\x00\x08\x00" + b"\x00" * 8)

    def test_empty(self) -> None:
        with self.assertRaises(axml.AxmlError):
            axml.parse_manifest(b"")

    def test_zero_size_chunk_cannot_loop_forever(self) -> None:
        blob = (b"\x03\x00\x08\x00" + (16).to_bytes(4, "little")
                + b"\x01\x00\x1c\x00" + (0).to_bytes(4, "little") + b"\x00" * 4)
        with self.assertRaises(axml.AxmlError):
            axml.parse_manifest(blob)

    def test_a_lying_string_count_does_not_exhaust_memory(self) -> None:
        blob = bytearray(b"\x03\x00\x08\x00" + (12).to_bytes(4, "little"))
        blob += b"\x01\x00\x1c\x00" + (28).to_bytes(4, "little")
        blob += (0x7FFFFFFF).to_bytes(4, "little")  # string count
        blob += b"\x00" * 12
        with self.assertRaises(axml.AxmlError):
            axml.parse_manifest(bytes(blob))

    def test_inspect_manifest_refuses_a_non_zip(self) -> None:
        report = axml.inspect_manifest("/etc/hostname")
        self.assertFalse(report["ok"])

    def test_truncation_every_seven_bytes_never_crashes(self) -> None:
        """A hostile or damaged manifest must fail cleanly, not raise something unexpected."""
        if not APK.is_file():
            self.skipTest("needs the real APK")
        raw = zipfile.ZipFile(APK).read("AndroidManifest.xml")
        for cut in range(0, len(raw), 7):
            try:
                parsed = axml.parse_manifest(raw[:cut])
            except axml.AxmlError:
                continue
            # Anything that parses must be structurally sane, not invented.
            self.assertIsInstance(parsed["elements"], int)
            self.assertGreaterEqual(parsed["elements"], 0)


@unittest.skipUnless(APK.is_file(), "needs a real APK on this host")
class CrossImplementationTest(unittest.TestCase):
    """Two decoders, two languages, one answer.

    This is the check with the most force: the Python decoder and the Go hub were written
    separately, so agreeing on every field is not something a shared misreading would produce.
    """

    def test_both_decoders_agree_on_every_field(self) -> None:
        # `./bin/xtforge` goes through the Rust launcher and the Go hub — which is the whole
        # point, since the hub is the decoder with the over-reporting bug. `python -m xtforge.cli`
        # reaches only the Python fallback and would let this test pass while the shipped binary
        # was still wrong; it skipped for exactly that reason until the launcher was used.
        launcher = ROOT / "bin" / "xtforge"
        if not launcher.is_file():
            self.skipTest("no launcher binary in this checkout")
        completed = subprocess.run([str(launcher), "re", "apk", str(APK), "--json"],
                                   capture_output=True, text=True, cwd=str(ROOT), timeout=180)
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            self.fail(f"the launcher did not produce JSON: {completed.stdout[:200]!r} "
                      f"{completed.stderr[:200]!r}")
        go = payload.get("manifest")
        self.assertIsNotNone(
            go, "the shipped binary returned no decoded manifest; the Go hub is not in use or "
                "was not rebuilt, so this check cannot vouch for what users run")
        python = python_manifest()

        self.assertEqual(python["permissions"], go["Permissions"])
        self.assertEqual(python["version_code"], go["VersionCode"])
        self.assertEqual(python["version_name"], go["VersionName"])
        self.assertEqual(python["package"], go["Package"])
        self.assertEqual(python["uses_sdk"].get("minSdkVersion"), go["MinSDK"])
        self.assertEqual(python["uses_sdk"].get("targetSdkVersion"), go["TargetSDK"])

        python_components = sorted(
            (c["name"], c["exported"], c["permission"] or "")
            for group in python["components"].values() for c in group)
        go_components = sorted((c["Name"], c["Exported"], c["Permission"] or "")
                               for c in go["Components"])
        self.assertEqual(python_components, go_components)


if __name__ == "__main__":
    unittest.main()
