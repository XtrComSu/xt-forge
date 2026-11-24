"""HarmonyOS `.hap` parsing, built from the documented container layout.

The breadth matrix excluded this as "requires HarmonyOS .hap packaging knowledge; not in this
engine's lane". The first clause is true and is the work, not a barrier: a `.hap` is a ZIP with
`module.json` and optionally `pack.info`, and this engine already reads ZIP-based packages. The
second clause is circular — whether it is in lane is what the audit decides.

The fixtures here are built byte by byte from that layout rather than taken from a real app,
because the point is to pin the *contract*: which key holds the bundle name, that
`requestPermissions` may hold objects or bare strings, that both `abilities` and
`extensionAbilities` carry entry points, and that an unknown `type` or `deviceTypes` value is
reported rather than dropped. A parser tested only on one real app would encode that app.

Not asserted anywhere: that this decompiles ArkTS. It does not, and the output says so.
"""
from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from xtforge.core.re import harmony


class HapCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="xthap-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def build(self, *, module: dict | None = None, pack: dict | None = None,
              extra: dict[str, bytes] | None = None, name: str = "t.hap") -> Path:
        path = Path(self.directory) / name
        with zipfile.ZipFile(path, "w") as archive:
            if module is not None:
                archive.writestr("module.json", json.dumps(module))
            if pack is not None:
                archive.writestr("pack.info", json.dumps(pack))
            for entry, payload in (extra or {}).items():
                archive.writestr(entry, payload)
        return path


class IdentityTest(HapCase):
    def test_bundle_name_and_version_come_from_pack_info(self) -> None:
        path = self.build(
            module={"name": "entry", "versionName": "9.9.9", "versionCode": 1},
            pack={"summary": {"app": {"bundleName": "com.example.app",
                                      "version": {"name": "1.2.3", "code": 42}}}})
        report = harmony.inspect_hap(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["bundle_name"], "com.example.app")
        self.assertEqual(report["version"], {"name": "1.2.3", "code": 42})

    def test_identity_falls_back_to_module_json(self) -> None:
        """A .hap built without pack.info still names itself through module.json."""
        path = self.build(module={"name": "entry", "versionName": "2.0.0", "versionCode": 7})
        report = harmony.inspect_hap(path)
        self.assertEqual(report["version"], {"name": "2.0.0", "code": 7})

    def test_a_missing_bundle_name_is_null_not_the_string_none(self) -> None:
        path = self.build(module={"name": "entry"})
        report = harmony.inspect_hap(path)
        self.assertIsNone(report["bundle_name"])


class ManifestTest(HapCase):
    def test_device_types_are_read(self) -> None:
        path = self.build(module={"name": "entry", "deviceTypes": ["phone", "tablet", "tv"]})
        self.assertEqual(harmony.inspect_hap(path)["device_types"], ["phone", "tablet", "tv"])

    def test_an_unknown_device_type_is_surfaced_not_dropped(self) -> None:
        """A newer target must not be silently discarded as if the field were absent."""
        path = self.build(module={"name": "entry", "deviceTypes": ["phone", "holo-deck"]})
        report = harmony.inspect_hap(path)
        self.assertEqual(report["device_types"], ["phone", "holo-deck"])
        self.assertEqual(report["unrecognised_device_types"], ["holo-deck"])

    def test_module_type_is_mapped_and_unknown_types_are_named(self) -> None:
        entry = self.build(module={"name": "e", "type": "entry"}, name="a.hap")
        self.assertEqual(harmony.inspect_hap(entry)["module_type"], "entry")
        strange = self.build(module={"name": "e", "type": "quantum"}, name="b.hap")
        report = harmony.inspect_hap(strange)
        self.assertEqual(report["module_type"], "quantum")
        self.assertEqual(report["unrecognised_module_type"], "quantum")

    def test_an_entry_module_without_a_type_reports_null(self) -> None:
        """Absent is not the same as "entry", and must not be guessed."""
        path = self.build(module={"name": "entry"})
        self.assertIsNone(harmony.inspect_hap(path)["module_type"])


class PermissionTest(HapCase):
    def test_permission_objects_are_read(self) -> None:
        path = self.build(module={"name": "e", "requestPermissions": [
            {"name": "ohos.permission.INTERNET", "reason": "$string:why",
             "usedScene": {"abilities": ["EntryAbility"]}},
            {"name": "ohos.permission.CAMERA"}]})
        report = harmony.inspect_hap(path)
        self.assertEqual(report["permission_count"], 2)
        names = [item["name"] for item in report["permissions"]]
        self.assertEqual(names, ["ohos.permission.INTERNET", "ohos.permission.CAMERA"])
        self.assertEqual(report["permissions"][0]["reason"], "$string:why")

    def test_a_bare_string_permission_is_accepted(self) -> None:
        """The manifest allows either shape; assuming only objects silently loses permissions."""
        path = self.build(module={"name": "e",
                                  "requestPermissions": ["ohos.permission.LOCATION"]})
        report = harmony.inspect_hap(path)
        self.assertEqual(report["permission_count"], 1)
        self.assertEqual(report["permissions"][0]["name"], "ohos.permission.LOCATION")

    def test_a_non_list_request_permissions_does_not_crash(self) -> None:
        """Found by fuzzing: `requestPermissions: 42` raised TypeError from the for loop.

        The format says this field is a list, so the code iterated it unguarded. Real manifests
        are generated by many tools and a wrong type must degrade to "none declared".
        """
        for value in (42, {"a": 1}, "ohos.permission.X", True):
            path = self.build(module={"name": "e", "requestPermissions": value},
                              name=f"p{abs(hash(str(value)))}.hap")
            report = harmony.inspect_hap(path)
            self.assertTrue(report["ok"], report.get("error"))
            if not isinstance(value, str):
                self.assertEqual(report["permission_count"], 0,
                                 f"{value!r} was not a list and must not yield permissions")

    def test_no_permissions_is_zero_not_an_error(self) -> None:
        path = self.build(module={"name": "e"})
        report = harmony.inspect_hap(path)
        self.assertEqual(report["permission_count"], 0)
        self.assertEqual(report["permissions"], [])


class AbilityTest(HapCase):
    def test_abilities_and_extensions_are_both_collected(self) -> None:
        path = self.build(module={
            "name": "e",
            "abilities": [{"name": "EntryAbility", "srcEntry": "./ets/a.ts", "exported": True}],
            "extensionAbilities": [{"name": "BackupExt", "type": "backup",
                                    "srcEntry": "./ets/b.ts"}]})
        report = harmony.inspect_hap(path)
        self.assertEqual(report["ability_count"], 2)
        kinds = {item["name"]: item["kind"] for item in report["abilities"]}
        self.assertEqual(kinds, {"EntryAbility": "ability", "BackupExt": "extension"})
        entry = report["abilities"][0]
        self.assertEqual(entry["src_entry"], "./ets/a.ts")
        self.assertTrue(entry["exported"])

    def test_exported_is_reported_as_declared_not_inferred(self) -> None:
        path = self.build(module={"name": "e",
                                  "abilities": [{"name": "A", "exported": False},
                                                {"name": "B"}]})
        report = harmony.inspect_hap(path)
        by_name = {item["name"]: item for item in report["abilities"]}
        self.assertFalse(by_name["A"]["exported"])
        self.assertIsNone(by_name["B"]["exported"],
                          "an absent exported flag must stay null, not become False")


class PayloadTest(HapCase):
    def test_bytecode_and_native_files_are_listed_with_sizes(self) -> None:
        path = self.build(module={"name": "e"},
                          extra={"ets/modules.abc": b"PANDA" + b"\x00" * 15,
                                 "libs/arm64-v8a/libapp.so": b"\x7fELF" + b"\x00" * 12})
        report = harmony.inspect_hap(path)
        self.assertEqual([item["path"] for item in report["bytecode_files"]],
                         ["ets/modules.abc"])
        self.assertEqual([item["path"] for item in report["native_files"]],
                         ["libs/arm64-v8a/libapp.so"])
        self.assertEqual(report["bytecode_files"][0]["size"], 20)

    def test_the_note_does_not_claim_decompilation(self) -> None:
        path = self.build(module={"name": "e"}, extra={"ets/modules.abc": b"PANDA"})
        report = harmony.inspect_hap(path)
        self.assertIn("not decompiled", report["note"])
        self.assertIn("disasm-native", report["note"])


class HonestyTest(HapCase):
    def test_a_non_zip_is_refused(self) -> None:
        path = Path(self.directory) / "x.hap"
        path.write_bytes(b"not a zip at all")
        report = harmony.inspect_hap(path)
        self.assertFalse(report["ok"])
        self.assertIn("not a readable ZIP", report["error"])

    def test_a_zip_without_a_manifest_is_refused_not_reported_empty(self) -> None:
        path = self.build(module=None, extra={"random.txt": b"x"})
        report = harmony.inspect_hap(path)
        self.assertFalse(report["ok"])
        self.assertIn("does not look like", report["hint"])

    def test_a_missing_file_is_refused(self) -> None:
        self.assertFalse(harmony.inspect_hap("/nonexistent/x.hap")["ok"])

    def test_malformed_json_is_treated_as_absent_rather_than_crashing(self) -> None:
        path = Path(self.directory) / "bad.hap"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("module.json", "{not json")
            archive.writestr("pack.info", json.dumps(
                {"summary": {"app": {"bundleName": "com.example.bad"}}}))
        report = harmony.inspect_hap(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["bundle_name"], "com.example.bad")
        self.assertIsNone(report["module_type"])


if __name__ == "__main__":
    unittest.main()
