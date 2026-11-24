"""Interface Builder (nib) decoding.

A compiled `.nib` is an NSKeyedArchiver plist, so the container decode reuses the keyed-archive
reader rather than adding a second parser for the same bytes. What a nib adds is meaning: outlets
and actions are stored as `IB*`-prefixed keys, and they say which code touches which control — an
outlet named `adminPanel` on a hidden view is a finding, and an action from a control to a method
says that control can drive that method.

Three implementation attempts were wrong, and each is pinned by a test because each produced a
plausible-looking report:

1. **Walking from `$top` alone reached one object of five.** `$top` names entry points; the document
   is the flat `$objects` table. Resolving from the root reported zero connections on a nib that
   has two.

2. **Recursing into each resolved object double-counted.** `resolve` inlines referenced objects, so
   a controller's outlet arrived both inside the controller and again at its own slot — 3
   connected objects for a nib with 2. Each `$objects` slot IS one object and the table is already
   flat, so there is nothing to descend into.

3. **Deduplicating by `id()` cannot work.** `resolve` builds a fresh dict per reference, so two
   views of one object are distinct objects to Python and `id()` never matches. The table index is
   the only stable identity an archived object has.

This is tested against nibs built to the NSKeyedArchiver structure in this file. No real `.nib`
exists on this host — no Xcode, no Interface Builder, no iOS app bundle — so what is verified is the
decode of the documented container plus the connection-derivation rules, not a byte-for-byte match
with a document Xcode wrote.
"""
from __future__ import annotations

import plistlib
import shutil
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import packaging


def _nib(objects: list) -> bytes:
    return plistlib.dumps({
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {"root": plistlib.UID(1)},
        "$objects": objects,
    }, fmt=plistlib.FMT_BINARY)


class InterfaceBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="xtnib-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)

    def _decode(self, payload: bytes, name: str = "Main.nib") -> dict:
        target = self.directory / name
        target.write_bytes(payload)
        return packaging.decode_interface_builder(str(target))

    def _controller_nib(self) -> bytes:
        return _nib([
            "$null",
            {"$classname": "NSMutableDictionary",
             "$classes": ["NSMutableDictionary", "NSDictionary", "NSObject"]},
            {"$classname": "NSWindowTemplate",
             "$classes": ["NSWindowTemplate", "NSObject"], "NSWindowName": "MainWindow"},
            # Indices are positional in `$objects`: 0 "$null", 1 dictionary, 2 window template,
            # 3 ViewController, 4 NSTableView. Writing UID(2) here pointed the controller's outlet
            # at the window template — a fixture bug that made the assertion look like a decoder
            # bug. Named indices keep it honest.
            {"$classname": "ViewController", "$classes": ["ViewController", "NSObject"],
             "IBOutlet_tableView": plistlib.UID(4),
             "IBOutgoingAction_save:": plistlib.UID(4),
             "IBIdentifier": "LoginScene"},
            {"$classname": "NSTableView", "$classes": ["NSTableView", "NSObject"],
             "IBOutlet_delegate": plistlib.UID(3), "NSIdentifier": "usersTable"},
        ])

    def test_a_nib_decodes_as_a_keyed_archive(self) -> None:
        report = self._decode(self._controller_nib())
        self.assertTrue(report["ok"])
        self.assertEqual(report["kind"], "interface-builder")
        self.assertEqual(report["archiver"], "NSKeyedArchiver")

    def test_every_class_in_the_table_is_reported(self) -> None:
        """Walking from `$top` reached one object of five and reported zero connections."""
        report = self._decode(self._controller_nib())
        self.assertIn("ViewController", report["classes"])
        self.assertIn("NSTableView", report["classes"])
        self.assertIn("NSWindowTemplate", report["classes"])

    def test_an_outlet_is_reported_with_its_target_class(self) -> None:
        report = self._decode(self._controller_nib())
        controller = next(entry for entry in report["connections"]
                          if entry["classname"] == "ViewController")
        self.assertIn("IBOutlet_tableView", controller["connections"])
        self.assertEqual(controller["connections"]["IBOutlet_tableView"]["$classname"],
                         "NSTableView")

    def test_an_action_is_reported_separately_from_an_outlet(self) -> None:
        """An outlet is a reference held; an action is a message sent. Merging them loses which
        control can drive which method, which is the question."""
        report = self._decode(self._controller_nib())
        controller = next(entry for entry in report["connections"]
                          if entry["classname"] == "ViewController")
        self.assertIn("IBOutgoingAction_save:", controller["actions"])
        self.assertNotIn("IBOutgoingAction_save:", controller["connections"])

    def test_connections_are_not_double_counted(self) -> None:
        """Recursing into resolved objects reported 3 connected objects for a nib with 2."""
        report = self._decode(self._controller_nib())
        self.assertEqual(report["connection_count"], 2,
                         [entry["classname"] for entry in report["connections"]])
        classes = [entry["classname"] for entry in report["connections"]]
        self.assertEqual(classes.count("ViewController"), 1)

    def test_each_connection_carries_its_table_index(self) -> None:
        report = self._decode(self._controller_nib())
        indices = sorted(entry["index"] for entry in report["connections"])
        self.assertEqual(indices, [3, 4])

    def test_identifiers_are_surfaced_as_labels(self) -> None:
        report = self._decode(self._controller_nib())
        controller = next(entry for entry in report["connections"]
                          if entry["classname"] == "ViewController")
        self.assertEqual(controller["labels"]["IBIdentifier"], "LoginScene")

    def test_a_document_with_no_connections_is_not_an_error(self) -> None:
        payload = _nib(["$null",
                        {"$classname": "NSView", "$classes": ["NSView", "NSObject"]}])
        report = self._decode(payload)
        self.assertTrue(report["ok"])
        self.assertEqual(report["connection_count"], 0)
        self.assertIn("NSView", report["classes"])

    def test_a_non_plist_file_reports_the_archive_error(self) -> None:
        report = self._decode(b"this is definitely not a plist", name="broken.nib")
        self.assertFalse(report["ok"])
        self.assertIn("plist", str(report.get("error")).lower())

    def test_the_flat_object_table_is_exposed(self) -> None:
        """A caller that needs every object cannot get it from `roots`."""
        target = self.directory / "table.nib"
        target.write_bytes(self._controller_nib())
        archive = packaging.inspect_keyed_archive(str(target))
        self.assertIn("objects", archive)
        self.assertEqual(len(archive["objects"]), archive["object_count"])
        for slot in archive["objects"]:
            self.assertIn("index", slot)
            self.assertIn("object", slot)

    def test_a_list_valued_connection_does_not_break_the_report(self) -> None:
        payload = _nib(["$null",
                        {"$classname": "UIView", "IBOutlet_many": [plistlib.UID(1)]}])
        report = self._decode(payload)
        self.assertTrue(report["ok"])
        entry = report["connections"][0]
        self.assertEqual(entry["connections"]["IBOutlet_many"]["_type"], "array")

    def test_a_missing_file_fails_cleanly(self) -> None:
        report = packaging.decode_interface_builder("/nonexistent/Main.nib")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
