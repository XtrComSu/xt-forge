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


class BytesInsteadOfPathTest(unittest.TestCase):
    """A caller holding an archive in memory must not have to write it to disk first.

    `inspect_electron_fuses` has accepted bytes since it was written. These two did not, and the
    failure was not merely an inconvenience — passing bytes was treated as a *path*, so the report
    read:

        not a regular file: b'<?xml version="1.0"…'

    a missing-file diagnosis handed to someone who never passed a filename.
    """

    def _archive(self) -> bytes:
        import plistlib
        U = plistlib.UID

        def convert(node):
            if isinstance(node, plistlib.UID):
                return {"CF$UID": node.data}
            if isinstance(node, dict):
                return {key: convert(value) for key, value in node.items()}
            if isinstance(node, list):
                return [convert(value) for value in node]
            return node

        return plistlib.dumps(convert({
            "$archiver": "NSKeyedArchiver", "$version": 100000,
            "$objects": ["$null", {"$classname": "NSWindowTemplate",
                                   "NSWindow_Name": "prefs"}],
            "$top": {"root": U(1)},
        }), fmt=plistlib.FMT_XML)

    def test_the_archive_decoder_accepts_bytes(self) -> None:
        from xtforge.core.re import packaging
        report = packaging.inspect_keyed_archive(self._archive())
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["path"], "<bytes>")

    def test_the_nib_decoder_accepts_bytes(self) -> None:
        from xtforge.core.re import packaging
        report = packaging.decode_interface_builder(self._archive())
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["classes"], ["NSWindowTemplate"])

    def test_bytes_and_the_same_bytes_on_disk_agree(self) -> None:
        import tempfile
        from pathlib import Path
        from xtforge.core.re import packaging
        blob = self._archive()
        directory = tempfile.mkdtemp(prefix="xtnibbytes-")
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        path = Path(directory) / "M.nib"
        path.write_bytes(blob)
        from_bytes = packaging.decode_interface_builder(blob)
        from_file = packaging.decode_interface_builder(path)
        self.assertEqual(from_bytes["classes"], from_file["classes"])
        self.assertEqual(from_bytes["connection_count"], from_file["connection_count"])
        self.assertEqual(from_file["path"], str(path))

    def test_garbage_bytes_report_a_parse_error_not_a_path_error(self) -> None:
        from xtforge.core.re import packaging
        report = packaging.decode_interface_builder(b"garbage")
        self.assertFalse(report["ok"])
        self.assertIn("plist", report["error"].lower())
        self.assertNotIn("regular file", report["error"])

    def test_the_bytes_label_is_not_the_whole_blob(self) -> None:
        """Echoing a multi-kilobyte plist into the `path` field makes the report unreadable."""
        from xtforge.core.re import packaging
        blob = self._archive()
        report = packaging.decode_interface_builder(blob)
        self.assertEqual(report["path"], "<bytes>")
        self.assertLess(len(report["path"]), 64)
