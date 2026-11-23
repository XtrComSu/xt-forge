"""Evidence bundles: export an investigation, verify it on arrival.

The distinction these tests protect is between *bundle integrity* and *input integrity*, which
fail independently and mean different things:

  * A bundle whose digest does not match was edited or corrupted after export. Every claim
    inside it is suspect.
  * A bundle that verifies perfectly but whose input file has since changed is worse than
    corrupt, because it looks trustworthy. The analysis was honest when it ran; the binary
    it describes is no longer that binary.

`verify_files` exists for the second case. Without it a bundle is self-consistent and
potentially misleading, which is why it is a separate opt-in with its own status per file.

The digest is SHA-256 over canonical JSON. It is deliberately *not* called a signature: there
is no key infrastructure here, and the bundle says so in its own `integrity_note` rather than
implying authentication it cannot provide.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import evidence


class BundleRoundTripTest(unittest.TestCase):
    def test_export_then_import_is_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "sample.bin"
            artifact.write_bytes(b"analysable bytes")
            record = evidence.build(artifact)
            manifest = evidence.export_bundle(
                root / "b.json", records=[record],
                findings=[{"verb": "overview"}], unknowns=[{"topic": "header"}])
            self.assertTrue(manifest["ok"])
            report = evidence.import_bundle(root / "b.json")
        self.assertEqual(report["integrity"], "intact")
        self.assertEqual(report["record_count"], 1)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["unknown_count"], 1)

    def test_round_trip_preserves_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "s.bin"
            artifact.write_bytes(b"payload")
            record = evidence.build(artifact)
            evidence.export_bundle(root / "b.json", records=[record])
            report = evidence.import_bundle(root / "b.json")
        self.assertEqual(report["records"][0]["sha256"], record["sha256"])
        self.assertEqual(report["records"][0]["size"], record["size"])

    def test_empty_bundle_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence.export_bundle(root / "empty.json")
            report = evidence.import_bundle(root / "empty.json")
        self.assertEqual(report["integrity"], "intact")
        self.assertEqual(report["record_count"], 0)

    def test_manifest_reports_what_was_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = evidence.export_bundle(
                root / "b.json", records=[{"a": 1}, {"b": 2}])
        self.assertEqual(manifest["record_count"], 2)
        self.assertGreater(manifest["size"], 0)
        self.assertEqual(len(manifest["digest"]), 64)


class TamperDetectionTest(unittest.TestCase):
    def _bundle(self, root: Path) -> Path:
        target = root / "b.json"
        evidence.export_bundle(target, records=[{"path": "/tmp/x", "sha256": "abc"}],
                               findings=[{"found": True}])
        return target

    def test_edited_bundle_is_a_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._bundle(root)
            document = json.loads(target.read_text())
            document["findings"].append({"injected": True})
            target.write_text(json.dumps(document))
            report = evidence.import_bundle(target)
        self.assertEqual(report["integrity"], "MISMATCH")
        self.assertIn("warning", report)
        self.assertIn("unverified", report["warning"])

    def test_edited_record_is_a_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._bundle(root)
            document = json.loads(target.read_text())
            document["records"][0]["sha256"] = "0" * 64
            target.write_text(json.dumps(document))
            report = evidence.import_bundle(target)
        self.assertEqual(report["integrity"], "MISMATCH")

    def test_digest_that_matches_is_reported_as_intact(self) -> None:
        """Formatting changes must not break the digest: it hashes canonical JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = self._bundle(root)
            document = json.loads(target.read_text())
            target.write_text(json.dumps(document, indent=4))  # reformatted, same content
            report = evidence.import_bundle(target)
        self.assertEqual(report["integrity"], "intact")

    def test_not_a_bundle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "other.json"
            target.write_text(json.dumps({"kind": "something-else"}))
            report = evidence.import_bundle(target)
        self.assertFalse(report["ok"])

    def test_unparseable_bundle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bad.json"
            target.write_text("{not json")
            report = evidence.import_bundle(target)
        self.assertFalse(report["ok"])

    def test_missing_bundle_is_rejected(self) -> None:
        report = evidence.import_bundle("/nonexistent/bundle.json")
        self.assertFalse(report["ok"])


class InputVerificationTest(unittest.TestCase):
    """A self-consistent bundle can still describe a file that has since changed."""

    def test_unchanged_input_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"original")
            evidence.export_bundle(root / "b.json",
                                   records=[evidence.build(artifact)])
            report = evidence.import_bundle(root / "b.json", verify_files=True)
        self.assertEqual(report["integrity"], "intact")
        self.assertEqual(report["file_checks"][0]["status"], "match")
        self.assertEqual(report["changed_files"], [])

    def test_changed_input_is_flagged_even_though_the_bundle_is_intact(self) -> None:
        """The important case: bundle digest fine, underlying bytes different."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"original")
            evidence.export_bundle(root / "b.json",
                                   records=[evidence.build(artifact)])
            artifact.write_bytes(b"replaced by something else")
            report = evidence.import_bundle(root / "b.json", verify_files=True)
        self.assertEqual(report["integrity"], "intact",
                         "the bundle itself should still verify")
        self.assertEqual(report["file_checks"][0]["status"], "CHANGED")
        self.assertEqual(report["changed_files"], [str(artifact)])

    def test_deleted_input_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"gone soon")
            evidence.export_bundle(root / "b.json",
                                   records=[evidence.build(artifact)])
            artifact.unlink()
            report = evidence.import_bundle(root / "b.json", verify_files=True)
        self.assertEqual(report["file_checks"][0]["status"], "missing")
        self.assertIn(str(artifact), report["changed_files"])

    def test_verification_is_off_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"x")
            evidence.export_bundle(root / "b.json",
                                   records=[evidence.build(artifact)])
            report = evidence.import_bundle(root / "b.json")
        self.assertNotIn("file_checks", report)


class HonestyTest(unittest.TestCase):
    def test_bundle_says_it_is_not_a_signature(self) -> None:
        """A digest invites the word 'verified'; the bundle must not overclaim."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "b.json"
            evidence.export_bundle(target)
            document = json.loads(target.read_text())
        self.assertIn("integrity_note", document)
        self.assertIn("not a signature", document["integrity_note"])

    def test_record_schema_note_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"x")
            record = evidence.build(artifact)
            self.assertIn("not a signature", record["schema_note"])

    def test_result_is_json_serialisable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"x")
            evidence.export_bundle(root / "b.json", records=[evidence.build(artifact)])
            json.dumps(evidence.import_bundle(root / "b.json", verify_files=True))

    def test_inspect_dispatches_on_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "a.bin"
            artifact.write_bytes(b"bytes here")
            evidence.export_bundle(root / "b.json", records=[evidence.build(artifact)])
            bundle = evidence.inspect(root / "b.json")
            bare = evidence.inspect(artifact)
        self.assertEqual(bundle["integrity"], "intact")
        self.assertIn("sha256", bare)


if __name__ == "__main__":
    unittest.main()
