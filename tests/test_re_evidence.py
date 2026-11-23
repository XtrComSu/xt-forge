"""Tests for the versioned reverse-engineering evidence record."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import evidence

EXPECTED_KEYS = {
    "schema", "path", "size", "sha256", "member", "slice",
    "address_space", "backend", "backend_version", "limits", "schema_note",
}


class TestBuild(unittest.TestCase):
    def test_build_matches_hashlib_and_has_every_key(self):
        payload = b"evidence bytes\n\x00with a nul\xffand high bytes\n"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sample.bin"
            target.write_bytes(payload)
            record = evidence.build(target)

        self.assertEqual(record["size"], len(payload))
        self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(set(record), EXPECTED_KEYS)
        self.assertEqual(record["schema"], 1)
        self.assertEqual(record["schema"], evidence.EVIDENCE_SCHEMA)
        self.assertEqual(record["path"], str(target))
        self.assertIsNone(record["member"])
        self.assertIsNone(record["slice"])
        self.assertIsNone(record["address_space"])
        self.assertEqual(record["limits"], {})
        self.assertEqual(record["schema_note"],
                         "identifies the analysed bytes; not a signature")

    def test_build_missing_path_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OSError):
                evidence.build(Path(tmp) / "absent.bin")

    def test_build_directory_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                evidence.build(tmp)

    def test_three_mib_file_is_hashed_in_full(self):
        payload = (b"0123456789abcdef" * (3 * 1024 * 1024 // 16))
        self.assertEqual(len(payload), 3 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "large.bin"
            target.write_bytes(payload)
            record = evidence.build(target)
        self.assertEqual(record["size"], 3 * 1024 * 1024)
        self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())

    def test_options_are_carried_into_the_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "fat.bin"
            target.write_bytes(b"fat")
            record = evidence.build(
                target, member="Payload/app", arch="arm64", verb="overview",
                backend="test-backend", backend_version="2.1",
                limits={"truncated": True},
                address_space={"base": 0x1000, "bits": 64},
            )
        self.assertEqual(record["member"], "Payload/app")
        self.assertEqual(record["slice"], "arm64")
        self.assertEqual(record["backend"], "test-backend")
        self.assertEqual(record["backend_version"], "2.1")
        self.assertEqual(record["limits"], {"truncated": True})
        self.assertEqual(record["address_space"], {"base": 0x1000, "bits": 64})


class TestAttach(unittest.TestCase):
    def test_attach_does_not_mutate_input(self):
        original = {"ok": True, "format": "macho"}
        record = {"schema": 1, "sha256": "abc"}
        combined = evidence.attach(original, record)
        self.assertNotIn("evidence", original)
        self.assertEqual(original, {"ok": True, "format": "macho"})
        self.assertEqual(combined["evidence"], record)
        self.assertEqual(combined["format"], "macho")
        self.assertIsNot(combined, original)


class TestEvidenceCli(unittest.TestCase):
    def _cli(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "--json", "re", "evidence", *argv],
            capture_output=True,
            text=True,
        )

    def test_cli_prints_a_versioned_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sample.bin"
            payload = b"cli evidence\n"
            target.write_bytes(payload)
            res = self._cli(str(target))
            expected_hash = hashlib.sha256(payload).hexdigest()
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["schema"], 1)
        self.assertEqual(set(data), EXPECTED_KEYS)
        self.assertEqual(len(data["sha256"]), 64)
        self.assertEqual(data["sha256"], expected_hash)

    def test_cli_passes_member_and_arch_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sample.bin"
            target.write_bytes(b"x")
            res = self._cli(str(target), "--member", "Payload/app", "--arch", "arm64")
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["member"], "Payload/app")
        self.assertEqual(data["slice"], "arm64")

    def test_human_form_is_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sample.bin"
            target.write_bytes(b"x")
            res = subprocess.run(
                [sys.executable, "-m", "xtforge.cli", "re", "evidence", str(target)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("backend", res.stdout)
        self.assertIn("xtforge-hub", res.stdout)
        self.assertLessEqual(len(res.stdout.splitlines()), 8)


if __name__ == "__main__":
    unittest.main()
