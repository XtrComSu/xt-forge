"""Tests for the V8 code cache reader.

The fixtures are real caches, written by Node's own
`new vm.Script(src, {produceCachedData: true}).createCachedData()`, and the oracle is
that same call: Node reports the cache length and `Buffer.byteLength(src)` reports the
source size, so the header fields are checked against the engine that wrote them rather
than against numbers I typed.

The bug this file exists to prevent: an earlier draft read the payload length one word
early (offset 16 instead of 20), and so reported a 2.5 GB payload inside a 536-byte
file. Every field still parsed, every call still returned ok:true, and nothing looked
wrong — which is exactly why the assertions below compare header fields to the real
file size instead of merely checking that parsing succeeded.
"""
from __future__ import annotations

import json
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import v8cache


def _node() -> str | None:
    return shutil.which("node")


def build_cache(directory: Path, *, source_padding: int = 0) -> dict | None:
    """Write a real V8 code cache. Returns None when node is unavailable."""
    node = _node()
    if node is None:
        return None
    source_text = "function computed(a, b) { return a * b + 1; }\nmodule.exports = { computed };\n"
    if source_padding:
        source_text += "//" + "x" * source_padding + "\n"
    source = directory / "mod.js"
    source.write_text(source_text)
    cache = directory / "mod.js.cache"
    script = directory / "make.js"
    script.write_text(f"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync({str(source)!r}, 'utf8');
const script = new vm.Script(src, {{ filename: 'mod.js', produceCachedData: true }});
const data = script.createCachedData();
fs.writeFileSync({str(cache)!r}, data);
console.log(JSON.stringify({{
  source_bytes: Buffer.byteLength(src),
  cache_bytes: data.length,
  magic: data.readUInt32LE(0),
}}));
""")
    result = subprocess.run([node, str(script)], capture_output=True, text=True,
                            timeout=120)
    if result.returncode != 0 or not cache.is_file():
        return None
    try:
        facts = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return None
    facts["path"] = cache
    facts["source"] = source
    return facts


class RealCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.small = build_cache(cls.root)
        nested = cls.root / "padded"
        nested.mkdir(exist_ok=True)
        cls.padded = build_cache(nested, source_padding=400)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.small is None:
            self.skipTest("node unavailable to produce a real V8 code cache")

    def test_magic_is_recognised(self) -> None:
        report = v8cache.inspect_v8_code_cache(self.small["path"])
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["kind"], "v8-code-cache")
        # Compare against the magic Node itself wrote, not a hardcoded constant.
        self.assertEqual(int(report["version_magic"], 16), self.small["magic"])

    def test_payload_length_plus_header_equals_file_size(self) -> None:
        """The check that catches an off-by-one-word header layout.

        Reading the payload length one word early yields a plausible integer that is
        simply wrong; only comparing against the real file size exposes it.
        """
        report = v8cache.inspect_v8_code_cache(self.small["path"])
        self.assertFalse(report.get("truncated"), report.get("warning"))
        self.assertEqual(report["payload_length"] + 32, report["file_size"])
        self.assertEqual(report["file_size"], self.small["cache_bytes"])

    def test_source_size_matches_the_real_source(self) -> None:
        """`source_size` is a header field, compared to Node's Buffer.byteLength."""
        report = v8cache.inspect_v8_code_cache(self.small["path"])
        self.assertEqual(report["source_size"], self.small["source_bytes"])

    def test_a_larger_source_changes_source_size_not_payload_size(self) -> None:
        """Padding the source 400 bytes must move source_size, not the payload.

        This distinguishes the two size fields from each other: if the reader had them
        swapped, this test fails while the single-cache test still passes.
        """
        if self.padded is None:
            self.skipTest("second cache could not be built")
        small = v8cache.inspect_v8_code_cache(self.small["path"])
        padded = v8cache.inspect_v8_code_cache(self.padded["path"])
        self.assertGreater(padded["source_size"], small["source_size"])
        self.assertEqual(padded["source_size"], self.padded["source_bytes"])
        # Same script shape, so the payload should be identical in size.
        self.assertEqual(padded["payload_length"], small["payload_length"])

    def test_source_is_located_from_the_cache_name(self) -> None:
        report = v8cache.inspect_v8_code_cache(self.small["path"])
        self.assertIsNotNone(report["source"])
        self.assertEqual(Path(report["source"]).name, "mod.js")

    def test_source_hash_is_not_claimed_as_verified(self) -> None:
        """V8's source hash is internal; recomputing it here would be a guess.

        The reader reports the field and says plainly that it did not verify it,
        rather than implying a match it never established.
        """
        report = v8cache.inspect_v8_code_cache(self.small["path"])
        self.assertFalse(report["source_hash_verified"])
        self.assertIn("not recomputed", report["source_hash_note"])

    def test_payload_hash_is_stable(self) -> None:
        first = v8cache.inspect_v8_code_cache(self.small["path"])
        second = v8cache.inspect_v8_code_cache(self.small["path"])
        self.assertEqual(first["payload_sha256"], second["payload_sha256"])
        self.assertEqual(len(first["payload_sha256"]), 64)

    def test_directory_survey(self) -> None:
        report = v8cache.inspect_v8_code_cache(self.root)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreaterEqual(report["cache_count"], 1)
        self.assertGreaterEqual(report["distinct_builds"], 1)
        self.assertGreaterEqual(report["sources_matched"], 1)


class SyntheticCacheTest(unittest.TestCase):
    """Format assertions on hand-built headers, so they run without node."""

    def _write(self, directory: Path, magic: int = 0xC0DE0628,
               source_size: int = 100, payload: bytes = b"\x01\x02\x03\x04",
               header_size: int = 32) -> Path:
        # Six words = 24 bytes; the real header is 32, with two reserved zero words.
        header = struct.pack("<IIIIIIII", magic, 0x8, source_size, 0xDEADBEEF,
                             0xCAFEBABE, len(payload), 0, 0)
        header = header.ljust(header_size, b"\x00")[:header_size]
        target = directory / "synthetic.cache"
        target.write_bytes(header + payload)
        return target

    def test_header_fields_are_read_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = v8cache.inspect_v8_code_cache(
                self._write(Path(tmp), source_size=1234))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["source_size"], 1234)
        self.assertEqual(report["source_hash"], "0xdeadbeef")
        self.assertEqual(report["flag_hash"], "0xcafebabe")
        self.assertEqual(report["payload_length"], 4)

    def test_wrong_magic_is_rejected_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = v8cache.inspect_v8_code_cache(
                self._write(Path(tmp), magic=0x12345678))
        self.assertFalse(report["ok"])
        self.assertEqual(report["found_magic"], "0x12345678")

    def test_truncated_payload_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = self._write(Path(tmp), payload=b"")
            data = bytearray(target.read_bytes())
            struct.pack_into("<I", data, 20, 9999)  # claim a payload that is not there
            target.write_bytes(bytes(data))
            report = v8cache.inspect_v8_code_cache(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(report["truncated"])
        self.assertIn("9999", report["warning"])

    def test_short_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "short.cache"
            target.write_bytes(struct.pack("<II", 0xC0DE0628, 8))
            report = v8cache.inspect_v8_code_cache(target)
        self.assertFalse(report["ok"])
        self.assertIn("truncated", report["error"])

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(4242)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(20):
                blob = root / f"r{index}.cache"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 200))))
                try:
                    v8cache.inspect_v8_code_cache(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")

    def test_missing_file_reports_error(self) -> None:
        report = v8cache.inspect_v8_code_cache("/nonexistent/x.cache")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
