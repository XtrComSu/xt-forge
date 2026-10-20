"""Contract tests for the codec toolkit (breadth phase 2, A1).

Acceptance: 20 fixtures round-trip encode/decode, and entropy matches a
reference within 0.01.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import codec as codecmod  # noqa: E402

# Twenty (scheme, value) fixtures. Every reversible scheme is covered at
# least once, including empty-ish, unicode, newlines and long input.
ROUNDTRIPS = [
    ("base64", "hello world"),
    ("base64", ""),
    ("base64", "line one\nline two\n"),
    ("base64", "ünïcodé ✅ and 中文"),
    ("base64", "x" * 1000),
    ("base64url", "a/b+c=d"),
    ("base64url", "eyJhbGciOiJIUzI1NiJ9"),
    ("base32", "secret value"),
    ("base32", "0123456789abcdef"),
    ("hex", "hi"),
    ("hex", ""),
    ("hex", "\x01\x02binary-ish"),
    ("hex", "deadbeef" * 8),
    ("binary", "A"),
    ("binary", "abc123"),
    ("url", "https://example.com/a b?x=1&y=2"),
    ("url", "path/to/file name.txt"),
    ("html", "<script>alert('x')</script>"),
    ("rot13", "Uryyb, Jbeyq!"),
    ("reverse", "MiXeD CaSe"),
]


class TestRoundTrip(unittest.TestCase):
    def test_twenty_fixtures_round_trip(self):
        broken = []
        for scheme, value in ROUNDTRIPS:
            raw = value.encode("utf-8")
            out = codecmod.decode(codecmod.encode(raw, scheme), scheme)
            if out != raw:
                broken.append((scheme, value))
        self.assertEqual(len(ROUNDTRIPS), 20)
        self.assertEqual(broken, [], f"schemes that lost data: {broken}")

    def test_reverse_scheme_is_its_own_inverse(self):
        self.assertEqual(codecmod.decode(codecmod.encode(b"abc", "reverse"),
                                         "reverse"), b"abc")

    def test_unknown_scheme_is_an_error(self):
        with self.assertRaises(ValueError):
            codecmod.encode(b"x", "klingon")
        with self.assertRaises(ValueError):
            codecmod.decode("x", "klingon")

    def test_hex_ignores_separators(self):
        self.assertEqual(codecmod.decode("68 69:6a", "hex"), b"hij")


class TestEntropy(unittest.TestCase):
    def test_reference_values(self):
        cases = [
            (b"", 0.0),
            (b"aaaa", 0.0),
            (b"abcd", 2.0),
            (b"aaaaaaaaaabbbbbccccc", 1.5),   # 10/20, 5/20, 5/20
        ]
        for raw, want in cases:
            self.assertAlmostEqual(codecmod.shannon(raw), want, places=2,
                                   msg=raw)

    def test_random_is_high(self):
        self.assertGreater(codecmod.shannon(os.urandom(4096)), 7.5)

    def test_verdicts(self):
        self.assertEqual(codecmod.entropy_report(b"aaaa")["verdict"], "low")
        self.assertEqual(codecmod.entropy_report(os.urandom(4096))["verdict"],
                         "random_or_encrypted")

    def test_block_report(self):
        report = codecmod.entropy_report(b"a" * 16 + os.urandom(16), block=16)
        self.assertEqual(len(report["blocks"]), 2)
        self.assertLess(report["blocks"][0]["entropy"],
                        report["blocks"][1]["entropy"])

    def test_no_negative_zero(self):
        self.assertEqual(codecmod.entropy_report(b"aaaa")["entropy"], 0.0)


class TestHash(unittest.TestCase):
    def test_known_digests(self):
        self.assertEqual(codecmod.digest(b"hello")["digest"],
                         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(codecmod.digest(b"hello", "md5")["digest"],
                         "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(codecmod.digest(b"hello", "crc32")["digest"], "3610a686")

    def test_all_algorithms(self):
        payload = codecmod.digest(b"hello", "all")
        self.assertEqual(len(payload["digests"]), len(codecmod.HASHES))

    def test_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            codecmod.digest(b"x", "md6")


class TestInspect(unittest.TestCase):
    def find(self, text: str, kind: str) -> dict:
        payload = codecmod.inspect(text)
        for item in payload["findings"]:
            if item["type"] == kind:
                return item
        self.fail(f"{kind} not detected in {text!r}: {payload['findings']}")

    def test_jwt(self):
        item = self.find("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                         "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                         "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt")
        self.assertEqual(item["detail"][0]["header"]["alg"], "HS256")

    def test_pem(self):
        item = self.find("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n"
                         "-----END RSA PRIVATE KEY-----", "pem")
        self.assertEqual(item["label"], "RSA PRIVATE KEY")

    def test_uuid(self):
        item = self.find("123e4567-e89b-12d3-a456-426614174000", "uuid")
        self.assertIn("urn:uuid:", item["urn"])

    def test_semver(self):
        item = self.find("v1.2.3-rc.1", "semver")
        self.assertEqual((item["major"], item["minor"], item["patch"]),
                         (1, 2, 3))

    def test_color(self):
        item = self.find("#ff8800", "color")
        self.assertEqual(item["rgb"], (255, 136, 0))

    def test_timestamp(self):
        item = self.find("1700000000", "unix_timestamp")
        self.assertTrue(item["iso"].startswith("2023-11-14"))

    def test_url_with_credentials(self):
        item = self.find("postgres://admin:hunter2@db.internal:5432/app", "url")
        self.assertTrue(item["credentials_in_url"])

    def test_hex_decodes_to_ascii(self):
        item = self.find("68656c6c6f", "hex")
        self.assertEqual(item["ascii"], "hello")

    def test_base64_decodes(self):
        item = self.find("aGVsbG8gd29ybGQ", "base64")
        self.assertEqual(item["ascii"], "hello world")

    def test_junk_is_unrecognised(self):
        payload = codecmod.inspect("not a format at all")
        self.assertEqual(payload["count"], 0)


class TestCliCodec(unittest.TestCase):
    def run_cli(self, *args, expect_ok: bool = True):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", "codec", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc

    def test_hash_over_cli(self):
        payload = json.loads(self.run_cli("hash", "hello", "--json").stdout)
        self.assertEqual(payload["algorithm"], "sha256")
        self.assertTrue(payload["digest"].startswith("2cf24dba"))

    def test_roundtrip_verifies_all_fixtures(self):
        for scheme, value in ROUNDTRIPS:
            proc = self.run_cli("roundtrip", value, "--scheme", scheme, "--json")
            self.assertTrue(json.loads(proc.stdout)["ok"], (scheme, value))

    def test_entropy_from_file(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(os.urandom(2048))
            path = fh.name
        try:
            payload = json.loads(self.run_cli("entropy", "--path", path,
                                              "--json").stdout)
            self.assertGreater(payload["entropy"], 7.0)
        finally:
            os.unlink(path)

    def test_inspect_over_cli(self):
        payload = json.loads(self.run_cli(
            "inspect", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "--json").stdout)
        self.assertGreaterEqual(payload["count"], 1)

    def test_binary_roundtrip_via_file(self):
        """Every byte value survives: argv cannot carry NUL, files can."""
        raw = bytes(range(256))
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(raw)
            src = fh.name
        try:
            encoded = json.loads(self.run_cli(
                "encode", "--scheme", "hex", "--path", src, "--json").stdout)
            decoded = json.loads(self.run_cli(
                "decode", "--scheme", "hex", encoded["output"], "--json").stdout)
            self.assertEqual(decoded["hex"], raw.hex())
        finally:
            os.unlink(src)

    def test_bad_scheme_is_reported(self):
        proc = self.run_cli("encode", "--scheme", "klingon", "x", "--json",
                            expect_ok=False)
        self.assertIn("unknown scheme", proc.stdout)


if __name__ == "__main__":
    unittest.main()
