"""CLI tests for the human summary of `re overview` on unclaimed files."""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestReUnknownRender(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _cli(self, verb: str, path: str | Path, *, as_json: bool = False
             ) -> subprocess.CompletedProcess[str]:
        # Mirror tests/test_re_container_verbs.py: include both fixture and
        # interpreter directories in the Go hub's read allowlist.
        roots = f"{self.dir},{Path(sys.executable).resolve().parent}"
        env = dict(os.environ, XT_ROOTS=roots)
        argv = [sys.executable, "-m", "xtforge.cli"]
        if as_json:
            argv.append("--json")
        argv.extend(["re", verb, str(path)])
        return subprocess.run(argv, capture_output=True, text=True, env=env)

    def _binary(self) -> Path:
        """A random-ish blob: high bytes cannot form ASCII runs or magic bytes."""
        rng = random.Random(20261123)
        data = bytearray(0x80 | (byte & 0x7F) for byte in rng.randbytes(512))
        data[0:8] = b"\x00\x01\x02\x03\x90\x91\x92\x93"
        for index, run in enumerate((b"SECTOR7", b"BLOBBY", b"MAGIC42",
                                     b"TRACE9", b"PACKET66")):
            at = 16 + index * 32
            data[at:at + len(run)] = run
        path = self.dir / "unclaimed-blob.bin"
        path.write_bytes(data)
        return path

    @property
    def elf(self) -> str:
        path = Path(sys.executable).resolve()
        if path.read_bytes()[:4] != b"\x7fELF":
            self.skipTest(f"interpreter is not an ELF binary: {path}")
        return str(path)

    def test_unknown_human_summary_is_only_seven_fields(self):
        res = self._cli("overview", self._binary())
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        lines = res.stdout.strip().splitlines()
        self.assertEqual(len(lines), 7, res.stdout)
        names = ["format", "size", "sha256", "entropy", "magic", "strings", "note"]
        for line, name in zip(lines, names):
            self.assertTrue(line.startswith(f"{name:<16} "), line)
        values = dict(line.split(maxsplit=1) for line in lines)
        self.assertEqual(values["format"], "unknown")
        self.assertEqual(values["size"], "512 bytes")
        self.assertRegex(values["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(values["entropy"], r"^\d+\.\d{2} \([a-z]+\)$")
        self.assertEqual(values["magic"], "0001020390919293")
        self.assertIn("BLOBBY", values["strings"])
        self.assertEqual(values["note"],
                         "unrecognised format; no disassembly or symbol recovery attempted")
        # The image's empty arch / zero bits placeholders must not leak into the
        # summary, nor may the rest of the raw report.
        self.assertNotIn("arch", res.stdout)
        self.assertNotIn("bits", res.stdout)
        self.assertNotIn("\"images\"", res.stdout)

    def test_unknown_json_shape_is_unchanged(self):
        res = self._cli("overview", self._binary(), as_json=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data.get("format"), "unknown")
        images = data.get("images") or []
        self.assertEqual(len(images), 1, data)
        image = images[0]
        self.assertEqual(image.get("arch"), "")
        self.assertEqual(image.get("bits"), 0)
        self.assertIn("unknown", image)
        self.assertEqual(set(image["unknown"]), {
            "size", "sha256", "entropy", "entropy_class", "magic",
            "hex_preview", "strings", "truncated", "note",
        })
        self.assertEqual(image["unknown"]["size"], 512)

    def test_elf_keeps_its_normal_summary(self):
        res = self._cli("overview", self.elf)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('"format": "elf"', res.stdout)
        self.assertIn('"arch"', res.stdout)
        self.assertIn('"sections"', res.stdout)
        self.assertNotIn("unknown", res.stdout.lower())


if __name__ == "__main__":
    unittest.main()
