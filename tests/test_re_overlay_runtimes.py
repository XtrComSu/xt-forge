"""Tests for RE annotation overlay, XOR strings, entropy, ASAR, HAR netcap, and APK analysis."""
from __future__ import annotations

import json
import os
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from xtforge.core.re.annotate import annotate, overlay_map_for_binary
from xtforge.core.re import runtimes as rt

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"


def _build_asar(files: dict[str, bytes]) -> bytes:
    entries = {}
    offset = 0
    payload = bytearray()
    for name, content in files.items():
        entries[name] = {"size": len(content), "offset": str(offset)}
        payload.extend(content)
        offset += len(content)
    header_bytes = json.dumps({"files": entries}).encode("utf-8")
    pad = (4 - (len(header_bytes) % 4)) % 4
    header_padded = header_bytes + (b"\x00" * pad)
    header_len = len(header_padded)
    # Chromium ASAR pickle header: [u32=4, u32=8+len, u32=4+len, u32=len]
    prefix = struct.pack("<IIII", 4, 8 + header_len, 4 + header_len, header_len)
    return prefix + header_padded + bytes(payload)


class TestReOverlayAndRuntimes(unittest.TestCase):
    def test_python_overlay_asar_netcap_apk(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.environ.get("XT_HOME")
            os.environ["XT_HOME"] = td
            try:
                sample = Path(td) / "bin.dat"
                sample.write_bytes(b"\x7fELF" + b"\x00" * 124)
                r1 = annotate(action="rename", binary=sample, rva="0x1200",
                              orig="sub_1200", name="decrypt_cfg")
                self.assertTrue(r1["ok"])
                annotate(action="comment", binary=sample, rva="0x1200",
                         comment="RC4 key schedule loop")
                exp = annotate(action="export", binary=sample, fmt="r2")
                self.assertIn("afn decrypt_cfg @ 0x1200", exp["script"])

                ov = overlay_map_for_binary(sample)
                self.assertEqual(ov["count"], 2)
                self.assertEqual(ov["renames_by_orig"]["sub_1200"], "decrypt_cfg")

                asar_p = Path(td) / "app.asar"
                asar_p.write_bytes(_build_asar({"main.js": b"console.log(1);", "pkg.json": b"{}"}))
                ares = rt.inspect_asar(asar_p)
                self.assertTrue(ares["ok"])
                self.assertEqual(ares["count"], 2)

                har_p = Path(td) / "cap.har"
                har_p.write_text(json.dumps({
                    "log": {"entries": [{"request": {
                        "method": "GET", "url": "https://api.example/v1/key",
                        "headers": [{"name": "Authorization", "value": "Bearer supersecret_token_value"}],
                    }, "response": {"status": 200}}]}
                }))
                nres = rt.inspect_netcap(har_p, reveal=False)
                self.assertTrue(nres["ok"])
                auth_val = nres["endpoints"][0]["headers"]["Authorization"]
                self.assertIn("...", auth_val)
                self.assertNotIn("supersecret_token_value", auth_val)

                apk_p = Path(td) / "test.apk"
                with zipfile.ZipFile(apk_p, "w") as zf:
                    zf.writestr("classes.dex", b"dex\n035\x00")
                    zf.writestr("AndroidManifest.xml", b"android.permission.INTERNET")
                    zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF")
                kres = rt.inspect_apk(apk_p)
                self.assertTrue(kres["ok"])
                self.assertIn("classes.dex", kres["dex_files"])
                self.assertIn("android.permission.INTERNET", kres["permissions"])
            finally:
                if old is None:
                    os.environ.pop("XT_HOME", None)
                else:
                    os.environ["XT_HOME"] = old

    def test_native_rust_and_go_cli(self):
        # This asserts engine == "rust", which the launcher can only report when the
        # native Rust binary is present. In a tree where it was never built (a fresh
        # checkout, or an isolated copy without native/xtforge-rs) the launcher falls
        # back to Python and the assertion reports a failure that says nothing about
        # the code. Skip instead: a false failure is worse than a skip, because it
        # trains people to ignore red runs.
        native = ROOT / "native" / "xtforge-rs" / "target" / "release" / "xtforge-native"
        if not native.is_file():
            self.skipTest(f"native Rust launcher not built at {native}")
        with tempfile.TemporaryDirectory() as td:
            env = {**os.environ, "XT_HOME": td}
            sample = Path(td) / "xor.bin"
            raw = bytes(b ^ 0x33 for b in b"https://c2.internal/beacon") + b"\x00\x00"
            sample.write_bytes(raw)
            r_xor = subprocess.run(
                [str(BIN), "re", "strings", str(sample), "--xor", "--json"],
                capture_output=True, text=True, env=env, cwd=str(ROOT),
            )
            self.assertEqual(r_xor.returncode, 0, r_xor.stderr)
            d_xor = json.loads(r_xor.stdout)
            self.assertEqual(d_xor["engine"], "rust")
            self.assertTrue(any("c2.internal" in h["string"] for h in d_xor["xor_strings"]))

            asar_p = Path(td) / "app.asar"
            asar_p.write_bytes(_build_asar({"index.js": b"hello"}))
            r_asar = subprocess.run(
                [str(BIN), "re", "asar", str(asar_p), "--json"],
                capture_output=True, text=True, env=env, cwd=str(ROOT),
            )
            self.assertEqual(r_asar.returncode, 0, r_asar.stderr)
            d_asar = json.loads(r_asar.stdout)
            self.assertTrue(d_asar["ok"])
            self.assertEqual(d_asar["count"], 1)


if __name__ == "__main__":
    unittest.main()
