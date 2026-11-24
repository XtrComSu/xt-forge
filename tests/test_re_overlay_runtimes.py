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

                # A real binary manifest, not a plain-text fake. The previous fixture was the
                # bytes `android.permission.INTERNET`, which only a byte-scanner could satisfy —
                # so this test was asserting the bug rather than the behaviour. A manifest whose
                # pool is genuinely UTF-16LE is the only fixture that means anything here.
                from xtforge.core.re import axml as _axml
                apk_p = Path(td) / "test.apk"
                with zipfile.ZipFile(apk_p, "w") as zf:
                    zf.writestr("classes.dex", b"dex\n035\x00")
                    zf.writestr("AndroidManifest.xml",
                                _binary_manifest([("uses-permission",
                                                   {"name": "android.permission.INTERNET"})]))
                    zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF")
                kres = rt.inspect_apk(apk_p)
                self.assertTrue(kres["ok"])
                self.assertIn("classes.dex", kres["dex_files"])
                self.assertIn("android.permission.INTERNET", kres["permissions"],
                              f"permissions were {kres['permissions']}; the manifest is binary "
                              "XML, so it must be decoded rather than scanned")
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


def _binary_manifest(children: list) -> bytes:
    """Build a minimal but genuine Android binary XML manifest.

    Structure: XML header, a UTF-16LE string pool, a resource map, then start/end element chunks.
    Attribute geometry follows the platform: the element body begins at chunk+8, so
    `attributeStart` (measured from chunk+16) points at chunk+16+20, and the records live there.
    """
    import struct as _struct

    strings: list[str] = []
    index: dict[str, int] = {}

    def intern(value: str) -> int:
        if value not in index:
            index[value] = len(strings)
            strings.append(value)
        return index[value]

    body = bytearray()

    def element(tag: str, attributes: dict[str, str], *, start: bool) -> None:
        tag_index = intern(tag)
        if start:
            for key in attributes:
                intern(key)
            for value in attributes.values():
                intern(value)
            header = bytearray(22)
            _struct.pack_into("<I", header, 12, tag_index)   # name at chunk+20
            _struct.pack_into("<H", header, 16, 20)          # attributeStart from chunk+16
            _struct.pack_into("<H", header, 18, 20)          # attributeSize
            _struct.pack_into("<H", header, 20, len(attributes))
            records = bytearray()
            for key, value in attributes.items():
                record = bytearray(20)
                _struct.pack_into("<I", record, 4, intern(key))
                _struct.pack_into("<I", record, 8, intern(value))  # rawValue
                record[15] = 0x03                                  # TYPE_STRING
                _struct.pack_into("<I", record, 16, intern(value))
                records += record
            total = 16 + 20 + len(records)
            chunk = bytearray(total)
            _struct.pack_into("<H", chunk, 0, 0x0102)
            _struct.pack_into("<H", chunk, 2, 16)
            _struct.pack_into("<I", chunk, 4, total)
            chunk[8:8 + len(header)] = header
            chunk[36:36 + len(records)] = records
            body.extend(chunk)
        else:
            chunk = bytearray(28)
            _struct.pack_into("<H", chunk, 0, 0x0103)
            _struct.pack_into("<H", chunk, 2, 16)
            _struct.pack_into("<I", chunk, 4, 28)
            _struct.pack_into("<I", chunk, 20, tag_index)
            body.extend(chunk)

    element("manifest", {"package": "com.example"}, start=True)
    for tag, attributes in children:
        element(tag, attributes, start=True)
        element(tag, attributes, start=False)
    element("manifest", {}, start=False)

    data = bytearray()
    offsets = []
    for value in strings:
        offsets.append(len(data))
        encoded = value.encode("utf-16-le")
        data += _struct.pack("<H", len(encoded) // 2) + encoded + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    header_size = 28
    pool_size = header_size + len(offsets) * 4 + len(data)
    pool = bytearray(pool_size)
    _struct.pack_into("<H", pool, 0, 0x0001)
    _struct.pack_into("<H", pool, 2, header_size)
    _struct.pack_into("<I", pool, 4, pool_size)
    _struct.pack_into("<I", pool, 8, len(strings))
    _struct.pack_into("<I", pool, 16, 0)                       # UTF-16LE
    _struct.pack_into("<I", pool, 20, header_size + len(offsets) * 4)
    for position, offset in enumerate(offsets):
        _struct.pack_into("<I", pool, header_size + position * 4, offset)
    pool[header_size + len(offsets) * 4:] = data

    document = bytes(pool) + bytes(body)
    out = bytearray(8 + len(document))
    _struct.pack_into("<H", out, 0, 0x0003)
    _struct.pack_into("<H", out, 2, 8)
    _struct.pack_into("<I", out, 4, len(out))
    out[8:] = document
    return bytes(out)
