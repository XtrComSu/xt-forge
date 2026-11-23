"""Tests for the Apple .car asset catalog reader.

Two fixture sources, deliberately:

  * A **synthetic** BOMStore built here, so every field's expected value is chosen.
  * A **real** `Assets.car` shipped inside a macOS application on this host, because the
    synthetic one encodes my understanding of the format and a real file does not.

The real file is what exposed all three bugs this reader had:

  * the index is `(addr, size)` pairs, not `block_count+1` consecutive offsets. Read the
    wrong way the offsets are non-monotonic and one block's size comes out negative.
  * blocks with size 0 are empty; treating 0 as an address reads the file header.
  * the BOM container is big-endian but the CARHEADER *contents* are little-endian, so
    the CoreUI version reads as 3422748672 instead of 972 and still parses cleanly.

The last one is the reason the tests assert exact numbers rather than `ok: true`.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import assetcatalog


def build_bom(blocks: list[tuple[str, bytes]], *, version: int = 1) -> bytes:
    """Assemble a BOMStore with the given (name, body) blocks. Names map in order."""
    header_size = 256
    # Lay blocks out after the header, aligned to 4 bytes.
    layout: list[tuple[int, int]] = []
    body = bytearray()
    cursor = header_size
    for _name, payload in blocks:
        padded = payload + bytes((-len(payload)) % 4)
        layout.append((cursor, len(payload)))
        body.extend(padded)
        cursor += len(padded)

    # Block table: count, then (addr, size) pairs.
    total_blocks = len(layout)
    table = struct.pack(">I", total_blocks)
    for addr, size in layout:
        table += struct.pack(">II", addr, size)

    # Name table: count, then (block index, u8 len, name).
    names = struct.pack(">I", len(blocks))
    for index, (name, _payload) in enumerate(blocks):
        encoded = name.encode("latin-1")
        names += struct.pack(">I", index) + bytes([len(encoded)]) + encoded

    blocks_offset = header_size
    index_offset = blocks_offset + len(body)
    vars_offset = index_offset + len(table)
    preamble = b"BOMStore" + struct.pack(
        ">IIIIII", version, total_blocks, index_offset, len(table),
        vars_offset, len(names))
    out = bytearray(preamble.ljust(header_size, b"\x00"))
    out.extend(body)
    out.extend(table)
    out.extend(names)
    return bytes(out)


def car_header_body(coreui: int = 972, version: int = 17, flags: int = 0,
                    keys: int = 33,
                    renderer: bytes = b"@(#)PROGRAM:CoreUI  PROJECT:CoreUI-972.1\x00"
                    ) -> bytes:
    return b"RATC" + struct.pack("<IIII", coreui, version, flags, keys) + renderer


def find_real_car() -> Path | None:
    """Any genuine .car on this host, found without hardcoding a project path."""
    for root in (Path.home() / "projects", Path.home() / "src", Path("/opt")):
        if not root.is_dir():
            continue
        try:
            for candidate in root.rglob("*.car"):
                try:
                    with candidate.open("rb") as handle:
                        if handle.read(8) == b"BOMStore":
                            return candidate
                except OSError:
                    continue
        except OSError:
            continue
    return None


class SyntheticBomTest(unittest.TestCase):
    def _write(self, directory: Path, blocks: list[tuple[str, bytes]], **kwargs) -> Path:
        target = directory / "Assets.car"
        target.write_bytes(build_bom(blocks, **kwargs))
        return target

    def test_container_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), [("CARHEADER", car_header_body())],
                               version=1)
            report = assetcatalog.inspect_asset_catalog(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["container"], "BOMStore")
        self.assertEqual(report["version"], 1)
        self.assertEqual(report["block_count"], 1)
        self.assertEqual(report["occupied_blocks"], 1)

    def test_named_blocks_resolve_to_their_extents(self) -> None:
        blocks = [("CARHEADER", car_header_body()),
                  ("RENDITIONS", b"tree" + bytes(20)),
                  ("KEYFORMAT", b"tmfk" + bytes(12))]
        with tempfile.TemporaryDirectory() as tmp:
            report = assetcatalog.inspect_asset_catalog(self._write(Path(tmp), blocks))
        names = report["named_blocks"]
        self.assertEqual(set(names), {"CARHEADER", "RENDITIONS", "KEYFORMAT"})
        self.assertEqual(names["CARHEADER"]["tag"], "RATC")
        self.assertEqual(names["CARHEADER"]["tag_kind"], "car-header")
        self.assertEqual(names["KEYFORMAT"]["tag"], "tmfk")

    def test_car_header_is_little_endian(self) -> None:
        """The container is big-endian; block contents are not.

        Read big-endian, the CoreUI version 972 becomes 3422748672 — a valid integer
        that nothing about the parse would flag.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = assetcatalog.inspect_asset_catalog(
                self._write(Path(tmp), [("CARHEADER", car_header_body(972, 17, 0, 33))]))
        header = report["car_header"]
        self.assertEqual(header["coreui_version"], 972)
        self.assertEqual(header["version"], 17)
        self.assertEqual(header["key_count"], 33)

    def test_renderer_string_is_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = assetcatalog.inspect_asset_catalog(
                self._write(Path(tmp), [("CARHEADER", car_header_body())]))
        self.assertIn("CoreUI-972.1", report["car_header"]["renderer"])

    def test_empty_block_is_not_read_as_file_header(self) -> None:
        """Size 0 means empty; address 0 would be the magic.

        A reader that treats 0 as a real offset reports the block's contents as
        "BOMStore", which looks like data rather than an error.
        """
        blocks = [("CARHEADER", car_header_body()), ("EMPTY", b"")]
        with tempfile.TemporaryDirectory() as tmp:
            report = assetcatalog.inspect_asset_catalog(self._write(Path(tmp), blocks))
        self.assertTrue(report["named_blocks"]["EMPTY"]["empty"])
        self.assertEqual(report["named_blocks"]["EMPTY"]["size"], 0)

    def test_pair_table_not_offset_list(self) -> None:
        """Sizes must come from each block's own field.

        Reading the table as consecutive offsets makes block N's span run to block N+1's
        address, which is only correct in a file where nothing is padded. Here every
        block is 4-byte padded, so the two readings disagree.
        """
        blocks = [("A", b"RATC" + bytes(5)),    # 9 bytes -> padded to 12
                  ("B", b"tree" + bytes(3))]    # 7 bytes -> padded to 8
        with tempfile.TemporaryDirectory() as tmp:
            report = assetcatalog.inspect_asset_catalog(self._write(Path(tmp), blocks))
        self.assertEqual(report["named_blocks"]["A"]["size"], 9)
        self.assertEqual(report["named_blocks"]["B"]["size"], 7)

    def test_index_count_is_reported(self) -> None:
        """The reported block count must agree with the parsed table, not the header."""
        with tempfile.TemporaryDirectory() as tmp:
            report = assetcatalog.inspect_asset_catalog(
                self._write(Path(tmp), [("CARHEADER", car_header_body())]))
        self.assertEqual(report["index_count"], report["block_count"])


class RealCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = find_real_car()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("no real BOMStore .car on this host")

    def test_real_catalog_parses(self) -> None:
        report = assetcatalog.inspect_asset_catalog(self.path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["container"], "BOMStore")
        self.assertGreater(report["block_count"], 10)

    def test_block_sizes_are_all_non_negative(self) -> None:
        """The bug the pair-table fix removed: a negative block size.

        Reading the index as consecutive offsets produced end < start on the real file.
        """
        report = assetcatalog.inspect_asset_catalog(self.path)
        for name, block in report["named_blocks"].items():
            self.assertGreaterEqual(block.get("size", 0), 0, name)

    def test_real_car_header_has_a_sane_coreui_version(self) -> None:
        """CoreUI versions are in the hundreds-to-thousands, not billions.

        A byte-order mistake yields ~3.4e9, which is the assertion that catches it.
        """
        report = assetcatalog.inspect_asset_catalog(self.path)
        header = report.get("car_header") or {}
        if not header:
            self.skipTest("this catalog has no readable CARHEADER")
        self.assertLess(header["coreui_version"], 100_000)
        self.assertGreater(header["coreui_version"], 0)
        self.assertLess(header["version"], 1000)

    def test_named_blocks_have_known_tags(self) -> None:
        report = assetcatalog.inspect_asset_catalog(self.path)
        tags = {name: block.get("tag") for name, block in report["named_blocks"].items()
                if block.get("tag")}
        self.assertTrue(tags, "no block tags recovered from a real catalog")
        for tag in tags.values():
            self.assertTrue(all(32 <= ord(ch) < 127 for ch in tag), tag)

    def test_occupied_plus_empty_equals_block_count(self) -> None:
        report = assetcatalog.inspect_asset_catalog(self.path)
        self.assertEqual(report["occupied_blocks"] + report["empty_blocks"],
                         report["block_count"])


class CatalogBoundariesTest(unittest.TestCase):
    def test_non_bom_is_rejected(self) -> None:
        report = assetcatalog.inspect_asset_catalog("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("not a BOMStore", report["error"])

    def test_short_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "short.car"
            target.write_bytes(b"BOMStore" + bytes(4))
            report = assetcatalog.inspect_asset_catalog(target)
        self.assertFalse(report["ok"])
        self.assertIn("truncated", report["error"])

    def test_missing_file_reports_error(self) -> None:
        report = assetcatalog.inspect_asset_catalog("/nonexistent/Assets.car")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)

    def test_truncated_index_is_rejected_not_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = bytearray(build_bom([("CARHEADER", car_header_body())]))
            target = Path(tmp) / "cut.car"
            # Claim 5000 blocks with a table that cannot hold them.
            struct.pack_into(">I", data, 16, 5000)
            target.write_bytes(bytes(data))
            report = assetcatalog.inspect_asset_catalog(target)
        self.assertFalse(report["ok"])

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(31337)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(20):
                blob = root / f"r{index}.car"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 400))))
                try:
                    assetcatalog.inspect_asset_catalog(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
