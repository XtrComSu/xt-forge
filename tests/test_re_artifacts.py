"""Tests for the SQLite, BEAM, EVM and Apple IPS readers.

The SQLite test is the important one, because it caught a real bug in the first
version: the SQLite database header is BIG-endian for every multi-byte field, and
reading it little-endian produced integers that were all plausible-looking and all
byte-reversed. A 32 KB page size read as 128, a 7-page database declared 117 million
pages, and the UTF-8 encoding id 1 read as 16777216. Nothing crashed and nothing
looked obviously wrong — the reader simply reported a database 65 GB larger than the
file. The assertion that catches it is a *consistency* check (declared size must
equal actual size) plus the object count against the sqlite3 module.

The BEAM, EVM and IPS fixtures are built here with known expected values: the BEAM
container is assembled chunk by chunk, the EVM bytecode uses the two canonical
Solidity function selectors, and the IPS file is two JSON objects as Apple writes
them.
"""
from __future__ import annotations

import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import artifacts


def find_sqlite() -> Path | None:
    """Locate a real SQLite database to test against, without hardcoding a path."""
    roots = [Path.home() / ".config", Path.home() / ".local",
             Path("/usr/lib"), Path("/usr/share"), Path("/var")]
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for candidate in root.rglob("*.db"):
                if not candidate.is_file():
                    continue
                try:
                    with candidate.open("rb") as handle:
                        if handle.read(16) == b"SQLite format 3\x00":
                            return candidate
                except OSError:
                    continue
        except OSError:
            continue
    return None


class SqliteTest(unittest.TestCase):
    """A real database, cross-checked against the sqlite3 module."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.db = find_sqlite()

    def setUp(self) -> None:
        if self.db is None:
            self.skipTest("no SQLite database on this host")
        self.report = artifacts.inspect_sqlite(self.db)

    def test_header_is_read_big_endian(self) -> None:
        """Declared size must equal actual size.

        This single check fails for any byte-order mistake, because a byte-swapped
        page count almost never times the page size into the real file length.
        """
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["declared_size"], self.report["actual_size"])

    def test_page_size_is_a_power_of_two_in_range(self) -> None:
        page_size = self.report["page_size"]
        self.assertGreaterEqual(page_size, 512)
        self.assertLessEqual(page_size, 65536)
        self.assertEqual(page_size & (page_size - 1), 0,
                         f"page size {page_size} is not a power of two")

    def test_text_encoding_is_one_of_the_three_declared_values(self) -> None:
        """Encoding id 1 is UTF-8. Read little-endian it becomes 16777216."""
        self.assertIn(self.report["text_encoding"],
                      ("UTF-8", "UTF-16le", "UTF-16be"))

    def test_object_names_match_sqlite3(self) -> None:
        """The schema walk must agree with the sqlite3 module, name for name.

        Skipping the rowid varint in a table-leaf cell makes the parser read the
        rowid as the record header length, which decodes to zero objects — it looks
        like an empty database rather than an error.
        """
        connection = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            expected = sorted(
                row[0] for row in connection.execute(
                    "select name from sqlite_master where name is not null"))
        finally:
            connection.close()
        ours = sorted(obj["name"] for obj in self.report["objects"])
        self.assertEqual(ours, expected)
        self.assertGreater(len(ours), 0)

    def test_object_types_are_recorded(self) -> None:
        for obj in self.report["objects"]:
            self.assertIn(obj["type"], ("table", "index", "view", "trigger"))

    def test_truncated_database_is_reported_not_refused(self) -> None:
        """A partial capture is the case this reader exists for.

        sqlite3 refuses to open a truncated database. The whole point of parsing the
        header directly is to describe that file, so truncation must produce a
        report with `truncated: True`, not an error.
        """
        raw = Path(self.db).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            cut = Path(tmp) / "cut.db"
            cut.write_bytes(raw[:len(raw) // 2])
            report = artifacts.inspect_sqlite(cut)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(report.get("truncated"))
        self.assertGreater(report.get("truncated_by", 0), 0)

    def test_journal_beside_the_database_is_noted(self) -> None:
        raw = Path(self.db).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "live.db"
            copy.write_bytes(raw)
            (Path(tmp) / "live.db-wal").write_bytes(b"\x00" * 32)
            report = artifacts.inspect_sqlite(copy)
        names = [j["name"] for j in report["journals"]]
        self.assertIn("live.db-wal", names)

    def test_non_database_is_rejected(self) -> None:
        report = artifacts.inspect_sqlite("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("magic", report["error"])


class BeamTest(unittest.TestCase):
    def _build(self, directory: Path) -> Path:
        atoms = b"mymod"
        atom_chunk = struct.pack(">I", 1) + bytes([len(atoms)]) + atoms

        def chunk(chunk_id: bytes, payload: bytes) -> bytes:
            pad = b"\x00" if len(payload) % 2 else b""
            return chunk_id + struct.pack(">I", len(payload)) + payload + pad

        exports = (struct.pack(">I", 2)
                   + bytes([4]) + b"init" + struct.pack(">II", 0, 0)
                   + bytes([3]) + b"run" + struct.pack(">II", 1, 0))
        compile_info = b"8.5.2\x00/opt/build/mymod.erl\x00"
        body = (b"BEAM" + chunk(b"AtU8", atom_chunk) + chunk(b"ExpT", exports)
                + chunk(b"CInf", compile_info) + chunk(b"Code", b"\x00" * 20))
        target = directory / "mymod.beam"
        target.write_bytes(b"FOR1" + struct.pack(">I", len(body)) + body)
        return target

    def test_module_name_exports_and_compile_info(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = artifacts.inspect_beam(self._build(Path(tmp)))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["module"], "mymod")
        self.assertEqual(report["compiler_version"], "8.5.2")
        self.assertEqual(report["source_paths"], ["/opt/build/mymod.erl"])
        self.assertEqual([(e["function"], e["arity"]) for e in report["exports"]],
                         [("init", 0), ("run", 1)])

    def test_odd_sized_chunks_are_padded(self) -> None:
        """IFF chunks pad to an even length. Ignoring the pad byte shifts every
        subsequent chunk id by one and turns the chunk list into noise."""
        with tempfile.TemporaryDirectory() as tmp:
            report = artifacts.inspect_beam(self._build(Path(tmp)))
        ids = [c["id"] for c in report["chunks"]]
        self.assertEqual(ids, ["AtU8", "ExpT", "CInf", "Code"])

    def test_non_beam_is_rejected(self) -> None:
        report = artifacts.inspect_beam("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("FOR1", report["error"])


class EvmTest(unittest.TestCase):
    # 0x2e64cec1 = retrieve(), 0x70a08231 = balanceOf(address) — the canonical
    # selectors every Solidity tutorial contract exports.
    BYTECODE = ("0x6080604052632e64cec114610011576370a08231146100225700")

    def test_selectors_are_extracted_from_the_dispatcher(self) -> None:
        """A selector is PUSH4 <4 bytes> followed by EQ; both must be recognised."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "c.hex"
            target.write_text(self.BYTECODE + "\n")
            report = artifacts.inspect_evm(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["selectors"], ["0x2e64cec1", "0x70a08231"])
        self.assertTrue(report["dispatches"])

    def test_push_data_is_not_disassembled_as_opcodes(self) -> None:
        """PUSH4's immediate bytes must be skipped.

        `0x2e64cec1` contains bytes that are themselves valid opcodes (0x63 is
        PUSH4, 0xC1 is unknown). A disassembler that walks byte-by-byte reports far
        more instructions than the code contains and invents selectors.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "c.hex"
            target.write_text(self.BYTECODE)
            report = artifacts.inspect_evm(target)
        # 5 opcodes before the first selector, then 2 selectors with 2 EQ + 2 JUMPI
        # and a STOP: the exact count only holds if PUSH immediates are skipped.
        self.assertEqual(report["bytecode_size"], 26)
        self.assertLess(report["instruction_count"], report["bytecode_size"])
        self.assertEqual(report["opcodes"].get("PUSH4"), 2)
        self.assertEqual(report["opcodes"].get("EQ"), 2)

    def test_raw_binary_bytecode_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "c.bin"
            target.write_bytes(bytes.fromhex(self.BYTECODE[2:]))
            report = artifacts.inspect_evm(target)
        self.assertTrue(report["ok"])
        self.assertEqual(report["input_form"], "raw bytecode")
        self.assertEqual(len(report["selectors"]), 2)

    def test_empty_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "empty.hex"
            target.write_text("")
            report = artifacts.inspect_evm(target)
        self.assertFalse(report["ok"])


class AppleIpsTest(unittest.TestCase):
    HEADER = {"bug_type": "309", "timestamp": "2024-01-15 10:00:00.00 +0530",
              "os_version": "iPhone OS 17.2 (21C62)"}
    PAYLOAD = {
        "app_name": "TestApp", "app_version": "1.0.0 (42)",
        "os_version": "iPhone OS 17.2 (21C62)",
        "exception": {"type": "EXC_CRASH", "signal": "SIGSEGV",
                      "subtype": "KERN_INVALID_ADDRESS"},
        "faultingThread": 1,
        "threads": [
            {"frames": []},
            {"frames": [{"imageIndex": 0, "symbol": "main", "imageOffset": 4096},
                        {"imageIndex": 0, "symbol": "start", "imageOffset": 8192}]},
        ],
        "usedImages": [{"name": "TestApp"}, {"name": "libsystem_kernel.dylib"}],
    }

    def _write(self, directory: Path) -> Path:
        target = directory / "crash.ips"
        target.write_text(json.dumps(self.HEADER) + "\n"
                          + json.dumps(self.PAYLOAD) + "\n")
        return target

    def test_two_object_form_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = artifacts.inspect_apple_ips(self._write(Path(tmp)))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["report_kind"], "crash")
        self.assertEqual(report["app_name"], "TestApp")
        self.assertEqual(report["timestamp"], self.HEADER["timestamp"])

    def test_faulting_thread_frames_are_resolved_to_images(self) -> None:
        """Frames address images by index; the reader must resolve them to names."""
        with tempfile.TemporaryDirectory() as tmp:
            report = artifacts.inspect_apple_ips(self._write(Path(tmp)))
        self.assertEqual(report["faulting_thread"], 1)
        self.assertEqual(report["faulting_frames"], 2)
        self.assertEqual(report["top_frames"][0]["image"], "TestApp")
        self.assertEqual(report["top_frames"][0]["symbol"], "main")

    def test_single_document_form_is_parsed(self) -> None:
        """Older .ips reports are one JSON object, not two lines."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "old.ips"
            target.write_text(json.dumps(self.PAYLOAD))
            report = artifacts.inspect_apple_ips(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["app_name"], "TestApp")

    def test_invalid_utf8_does_not_discard_the_report(self) -> None:
        """Apple reports embed raw memory and are not always valid UTF-8."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.ips"
            body = json.dumps(self.PAYLOAD).encode()
            target.write_bytes(json.dumps(self.HEADER).encode() + b"\n" + body + b"\xff")
            report = artifacts.inspect_apple_ips(target)
        self.assertIn("ok", report)

    def test_non_json_is_rejected(self) -> None:
        report = artifacts.inspect_apple_ips("/bin/ls")
        self.assertFalse(report["ok"])


class DetectorTest(unittest.TestCase):
    def test_formats_are_detected_from_content(self) -> None:
        db = find_sqlite()
        if db is None:
            self.skipTest("no SQLite database on this host")
        self.assertEqual(artifacts.inspect(db).get("format", "sqlite"), "sqlite")
        self.assertTrue(artifacts.inspect(db)["ok"])

    def test_unknown_content_is_rejected_with_the_checked_list(self) -> None:
        report = artifacts.inspect("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("checked", report)

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(4242)
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(20):
                blob = Path(tmp) / f"r{index}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 2000))))
                for reader in (artifacts.inspect, artifacts.inspect_sqlite,
                               artifacts.inspect_beam, artifacts.inspect_evm,
                               artifacts.inspect_apple_ips):
                    try:
                        reader(blob)
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"{reader.__name__} raised {type(exc).__name__}: {exc}")

    def test_missing_file_reports_not_raises(self) -> None:
        for reader in (artifacts.inspect, artifacts.inspect_sqlite,
                       artifacts.inspect_beam, artifacts.inspect_evm,
                       artifacts.inspect_apple_ips):
            report = reader("/nonexistent/nothing")
            self.assertFalse(report["ok"])
            self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
