"""Tests for the NTFS volume and $LogFile reader.

The oracle is a real NTFS image built with `mkntfs` from the ntfsprogs package, with a
real file written into it by `ntfscp`. `ntfsls` then gives an independent listing to
compare against — so the file names reported here are checked against another
implementation, not against the same bytes parsed twice.

What the real image proved, and what it refused to prove:

  * The MFT attribute chain is at a variable offset (56 here, not 0x30) and walking it by
    assuming a layout finds nothing.
  * Attribute values need the **update-sequence-array fixup**: the last two bytes of every
    512-byte sector are replaced on disk by a sequence number.
  * `$LogFile` data runs are **delta-coded variable-width**, and getting them wrong points
    at the wrong offset entirely — an early version of this reader reported a journal full
    of 0xFF because it computed the log's position from the raw first run bytes.
  * `mkntfs` **formats `$LogFile` without writing a restart area** — the log is all
    erased-flash 0xFF and contains no transaction records. So this reader reports
    `formatted_only: true` rather than implying a clean, empty journal. A "clean" claim
    would be indistinguishable from a formatting artifact, and wrong.

That last point is why no test here asserts transaction history: the host has no way to
mount the image read-write (no libfuse user_allow_other, no root) and no tool that writes
NTFS journal records. The honest boundary is stated in the coverage note.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import ntfs

CLUSTER = 4096


def find_ntfs_tools() -> dict[str, Path] | None:
    """The unpacked ntfsprogs binaries on this host, if present."""
    for root in (Path("/tmp/art"), Path.home() / "art"):
        if not root.is_dir():
            continue
        try:
            found = {}
            for name in ("mkntfs", "ntfscp", "ntfsls"):
                hits = list(root.rglob(name))
                hits = [hit for hit in hits if hit.is_file() and os.access(hit, os.X_OK)]
                if not hits:
                    break
                found[name] = hits[0]
            if len(found) == 3:
                libs = list(root.rglob("libntfs-3g.so*"))
                if libs:
                    found["_libdir"] = libs[0].parent
                    return found
        except OSError:
            continue
    return None


def build_image(tools: dict[str, Path], directory: Path,
                files: list[tuple[str, bytes]] | None = None) -> Path | None:
    """Format a small NTFS image and write files into it."""
    image = directory / "test.img"
    with image.open("wb") as handle:
        handle.truncate(8 * 1024 * 1024)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(tools["_libdir"])
    try:
        subprocess.run([str(tools["mkntfs"]), "-F", "-q", "-L", "XTFVOL", str(image)],
                       capture_output=True, timeout=120, check=False, env=env)
    except (OSError, subprocess.SubprocessError):
        return None
    for target, content in (files or []):
        source = directory / f"src_{target.strip('/').replace('/', '_')}"
        source.write_bytes(content)
        try:
            subprocess.run([str(tools["ntfscp"]), str(image), str(source), target],
                           capture_output=True, timeout=120, check=False, env=env)
        except (OSError, subprocess.SubprocessError):
            return None
    return image


class RealImageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.tools = find_ntfs_tools()
        cls.image = None
        cls.report = None
        if cls.tools is None:
            return
        cls.image = build_image(cls.tools, cls.root, [
            ("hello.txt", b"test content\n"),
            ("nested.bin", b"\x00\x01\x02\x03" * 64),
        ])
        if cls.image is not None:
            cls.report = ntfs.inspect_ntfs_journal(cls.image)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.tools is None:
            self.skipTest("ntfsprogs is not available on this host")
        if self.report is None:
            self.skipTest("could not build an NTFS image")

    def test_boot_sector_is_parsed(self) -> None:
        volume = self.report["volume"]
        self.assertEqual(volume["oem_id"], "NTFS")
        self.assertEqual(volume["bytes_per_sector"], 512)
        self.assertEqual(volume["cluster_size"], CLUSTER)
        self.assertGreater(volume["volume_size"], 0)

    def test_volume_serial_is_reported(self) -> None:
        self.assertTrue(self.report["volume"]["serial"].startswith("0x"))

    def test_mft_records_are_read(self) -> None:
        self.assertGreater(self.report["mft_record_count"], 10)
        records = {record["record"]: record for record in self.report["records"]}
        # The system files occupy the first records, in this order on every NTFS volume.
        self.assertEqual(records[0]["name"], "$MFT")
        self.assertEqual(records[1]["name"], "$MFTMirr")
        self.assertEqual(records[2]["name"], "$LogFile")

    def test_root_directory_is_a_directory(self) -> None:
        records = {record["record"]: record for record in self.report["records"]}
        self.assertTrue(records[5]["directory"])
        self.assertTrue(records[5]["in_use"])

    def test_written_files_appear(self) -> None:
        names = {entry["name"] for entry in self.report["entries"]}
        self.assertIn("hello.txt", names)
        self.assertIn("nested.bin", names)

    def test_names_match_an_independent_listing(self) -> None:
        """`ntfsls` is a separate implementation; its listing must agree."""
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = str(self.tools["_libdir"])
        try:
            proc = subprocess.run([str(self.tools["ntfsls"]), str(self.image)],
                                  capture_output=True, timeout=120, check=False, env=env)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("ntfsls could not be run")
        listed = {line.strip() for line in
                  proc.stdout.decode("utf-8", "replace").splitlines() if line.strip()}
        if not listed:
            self.skipTest("ntfsls produced no output")
        ours = {entry["name"] for entry in self.report["entries"]}
        self.assertTrue(listed <= ours, f"ntfsls listed {listed - ours} which we missed")

    def test_logfile_runs_are_resolved(self) -> None:
        """$LogFile's location comes from delta-coded data runs, not a byte search."""
        logfile = self.report["logfile"]
        self.assertTrue(logfile.get("present"))
        self.assertIn("log_offset", logfile)
        self.assertGreater(logfile["log_offset"], 0)
        self.assertGreater(logfile["log_clusters"], 0)
        # The offset must be cluster-aligned and inside the image.
        self.assertEqual(logfile["log_offset"] % CLUSTER, 0)
        self.assertLess(logfile["log_offset"], self.report["file_size"])

    def test_freshly_formatted_log_is_reported_as_formatted_only(self) -> None:
        """mkntfs formats $LogFile but writes no restart area.

        Reporting "clean shutdown" here would be a fabrication: the log holds no
        transactions at all. The reader must distinguish "no journal content" from "a
        journal that says the volume shut down cleanly".
        """
        logfile = self.report["logfile"]
        if logfile.get("restart_signature"):
            self.skipTest("this image actually has a restart area")
        self.assertFalse(logfile.get("shutdown") == "clean",
                         "claimed a clean shutdown without a restart signature")
        self.assertTrue(logfile.get("formatted_only"),
                        "erased log was not reported as formatted-only")

    def test_restart_page_fields_are_read_from_the_documented_offsets(self) -> None:
        """A synthetic restart page with known values, read back field by field.

        This exists because the parser originally read every restart-page field eight bytes
        early — it took the low half of `chkdsk_lsn` as `system_page_size` — so a real journal
        would have been reported with a nonsense page size and version while still looking
        structurally plausible. Offsets come from ntfs-3g's `logfile.h`:

            8 chkdsk_lsn (8 bytes) · 16 system_page_size · 20 log_page_size
            24 restart_area_offset · 26 minor_ver · 28 major_ver

        The signature is written with the values chosen so that a mis-read is obvious rather
        than subtle: 4096 read from 8 would come back as half of a non-zero LSN.
        """
        import struct
        raw = bytearray(self.image.read_bytes())
        logfile = self.report["logfile"]
        offset = logfile["log_offset"]
        page = 4096
        if offset + page > len(raw):
            self.skipTest("log offset is past the end of this image")
        area = bytearray(page)
        area[0:4] = b"RSTR"
        struct.pack_into("<H", area, 4, 0x30)          # usa_ofs
        struct.pack_into("<H", area, 6, 0x0009)        # usa_count
        struct.pack_into("<Q", area, 8, 0x1234)        # chkdsk_lsn (non-zero on purpose)
        struct.pack_into("<I", area, 16, page)         # system_page_size
        struct.pack_into("<I", area, 20, page)         # log_page_size
        struct.pack_into("<H", area, 24, 0x30)         # restart_area_offset
        struct.pack_into("<H", area, 26, 2)            # minor
        struct.pack_into("<H", area, 28, 1)            # major
        raw[offset:offset + page] = area
        patched = Path(str(self.image) + ".restart")
        patched.write_bytes(raw)
        try:
            report = ntfs.inspect_ntfs_journal(patched)
        finally:
            patched.unlink(missing_ok=True)
        found = report["logfile"]
        self.assertEqual(found["restart_signature"], "RSTR")
        self.assertEqual(found["shutdown"], "clean")
        self.assertEqual(found["system_page_size"], 4096,
                         "system_page_size read from the wrong offset")
        self.assertEqual(found["log_page_size"], 4096)
        self.assertEqual(found["major_version"], 1)
        self.assertEqual(found["minor_version"], 2)
        self.assertEqual(found["chkdsk_lsn"], 0x1234)

    def test_chkd_signature_reports_a_dirty_shutdown(self) -> None:
        """`CHKD` means the volume was checked after a dirty shutdown, not that it is clean."""
        raw = bytearray(self.image.read_bytes())
        offset = self.report["logfile"]["log_offset"]
        if offset + 8 > len(raw):
            self.skipTest("log offset is past the end of this image")
        raw[offset:offset + 4] = b"CHKD"
        patched = Path(str(self.image) + ".chkd")
        patched.write_bytes(raw)
        try:
            report = ntfs.inspect_ntfs_journal(patched)
        finally:
            patched.unlink(missing_ok=True)
        self.assertEqual(report["logfile"]["restart_signature"], "CHKD")
        self.assertEqual(report["logfile"]["shutdown"], "dirty")

    def test_fixups_are_applied_to_resident_values(self) -> None:
        """The update-sequence array must be undone before attributes are read.

        Each 512-byte sector's last two bytes are replaced on disk by a sequence number.
        A record's first attributes never cross that boundary, so a reader that skips the
        fixup still returns correct FILE_NAMEs and looks right — the corruption only shows
        up inside attribute values that straddle it. This test recomputes one such value
        from the raw image both ways and requires the fixed digest.
        """
        import hashlib
        raw_image = self.image.read_bytes()
        volume = self.report["volume"]
        mft_offset = volume["mft_offset"]
        bps = volume["bytes_per_sector"]
        checked = 0
        for record in self.report["records"]:
            # A record can hold several attributes of the same type (a file has both a
            # POSIX and a Win32 FILE_NAME), so collect every digest rather than keying a
            # dict by type — a dict silently drops all but the last.
            stored = [entry["sha1"] for entry in record.get("resident_values", [])]
            if not any(entry["type"] == "0x90"
                       for entry in record.get("resident_values", [])):
                continue
            start = mft_offset + record["record"] * 1024
            chunk = bytearray(raw_image[start:start + 1024])
            if chunk[:4] != b"FILE":
                continue
            (usa_offset, usa_count) = struct.unpack_from("<HH", chunk, 4)
            attributes_offset, = struct.unpack_from("<H", chunk, 20)
            # Find the 0x90 attribute and read its resident value without fixing up.
            cursor = attributes_offset
            while cursor + 8 <= len(chunk):
                kind, = struct.unpack_from("<I", chunk, cursor)
                if kind in (0xFFFFFFFF, 0):
                    break
                length, = struct.unpack_from("<I", chunk, cursor + 4)
                if length < 8:
                    break
                non_resident = chunk[cursor + 8]
                if kind == 0x90 and not non_resident:
                    value_length, = struct.unpack_from("<I", chunk, cursor + 16)
                    value_offset, = struct.unpack_from("<H", chunk, cursor + 20)
                    raw_value = bytes(chunk[cursor + value_offset:
                                            cursor + value_offset + value_length])
                    # Only attribute values that straddle a sector boundary differ.
                    end = cursor + value_offset + value_length
                    # The last two bytes of each sector are replaced, so a value whose
                    # END lands exactly on the boundary still contains those bytes:
                    # span 368..512 covers offsets 510 and 511.
                    if not any(cursor + value_offset < boundary < end
                               or end == boundary + 2
                               for boundary in (bps - 2, 2 * bps - 2)):
                        cursor += length
                        continue
                    fixed = bytearray(chunk)
                    for index in range(1, usa_count):
                        position = index * bps - 2
                        source = usa_offset + index * 2
                        if position + 2 <= len(fixed) and source + 2 <= len(fixed):
                            fixed[position:position + 2] = fixed[source:source + 2]
                    fixed_value = bytes(fixed[cursor + value_offset:
                                              cursor + value_offset + value_length])
                    if raw_value == fixed_value:
                        cursor += length
                        continue
                    expected = hashlib.sha1(fixed_value).hexdigest()[:16]
                    self.assertIn(expected, stored,
                                  f"record {record['record']}: resident value crossing "
                                  f"a sector boundary was not fixed up")
                    checked += 1
                cursor += length
        self.assertGreater(checked, 0,
                           "no resident value crossed a sector boundary, so this test "
                           "could not observe the fixup")

    def test_result_is_json_serialisable(self) -> None:
        import json
        json.dumps(self.report)

    def test_no_private_keys_leak(self) -> None:
        for record in self.report["records"]:
            for key in record:
                self.assertFalse(key.startswith("_"), f"private key {key} leaked")


class SyntheticImageTest(unittest.TestCase):
    def _boot_sector(self, *, oem: bytes = b"NTFS    ", cluster: int = 8,
                     mft_cluster: int = 4, size: int = 1 << 20) -> bytes:
        sector = bytearray(512)
        sector[3:11] = oem
        struct.pack_into("<H", sector, 11, 512)
        sector[13] = cluster
        struct.pack_into("<Q", sector, 40, size // 512)
        struct.pack_into("<Q", sector, 48, mft_cluster)
        struct.pack_into("<Q", sector, 72, 0xDEADBEEFCAFEF00D)
        return bytes(sector)

    def test_non_ntfs_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.img"
            path.write_bytes(bytes(512))
            report = ntfs.inspect_ntfs_journal(path)
        self.assertFalse(report["ok"])
        self.assertIn("not an NTFS volume", report["error"])

    def test_short_image_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.img"
            path.write_bytes(b"NTFS    " + bytes(8))
            report = ntfs.inspect_ntfs_journal(path)
        self.assertFalse(report["ok"])

    def test_zero_cluster_size_is_rejected(self) -> None:
        """A zero cluster size would make every offset divide-by-zero or zero."""
        sector = bytearray(self._boot_sector())
        sector[13] = 0
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.img"
            path.write_bytes(bytes(sector) + bytes(4096))
            report = ntfs.inspect_ntfs_journal(path)
        self.assertFalse(report["ok"])

    def test_empty_volume_parses_with_no_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.img"
            path.write_bytes(self._boot_sector() + bytes(1 << 20))
            report = ntfs.inspect_ntfs_journal(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["mft_record_count"], 0)
        self.assertEqual(report["logfile"], {})

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(90210)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(12):
                blob = root / f"r{index}.img"
                payload = bytearray(bytes(random.randrange(256)
                                          for _ in range(random.randint(0, 3000))))
                if len(payload) > 11:
                    payload[3:11] = b"NTFS    "
                blob.write_bytes(bytes(payload))
                try:
                    ntfs.inspect_ntfs_journal(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")


class DataRunTest(unittest.TestCase):
    """The mapping-pairs decoder, tested directly.

    Isolation matters: a wrong decode still yields a positive offset inside the image, so
    an integration test alone cannot tell a correct run from a plausible one.
    """

    def _record_with_runs(self, runs: bytes) -> tuple[bytes, int]:
        # Build an attribute whose mapping pairs start at +64 of a 1024-byte record.
        record = bytearray(1024)
        struct.pack_into("<I", record, 0, 0x80)      # DATA
        struct.pack_into("<I", record, 4, 72)        # length
        record[8] = 1                                # non-resident
        struct.pack_into("<H", record, 32, 64)       # data runs offset
        record[64:64 + len(runs)] = runs
        return bytes(record), 0

    def test_single_run(self) -> None:
        # header 0x22: 2 length bytes, 2 offset bytes; length 256, offset 512
        record, offset = self._record_with_runs(
            b"\x22\x00\x01\x00\x02\x00\x00")
        runs = ntfs._data_runs(record, offset)
        self.assertEqual(runs, [(512, 256)])

    def test_negative_delta_is_signed(self) -> None:
        """A delta is signed: a run may point backwards from the previous one.

        Read as unsigned, 0xFE becomes 254 instead of -2, putting the run 256 clusters
        past where it belongs.
        """
        record, offset = self._record_with_runs(
            b"\x22\x00\x01\x00\x02" + b"\x22\x00\x01\xfe\xff" + b"\x00")
        runs = ntfs._data_runs(record, offset)
        self.assertEqual(runs[0], (512, 256))
        self.assertEqual(runs[1], (510, 256))

    def test_terminator_stops_the_chain(self) -> None:
        record, offset = self._record_with_runs(
            b"\x22\x00\x01\x00\x02" + b"\x00" + b"\x22\x00\x01\x00\x02")
        runs = ntfs._data_runs(record, offset)
        self.assertEqual(len(runs), 1)

    def test_variable_width_length(self) -> None:
        # 3 length bytes, 1 offset byte
        record, offset = self._record_with_runs(
            b"\x13\x00\x00\x01\x05" + b"\x00")
        runs = ntfs._data_runs(record, offset)
        self.assertEqual(runs, [(5, 0x010000)])


if __name__ == "__main__":
    unittest.main()


class RestartAreaParsingTest(unittest.TestCase):
    """The restart-area path, exercised with a synthetic but correctly shaped area.

    This is deliberately separate from the real-image tests. No tool on this host writes an
    NTFS journal — `mkntfs` formats `$LogFile` and leaves it all-0xFF, `ntfscp` refuses to
    run on a volume with a scheduled check, and mounting needs root — so the `RSTR`/`CHKD`
    branch cannot be reached from a real image here.

    Building the restart area by hand tests the *parser*, and it is worth doing because the
    alternative is an untested branch that silently mis-reads a real Windows log. What it
    does NOT prove is that the record layout matches a real Windows `$LogFile`; that needs a
    Windows-written image. The reader's own coverage row stays `partial` for that reason.
    """

    def _volume(self) -> object:
        """A minimal volume built from a real boot sector, 512-byte / 8-sector clusters."""
        boot = bytearray(512)
        boot[3:11] = b"NTFS    "
        struct.pack_into("<H", boot, 11, 512)     # bytes per sector
        boot[13] = 8                              # sectors per cluster -> 4096 bytes
        struct.pack_into("<Q", boot, 40, 1024)    # total sectors
        struct.pack_into("<Q", boot, 48, 4)       # $MFT cluster
        struct.pack_into("<Q", boot, 72, 0x1234)  # serial
        return ntfs._Volume(bytes(boot))

    def _image_with_log(self, log: bytes, cluster: int = 4) -> tuple[bytes, dict]:
        """An image whose $MFT record 2 points at `log`, plus that MFT record."""
        start = cluster * 4096
        raw = bytearray(start + len(log) + 4096)
        raw[start:start + len(log)] = log
        record = {"record": 2, "_runs": [(cluster, len(log) // 4096 or 1)]}
        return bytes(raw), record

    def _restart_page(self, signature: bytes = b"RSTR", *, chkdsk_lsn: int = 0,
                      system_page_size: int = 4096, log_page_size: int = 4096,
                      restart_offset: int = 0x30, minor: int = 1,
                      major: int = 5) -> bytes:
        """A restart page laid out per ntfs-3g's `logfile.h`.

        The first version of `test_clean_restart_area_is_parsed` packed its fields with the
        same wrong offsets the parser used (page sizes at 8), so test and code agreed on a
        layout that does not exist and neither could catch the other. Offsets now come from
        the header:

            8 chkdsk_lsn (8) · 16 system_page_size · 20 log_page_size
            24 restart_area_offset · 26 minor_ver · 28 major_ver
        """
        log = bytearray(4096)
        log[0:4] = signature
        struct.pack_into("<H", log, 4, 0x30)          # usa_ofs
        struct.pack_into("<H", log, 6, 0x0009)        # usa_count
        struct.pack_into("<Q", log, 8, chkdsk_lsn)
        struct.pack_into("<I", log, 16, system_page_size)
        struct.pack_into("<I", log, 20, log_page_size)
        struct.pack_into("<H", log, 24, restart_offset)
        struct.pack_into("<H", log, 26, minor)
        struct.pack_into("<H", log, 28, major)
        return bytes(log)

    def test_clean_restart_area_is_parsed(self) -> None:
        log = self._restart_page()
        raw, record = self._image_with_log(log)
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertEqual(area["restart_signature"], "RSTR")
        self.assertEqual(area["shutdown"], "clean")
        self.assertEqual(area["system_page_size"], 4096)
        self.assertEqual(area["log_page_size"], 4096)
        self.assertEqual(area["major_version"], 5)
        self.assertEqual(area["minor_version"], 1)
        self.assertEqual(area["restart_area_offset"], 0x30)

    def test_a_non_zero_chkdsk_lsn_is_read_from_its_own_field(self) -> None:
        """The bug was reading `system_page_size` from the LSN's low half.

        A page whose LSN is deliberately large makes that mis-read unmistakable: reading at
        8 yields 0x5678 instead of 4096, and reading `chkdsk_lsn` from the wrong place yields
        a value built out of page-size bytes.
        """
        log = self._restart_page(chkdsk_lsn=0x1234_5678_9ABC)
        raw, record = self._image_with_log(log)
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertEqual(area["chkdsk_lsn"], 0x1234_5678_9ABC)
        self.assertEqual(area["system_page_size"], 4096,
                         "system_page_size was read from the chkdsk_lsn field")
        self.assertEqual(area["log_page_size"], 4096)
        self.assertEqual(area["major_version"], 5)

    def test_page_sizes_and_version_are_independent(self) -> None:
        """Distinct values in every field, so a shifted read cannot look correct."""
        log = self._restart_page(system_page_size=4096, log_page_size=512,
                                 minor=7, major=3, restart_offset=0x50)
        raw, record = self._image_with_log(log)
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertEqual(area["system_page_size"], 4096)
        self.assertEqual(area["log_page_size"], 512)
        self.assertEqual(area["minor_version"], 7)
        self.assertEqual(area["major_version"], 3)
        self.assertEqual(area["restart_area_offset"], 0x50)

    def test_dirty_restart_area_is_parsed(self) -> None:
        """CHKD means the volume was not shut down cleanly."""
        log = bytearray(4096)
        log[0:4] = b"CHKD"
        raw, record = self._image_with_log(bytes(log))
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertEqual(area["restart_signature"], "CHKD")
        self.assertEqual(area["shutdown"], "dirty")

    def test_restart_area_offset_is_reported(self) -> None:
        """A restart area need not start at the beginning of the log."""
        log = bytearray(4096)
        log[1024:1028] = b"RSTR"
        raw, record = self._image_with_log(bytes(log))
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertEqual(area["offset_in_log"], 1024)

    def test_erased_log_is_not_a_clean_shutdown(self) -> None:
        """All-0xFF is "no journal", which must not be reported as "clean"."""
        raw, record = self._image_with_log(b"\xff" * 4096)
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertFalse(area.get("shutdown") == "clean")
        self.assertTrue(area["formatted_only"])
        self.assertEqual(area["erased_bytes"], 4096)

    def test_zeroed_log_is_also_not_a_clean_shutdown(self) -> None:
        raw, record = self._image_with_log(bytes(4096))
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertFalse(area.get("shutdown") == "clean")
        self.assertTrue(area["formatted_only"])
        self.assertEqual(area["zero_bytes"], 4096)

    def test_partially_written_log_is_not_formatted_only(self) -> None:
        """Real content mixed with erased space must not be called formatted-only."""
        log = bytearray(b"\xff" * 4096)
        log[2048:2064] = b"some transaction"
        raw, record = self._image_with_log(bytes(log))
        area = ntfs._logfile_restart(raw, self._volume(), [record])
        self.assertFalse(area.get("formatted_only"))
        self.assertFalse(area.get("shutdown") == "clean")

    def test_no_logfile_record_returns_empty(self) -> None:
        area = ntfs._logfile_restart(bytes(8192), self._volume(), [])
        self.assertEqual(area, {})

    def test_truncated_restart_area_does_not_raise(self) -> None:
        """A signature with no room for the rest must not raise."""
        log = bytearray(4096)
        log[0:4] = b"RSTR"
        raw, record = self._image_with_log(bytes(log))
        try:
            area = ntfs._logfile_restart(raw[:16], self._volume(), [record])
        except Exception as exc:  # noqa: BLE001
            self.fail(f"raised {type(exc).__name__}: {exc}")
        self.assertIsInstance(area, dict)
