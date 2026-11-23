"""Tests for the UEFI NVRAM variable reader.

Fixtures are synthesised, because a machine without UEFI firmware has no efivars
directory at all and a CI host is exactly that machine. Every byte here is written by
the test, so every expected value is chosen rather than observed — and if a real
efivars directory happens to exist, the reader is additionally checked against it.

Three bugs found while writing this reader, each pinned below:

  * The description's NUL terminator was searched with `find(b"\\x00\\x00")`, which
    matches the high byte of the *last character* plus the low byte of the
    terminator. Real output was 'Windows Boot Manager\\ufffd' — one character early,
    with a replacement char.
  * `6 + FilePathListLength` was used as the *start* of the device path. It is the
    path's Length, not its offset; treating it as an offset starts the path in the
    middle and decodes as plausible nonsense (`type-92/subtype-0` for a genuine
    Windows Boot Manager entry).
  * The attribute word only precedes the value in an efivarfs file. A raw firmware
    dump has no attribute word, and assuming one eats the first four bytes of the
    value — invisible on a 2 KB `db`, fatal on a 1-byte `SecureBoot`.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import uefi

# A GUID in canonical form, as efivarfs mangles it into the filename.
SAMPLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"  # EFI_GLOBAL_VARIABLE
BOOT_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def write_variable(directory: Path, name: str, guid: str, attributes: int,
                   value: bytes) -> Path:
    """Write an efivarfs-shaped file: 4-byte attribute word, then the value."""
    target = directory / f"{name}-{guid}"
    target.write_bytes(struct.pack("<I", attributes) + value)
    return target


def load_option(description: str, device_path: bytes) -> bytes:
    """Build an EFI_LOAD_OPTION: attributes, path length, UTF-16 description, path."""
    encoded = description.encode("utf-16-le") + b"\x00\x00"
    return (struct.pack("<IH", 0x00000001, len(device_path))
            + encoded + device_path)


def harddrive_path() -> bytes:
    """A Media/HardDrive node, a Media/FilePath node and an End node."""
    harddrive = bytes([0x04, 0x01]) + struct.pack("<H", 42) + bytes(38)
    file_path = bytes([0x04, 0x04]) + struct.pack("<H", 70) + ("\\EFI\\BOOT\\BOOTX64.EFI"
                                                               .encode("utf-16-le"))
    file_path += bytes(70 - len(file_path))
    end = bytes([0x7F, 0xFF]) + struct.pack("<H", 4)
    return harddrive + file_path + end


class BootEntryTest(unittest.TestCase):
    def test_description_terminates_one_character_late_not_early(self) -> None:
        """The terminator is a UTF-16 NUL unit at an even offset.

        Searching for b"\\x00\\x00" finds the high byte of the final character
        followed by the terminator's low byte, so 'Windows Boot Manager' comes back as
        'Windows Boot Manager\\ufffd'.
        """
        entry = load_option("Windows Boot Manager", harddrive_path())
        report = uefi.parse_boot_entry(entry)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["description"], "Windows Boot Manager")
        self.assertNotIn("\ufffd", report["description"])

    def test_odd_length_description_also_clean(self) -> None:
        entry = load_option("Linux Boot Manager", harddrive_path())
        report = uefi.parse_boot_entry(entry)
        self.assertEqual(report["description"], "Linux Boot Manager")

    def test_device_path_starts_after_the_terminator(self) -> None:
        """FilePathListLength is a length, not an offset.

        Reading it as an offset starts 116 bytes into a 116-byte path, so the nodes
        decode from the wrong bytes.
        """
        path = harddrive_path()
        report = uefi.parse_boot_entry(load_option("X", path))
        names = [node["name"] for node in report["device_path_nodes"]]
        self.assertEqual(names, ["Media/HardDrive", "Media/FilePath", "End"])

    def test_device_path_node_lengths_sum_to_the_declared_length(self) -> None:
        path = harddrive_path()
        report = uefi.parse_boot_entry(load_option("X", path))
        total = sum(node["length"] for node in report["device_path_nodes"])
        self.assertEqual(total, len(path))

    def test_truncated_entry_is_rejected(self) -> None:
        report = uefi.parse_boot_entry(b"\x01\x00")
        self.assertFalse(report["ok"])
        self.assertIn("too short", report["error"])

    def test_path_length_past_the_value_is_rejected(self) -> None:
        bad = struct.pack("<IH", 1, 9999) + b"\x00\x00"
        report = uefi.parse_boot_entry(bad)
        self.assertFalse(report["ok"])
        self.assertIn("runs past", report["error"])


class VariableFileTest(unittest.TestCase):
    def test_attributes_are_little_endian_and_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = write_variable(Path(tmp), "SecureBoot", SAMPLE_GUID, 0x6, b"\x01")
            report = uefi.inspect_uefi_variables(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["attributes"], "0x00000006")
        self.assertIn("BOOTSERVICE_ACCESS", report["attribute_names"])
        self.assertIn("RUNTIME_ACCESS", report["attribute_names"])
        self.assertEqual(report["value_size"], 1)
        self.assertTrue(report["secure_boot_enabled"])

    def test_raw_dump_without_attribute_word_does_not_lose_the_value(self) -> None:
        """secureboot.raw from a firmware dump is one byte: 0x01.

        Assuming a leading attribute word consumes it and leaves an empty value,
        which reads as Secure Boot *disabled* — the single most consequential wrong
        answer this reader could give.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "SecureBoot.raw"
            target.write_bytes(b"\x01")
            report = uefi.inspect_uefi_variables(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertFalse(report["attributes_present"])
        self.assertEqual(report["value_size"], 1)
        self.assertTrue(report["secure_boot_enabled"])

    def test_signature_list_guid_is_not_mistaken_for_attributes(self) -> None:
        """A raw `db` dump starts with an EFI_SIGNATURE_LIST, whose first bytes are a
        signature-type GUID (EFI_CERT_SHA256_GUID begins a1 59 c0 a5).

        Those four bytes are outside the attribute bit range, which is what lets the
        reader tell a raw dump from an efivarfs file. Without that check every raw
        `db` loses its first four bytes — the signature type — and the remaining
        bytes no longer line up with the declared list structure.
        """
        sha256_guid = bytes.fromhex("a159c0a5e5e34b32b3e5cfefaede68da")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "db.raw"
            target.write_bytes(sha256_guid + b"\x00" * 16)
            report = uefi.inspect_uefi_variables(target)
        self.assertFalse(report["attributes_present"])
        self.assertEqual(report["value_size"], 32)
        self.assertEqual(report["raw_value"][:8], "a159c0a5")

    def test_ambiguous_attribute_word_can_be_overridden(self) -> None:
        """The one case content cannot settle.

        A raw dump whose value happens to start with a valid attribute mask is
        indistinguishable from an efivarfs file by inspection. Guessing wrong shifts
        the value by four bytes — which for a binary structure like a signature list
        turns a parseable value into noise. The caller can state the provenance.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "db-raw.bin"
            # A signature list that begins with bytes that look like attributes.
            target.write_bytes(struct.pack("<I", 0x00000006) + b"\x01" * 8)
            inferred = uefi.inspect_uefi_variables(target)
            as_raw = uefi.inspect_uefi_variables(target, has_attributes=False)
            as_file = uefi.inspect_uefi_variables(target, has_attributes=True)
        self.assertEqual(inferred["attribute_confidence"], "inferred")
        self.assertTrue(inferred["attributes_present"])
        self.assertEqual(inferred["value_size"], 8)
        self.assertFalse(as_raw["attributes_present"])
        self.assertEqual(as_raw["value_size"], 12)
        self.assertTrue(as_file["attributes_present"])
        self.assertEqual(as_file["value_size"], 8)
        self.assertEqual(as_file["attribute_confidence"], "known")

    def test_name_with_hyphens_splits_from_the_guid_only(self) -> None:
        """Vendor variable names contain hyphens; only the trailing 36 chars are the
        GUID. Splitting on '-' truncates names like this one."""
        name = "AmiHardwareSignatureSetupUpdateCountVar"
        with tempfile.TemporaryDirectory() as tmp:
            target = write_variable(Path(tmp), name, SAMPLE_GUID, 0x7, b"\x05")
            report = uefi.inspect_uefi_variables(target)
        self.assertEqual(report["name"], name)
        self.assertEqual(report["guid"], SAMPLE_GUID)

    def test_platform_language_decodes_as_utf16(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = write_variable(Path(tmp), "PlatformLang", SAMPLE_GUID, 0x7,
                                    "en-US".encode("utf-16-le") + b"\x00\x00")
            report = uefi.inspect_uefi_variables(target)
        self.assertEqual(report.get("text"), "en-US")


class DirectoryTest(unittest.TestCase):
    def _build(self, directory: Path) -> Path:
        root = directory / "efivars"
        root.mkdir()
        write_variable(root, "SecureBoot", SAMPLE_GUID, 0x6, b"\x01")
        write_variable(root, "SetupMode", SAMPLE_GUID, 0x6, b"\x00")
        write_variable(root, "PK", SAMPLE_GUID, 0x27, b"\x00" * 32)
        write_variable(root, "KEK", SAMPLE_GUID, 0x27, b"\x00" * 32)
        write_variable(root, "db", SAMPLE_GUID, 0x27, b"\x00" * 32)
        write_variable(root, "BootOrder", SAMPLE_GUID, 0x7,
                       struct.pack("<HH", 0, 2))
        write_variable(root, "Boot0000", BOOT_GUID, 0x1,
                       load_option("Windows Boot Manager", harddrive_path()))
        write_variable(root, "Boot0002", BOOT_GUID, 0x1,
                       load_option("Linux Boot Manager", harddrive_path()))
        return root

    def test_inventory_and_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = uefi.inspect_uefi_variables(self._build(Path(tmp)))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["readable_count"], 8)
        self.assertTrue(report["secure_boot_enabled"])
        self.assertFalse(report["setup_mode"])
        self.assertIn("PK", report["security"])
        self.assertIn("enabled with PK, KEK and db", report["assessment"])

    def test_boot_order_is_decoded_from_u16_indices(self) -> None:
        """BootOrder is a plain array of u16 indices, not an EFI_LOAD_OPTION."""
        with tempfile.TemporaryDirectory() as tmp:
            report = uefi.inspect_uefi_variables(self._build(Path(tmp)))
        self.assertEqual(report["boot_order"], ["Boot0000", "Boot0002"])

    def test_boot_entries_are_parsed_with_descriptions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = uefi.inspect_uefi_variables(self._build(Path(tmp)))
        descriptions = [entry["boot_entry"]["description"]
                        for entry in report["boot_entries"]]
        self.assertEqual(descriptions, ["Windows Boot Manager", "Linux Boot Manager"])

    def test_setup_mode_is_called_out_as_dangerous(self) -> None:
        """Setup mode means the key hierarchy can be replaced by anyone local."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._build(Path(tmp))
            write_variable(root, "SetupMode", SAMPLE_GUID, 0x6, b"\x01")
            report = uefi.inspect_uefi_variables(root)
        self.assertTrue(report["setup_mode"])
        self.assertIn("SETUP MODE", report["assessment"])

    def test_incomplete_key_hierarchy_is_reported(self) -> None:
        """SecureBoot=1 with no db is not a healthy platform."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._build(Path(tmp))
            for victim in ("db", "PK", "KEK"):
                (root / f"{victim}-{SAMPLE_GUID}").unlink()
            report = uefi.inspect_uefi_variables(root)
        self.assertIn("incomplete", report["assessment"])

    def test_absent_secureboot_is_not_reported_as_disabled(self) -> None:
        """A machine with no SecureBoot variable does not support Secure Boot;
        saying 'disabled' would imply it could be enabled."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "efivars"
            root.mkdir()
            write_variable(root, "BootOrder", SAMPLE_GUID, 0x7, b"\x00\x00")
            report = uefi.inspect_uefi_variables(root)
        self.assertIsNone(report["secure_boot_enabled"])
        self.assertIn("may not support", report["assessment"])


class HostTest(unittest.TestCase):
    """If this host has real firmware variables, the reader must handle them."""

    def setUp(self) -> None:
        self.root = Path("/sys/firmware/efi/efivars")
        if not self.root.is_dir():
            self.skipTest("no efivarfs on this host")

    def test_real_firmware_is_inventoried(self) -> None:
        report = uefi.inspect_uefi_variables(self.root)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["readable_count"], 0)
        self.assertIn("assessment", report)

    def test_real_boot_entries_have_clean_descriptions(self) -> None:
        report = uefi.inspect_uefi_variables(self.root)
        for entry in report.get("boot_entries") or []:
            detail = entry.get("boot_entry") or {}
            self.assertNotIn("\ufffd", detail.get("description") or "",
                             f"{entry['name']} description has a replacement char")


class RobustnessTest(unittest.TestCase):
    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(90210)
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(20):
                blob = Path(tmp) / f"v{index}-{SAMPLE_GUID}"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 400))))
                try:
                    uefi.inspect_uefi_variables(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")

    def test_missing_path_reports_not_raises(self) -> None:
        report = uefi.inspect_uefi_variables("/nonexistent/efivars")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
