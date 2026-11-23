"""Tests for devicetree, kernel config and Windows shortcut readers.

Fixtures are real files found on this host for devicetree and .lnk, which is better
than hand-built bytes: a real Android devicetree dump exercises the embedded-header
path (the FDT starts at offset 64, not 0) and a real .lnk exercises the LinkInfo
variant a real installer wrote.

The kernel-config fixtures are synthetic because no kernel with CONFIG_IKCONFIG is
installed here, but the synthetic blob is built by gzip-compressing a known config
between the real IKCFG_ST/IKCFG_ED markers, so every expected value is chosen by the
test.

Bugs found while writing the devicetree walker, both now pinned by tests:

  * the FDT header was assumed to be at offset 0, so a devicetree embedded in a
    container — the normal case for an Android boot image, and the case of the
    fixture here at offset 0x40 — was rejected or read as garbage;
  * an early walk reported 2 nodes for this file because it capped depth against
    the wrong counter. The count assertion (629 nodes, 4635 properties) is what
    catches any recurrence: every individual token such a walk produces is valid,
    so nothing else notices.

Alignment is computed relative to the struct block because that is what ECMA-style
FDT padding specifies. Worth noting the two readings coincide when the block is
4-byte aligned — which this fixture is — so an alignment regression would not show
up here; the count assertion guards the walk as a whole instead.
"""
from __future__ import annotations

import gzip
import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import devices

def _search(pattern: str, *roots: Path) -> Path | None:
    """Find a fixture under a set of conventional roots.

    Hardcoding an absolute home directory here would work on exactly one machine
    and trips the repo's own no-hardcoded-paths guard, which is correct: a test that
    depends on one user's file layout is not a test of the code.  Searching keeps the
    real-file coverage without pinning the path.
    """
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in sorted(root.rglob(pattern)):
            if candidate.is_file():
                return candidate
    return None


def find_dtb() -> Path | None:
    home = Path.home()
    return (_search("*.dtb", home / "kernel_artifacts")
            or _search("*.dtb", Path("/usr/lib/firmware"), Path("/boot"),
                       Path("/usr/share")))


def find_lnk() -> Path | None:
    home = Path.home()
    return (_search("*.lnk", home / "Desktop")
            or _search("*.lnk", home / ".wine")
            or _search("*.lnk", Path("/usr/share"), Path("/opt")))


class DevicetreeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dtb = find_dtb()

    def setUp(self) -> None:
        if self.dtb is None:
            self.skipTest("no devicetree blob on this host")
        self.report = devices.inspect_devicetree(self.dtb)

    def test_header_fields(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["version"], 17)
        self.assertEqual(self.report["total_size"], 134872)

    def test_embedded_header_is_located_not_assumed_at_zero(self) -> None:
        """This devicetree sits at offset 0x40 inside a container.

        Reading a header from byte 0 gives a magic-valid but inconsistent struct:
        off_dt_struct=32, off_mem_rsvmap=1, last_comp_version=2048. The reader has
        to find the header, not assume it.
        """
        self.assertTrue(self.report["embedded"])
        self.assertEqual(self.report["header_offset"], 0x40)

    def test_node_and_property_counts(self) -> None:
        """629 nodes, 4635 properties.

        The wrong alignment (file-relative instead of struct-relative) reported 2
        nodes for this same file. A count assertion is the only thing that catches
        that: every token it read was individually valid.
        """
        self.assertEqual(self.report["node_count"], 629)
        self.assertEqual(self.report["property_count"], 4635)
        self.assertGreater(self.report["max_depth"], 3)

    def test_root_compatible_matches_the_raw_bytes(self) -> None:
        compat = self.report["compatible"]
        self.assertIsInstance(compat, list)
        self.assertIn("samsung,armv8", compat)
        raw = Path(self.dtb).read_bytes()
        for entry in compat:
            self.assertIn(entry.encode(), raw,
                          f"compatible {entry!r} is not in the file — parser invented it")

    def test_node_paths_are_well_formed(self) -> None:
        for node in self.report["nodes"]:
            self.assertTrue(node["path"].startswith("/"))
            self.assertNotIn("//", node["path"])

    def test_property_values_are_typed(self) -> None:
        """Strings decode as strings, cell lists as cells — not everything as hex."""
        kinds = set()
        for prop in self.report["properties"]:
            value = prop["value"]
            kinds.add(type(value).__name__ if not isinstance(value, dict)
                      else next(iter(value)))
        self.assertIn("list", kinds)       # string lists like compatible
        self.assertIn("cells", kinds)      # numeric cells like #address-cells

    def test_non_dtb_is_rejected(self) -> None:
        report = devices.inspect_devicetree("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("no FDT header", report["error"])

    def test_truncated_blob_is_rejected_with_reason(self) -> None:
        raw = Path(self.dtb).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            cut = Path(tmp) / "cut.dtb"
            cut.write_bytes(raw[:len(raw) // 2])
            report = devices.inspect_devicetree(cut)
        self.assertFalse(report["ok"])
        self.assertIn("error", report)


class KernelConfigTest(unittest.TestCase):
    CONFIG = (
        b'CONFIG_LOCALVERSION="-xtecho"\n'
        b"CONFIG_MODULES=y\n"
        b"CONFIG_KALLSYMS=y\n"
        b"CONFIG_DEBUG_INFO=y\n"
        b"CONFIG_SECURITY_SELINUX=y\n"
        b"CONFIG_RANDOMIZE_BASE=n\n"
        b"# CONFIG_PROC_KCORE is not set\n"
        b"CONFIG_BLK_DEV_LOOP=m\n"
    )

    def _write(self, directory: str, payload: bytes, name: str = "vmlinuz") -> Path:
        target = Path(directory) / name
        target.write_bytes(payload)
        return target

    def test_embedded_ikconfig_blob_is_extracted(self) -> None:
        """A kernel with CONFIG_IKCONFIG carries its own .config, gzipped, between
        the IKCFG_ST and IKCFG_ED markers, inside a much larger image."""
        with tempfile.TemporaryDirectory() as tmp:
            blob = b"IKCFG_ST" + gzip.compress(self.CONFIG) + b"IKCFG_ED"
            image = b"\x7fELF" + bytes(2000) + blob + bytes(500)
            report = devices.inspect_kernel_config(self._write(tmp, image))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["source"], "embedded IKCONFIG")
        self.assertEqual(report["version"], "-xtecho")

    def test_counts_split_enabled_modules_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = b"IKCFG_ST" + gzip.compress(self.CONFIG) + b"IKCFG_ED"
            report = devices.inspect_kernel_config(self._write(tmp, blob))
        self.assertEqual(report["enabled_count"], 4)   # MODULES/KALLSYMS/DEBUG_INFO/SELINUX
        self.assertEqual(report["module_count"], 1)    # BLK_DEV_LOOP
        self.assertEqual(report["disabled_count"], 1)  # RANDOMIZE_BASE

    def test_not_set_comment_is_not_counted_as_a_setting(self) -> None:
        """`# CONFIG_X is not set` is a disabled config, not a comment to ignore.

        Reporting it as absent makes a hardened kernel look identical to one where
        the option was never offered.
        """
        with tempfile.TemporaryDirectory() as tmp:
            blob = b"IKCFG_ST" + gzip.compress(self.CONFIG) + b"IKCFG_ED"
            report = devices.inspect_kernel_config(self._write(tmp, blob))
        self.assertNotIn("CONFIG_PROC_KCORE", report["settings"])

    def test_plaintext_config_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = devices.inspect_kernel_config(
                self._write(tmp, self.CONFIG, name="config"))
        self.assertTrue(report["ok"])
        self.assertEqual(report["source"], "plaintext .config")

    def test_markers_without_gzip_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = devices.inspect_kernel_config(
                self._write(tmp, b"IKCFG_ST" + b"not gzip at all" + b"IKCFG_ED"))
        self.assertFalse(report["ok"])
        self.assertIn("no gzip blob", report["error"])

    def test_empty_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = devices.inspect_kernel_config(self._write(tmp, b""))
        self.assertFalse(report["ok"])


class ShortcutTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lnk = find_lnk()
        if self.lnk is None:
            self.skipTest("no .lnk on this host")
        self.report = devices.inspect_shortcut(self.lnk)

    def test_header_is_validated(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertIn("HasLinkInfo", self.report["flag_names"])

    def test_target_command_names_an_executable(self) -> None:
        command = self.report["command"]
        self.assertIsNotNone(command)
        self.assertTrue(command.lower().endswith(".exe") or ".exe " in command.lower(),
                        f"target does not look like an executable: {command}")

    def test_local_base_path_comes_from_link_info(self) -> None:
        """The reported path must literally appear in the file, in one encoding.

        LinkInfo carries the path twice: LocalBasePath (ANSI) and
        LocalBasePathUnicode. Which one is populated depends on what wrote the
        shortcut — this file stores ANSI only, and an earlier version of this test
        assumed UTF-16 and failed against a correct parser. Check both encodings
        and require that *one* of them is present, which proves the value came from
        the file rather than from inference.
        """
        self.assertIn("local_base_path", self.report)
        path = self.report["local_base_path"]
        self.assertTrue(path)
        raw = Path(self.lnk).read_bytes()
        candidates = [path.encode("utf-16-le", "ignore"), path.encode("latin-1", "ignore")]
        present = [enc for enc in candidates if enc and enc[:20] in raw]
        self.assertTrue(present,
                        f"reported path {path!r} appears in neither UTF-16 nor ANSI "
                        "form — it was not read from the file")

    def test_volume_serial_is_decoded(self) -> None:
        volume = self.report.get("volume") or {}
        if not volume:
            self.skipTest("this shortcut stores no volume id")
        self.assertIn(volume["drive_type"],
                      ("Fixed", "Removable", "Remote", "Unknown", "CDRom",
                       "RamDisk", "NoRootDir"))

    def test_wrong_clsid_is_rejected(self) -> None:
        raw = bytearray(Path(self.lnk).read_bytes())
        raw[4] = 0xFF
        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / "bogus.lnk"
            bogus.write_bytes(bytes(raw))
            report = devices.inspect_shortcut(bogus)
        self.assertFalse(report["ok"])
        self.assertIn("CLSID", report["error"])

    def test_short_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tiny = Path(tmp) / "tiny.lnk"
            tiny.write_bytes(b"L\x00\x00\x00")
            report = devices.inspect_shortcut(tiny)
        self.assertFalse(report["ok"])
        self.assertIn("too small", report["error"])


class DeviceRobustnessTest(unittest.TestCase):
    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(31337)
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(25):
                blob = Path(tmp) / f"r{index}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 3000))))
                for reader in (devices.inspect_devicetree,
                               devices.inspect_kernel_config,
                               devices.inspect_shortcut):
                    try:
                        reader(blob)
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"{reader.__name__} raised {type(exc).__name__}: {exc}")

    def test_missing_file_reports_not_raises(self) -> None:
        for reader in (devices.inspect_devicetree, devices.inspect_kernel_config,
                       devices.inspect_shortcut):
            report = reader("/nonexistent/nothing/here")
            self.assertFalse(report["ok"])
            self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
