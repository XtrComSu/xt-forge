"""Class search and reference tracing over .dex and .apk files.

These two capabilities were filed in the breadth matrix under "ADB device and package
management", excluded as requiring a device. Nothing about either needs one: listing classes
and finding where a symbol is declared are reads of the DEX tables this engine already parses.
Moving them out of that row is what made the missing verbs visible.

The tests use a synthetic DEX built here rather than a real APK, so the expected class and
method names are known exactly instead of being whatever the host happens to carry. A real-APK
test runs too when one is present, because a parser only ever exercised on its own fixture can
agree with itself.
"""
from __future__ import annotations

import glob
import os
import struct
import unittest
from pathlib import Path

from xtforge.core.re import dex

# A minimal but structurally valid DEX: header, string ids, type ids, method ids, class defs.
def build_dex(class_names: list[str], method_names: list[str],
              super_name: str = "Ljava/lang/Object;") -> bytes:
    """Assemble a DEX whose only real content is the string, type and id tables."""
    strings: list[str] = []
    def intern(text: str) -> int:
        if text not in strings:
            strings.append(text)
        return strings.index(text)
    for name in class_names:
        intern(name)
        intern(super_name)
    for name in method_names:
        intern(name)

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    # String data follows the id tables.
    type_ids_off = string_ids_off + string_ids_size * 4
    type_ids_size = len(strings)
    method_ids_off = type_ids_off + type_ids_size * 4
    method_ids_size = len(method_names)
    class_defs_off = method_ids_off + method_ids_size * 8
    class_defs_size = len(class_names)

    # Lay out string data, aligned to 4 bytes as the format requires.
    data_start = class_defs_off + class_defs_size * 32
    string_data = b""
    offsets: list[int] = []
    for text in strings:
        offsets.append(data_start + len(string_data))
        encoded = text.encode("utf-8")
        # uleb128 length followed by the bytes and a NUL.
        length = len(encoded)
        leb = b""
        value = length
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                leb += bytes([byte | 0x80])
            else:
                leb += bytes([byte])
                break
        string_data += leb + encoded + b"\x00"
    while len(string_data) % 4:
        string_data += b"\x00"

    out = bytearray(header_size)
    out += b"".join(struct.pack("<I", offset) for offset in offsets)
    out += b"".join(struct.pack("<I", index) for index in range(type_ids_size))
    for name in method_names:
        # class_idx points into type_ids; entry 0 is the first interned string, which is a
        # class name in these fixtures.
        out += struct.pack("<HHI", 0, 0, strings.index(name))
    for name in class_names:
        # superclass_idx is a type_ids index, not an offset. The fixture writes
        # 0xFFFFFFFF (NO_INDEX) for every class, which correctly resolves to None — so the
        # test asserting a resolved superclass was asserting a value the fixture never encoded.
        # intern() gives each class its superclass string immediately after its own name.
        out += struct.pack("<IIIIIIII", strings.index(name), 0x1,
                           strings.index(super_name), 0, 0xFFFFFFFF, 0, 0, 0)
    out += string_data

    # Header fields the reader validates.
    # "dex\n" + three ASCII version digits + a NUL terminator. Packing the version as a
    # little-endian int put the terminator at the wrong byte and the reader refused the file.
    out[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", out, 32, len(out))          # file_size
    struct.pack_into("<I", out, 36, header_size)       # header_size
    struct.pack_into("<I", out, 40, 0x12345678)        # endian_tag
    struct.pack_into("<I", out, 56, string_ids_size)
    struct.pack_into("<I", out, 60, string_ids_off)
    struct.pack_into("<I", out, 64, type_ids_size)
    struct.pack_into("<I", out, 68, type_ids_off)
    struct.pack_into("<I", out, 88, method_ids_size)
    struct.pack_into("<I", out, 92, method_ids_off)
    struct.pack_into("<I", out, 96, class_defs_size)
    struct.pack_into("<I", out, 100, class_defs_off)
    struct.pack_into("<I", out, 104, len(string_data))
    struct.pack_into("<I", out, 108, data_start)
    return bytes(out)


REAL_APK = (sorted(glob.glob(os.path.expanduser("~/XT-OSS-Exynos9611/flash/*.apk"))) or [None])[0]


class ClassSearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = Path(__import__("tempfile").mkdtemp(prefix="xtdex-"))
        cls.dex_path = cls.directory / "classes.dex"
        cls.dex_path.write_bytes(build_dex(
            ["Lcom/example/AlphaActivity;", "Lcom/example/BetaService;", "Lcom/other/Gamma;"],
            ["onCreate", "onStart", "helper"]))

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil
        shutil.rmtree(cls.directory, ignore_errors=True)

    def test_a_substring_matches_the_expected_classes(self) -> None:
        report = dex.search_classes(self.dex_path, "Activity")
        self.assertTrue(report["ok"], report.get("error"))
        names = [item["name"] for item in report["matches"]]
        self.assertEqual(names, ["Lcom/example/AlphaActivity;"])

    def test_matching_is_case_insensitive(self) -> None:
        """Class names are case-sensitive by spec but a search is not a lookup."""
        report = dex.search_classes(self.dex_path, "activity")
        self.assertEqual([item["name"] for item in report["matches"]],
                         ["Lcom/example/AlphaActivity;"])

    def test_the_superclass_is_resolved(self) -> None:
        report = dex.search_classes(self.dex_path, "Alpha")
        self.assertEqual(report["matches"][0]["superclass"], "Ljava/lang/Object;")

    def test_the_scanned_count_reflects_the_real_total(self) -> None:
        """`classes_scanned` must count every class, not only the matches."""
        report = dex.search_classes(self.dex_path, "Gamma")
        self.assertEqual(report["classes_scanned"], 3)
        self.assertEqual(report["match_count"], 1)

    def test_no_match_is_zero_not_an_error(self) -> None:
        report = dex.search_classes(self.dex_path, "DoesNotExist")
        self.assertTrue(report["ok"])
        self.assertEqual(report["match_count"], 0)

    def test_an_empty_pattern_is_refused(self) -> None:
        report = dex.search_classes(self.dex_path, "")
        self.assertFalse(report["ok"])
        self.assertIn("pattern is required", report["error"])

    def test_an_invalid_regex_is_refused(self) -> None:
        report = dex.search_classes(self.dex_path, "[unclosed")
        self.assertFalse(report["ok"])
        self.assertIn("invalid pattern", report["error"])

    def test_the_limit_is_honoured_and_reported(self) -> None:
        report = dex.search_classes(self.dex_path, "Lcom", limit=1)
        self.assertEqual(len(report["matches"]), 1)
        self.assertTrue(report["truncated"])

    def test_the_walk_stops_early_on_a_large_input(self) -> None:
        """The early break is what keeps a broad pattern over a big APK cheap.

        With only three fixture classes, removing the break changes nothing observable — the
        `limit=1` test still passes because the result is sliced anyway. The break only earns
        its place when there are far more matches than the limit, so this checks
        `classes_scanned`, which is the field that reveals a full walk.
        """
        names = [f"Lcom/example/Generated{index:04d};" for index in range(400)]
        path = self.directory / "many.dex"
        path.write_bytes(build_dex(names, ["m"]))
        report = dex.search_classes(path, "Generated", limit=5)
        self.assertEqual(len(report["matches"]), 5)
        self.assertTrue(report["truncated"])
        self.assertLess(report["classes_scanned"], 50,
                        f"the walk scanned {report['classes_scanned']} classes for a limit "
                        "of 5, so it did not stop early")

    def test_a_missing_file_is_refused(self) -> None:
        self.assertFalse(dex.search_classes("/nonexistent/x.apk", "A")["ok"])


class ReferenceTraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = Path(__import__("tempfile").mkdtemp(prefix="xtdexr-"))
        cls.dex_path = cls.directory / "classes.dex"
        cls.dex_path.write_bytes(build_dex(
            ["Lcom/example/Alpha;"], ["onCreate", "onCreateOptionsMenu", "unrelated"]))

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil
        shutil.rmtree(cls.directory, ignore_errors=True)

    def test_a_method_name_is_found(self) -> None:
        report = dex.trace_references(self.dex_path, "onCreate")
        self.assertTrue(report["ok"], report.get("error"))
        names = {item["name"] for item in report["references"]}
        # Both the exact name and the longer one containing it are references to the prefix.
        self.assertIn("onCreate", names)
        self.assertIn("onCreateOptionsMenu", names)
        self.assertNotIn("unrelated", names)

    def test_the_declaring_class_is_reported(self) -> None:
        report = dex.trace_references(self.dex_path, "onCreateOptionsMenu")
        self.assertEqual(report["references"][0]["class"], "Lcom/example/Alpha;")

    def test_an_absent_symbol_is_zero_not_an_error(self) -> None:
        report = dex.trace_references(self.dex_path, "zzz_not_here")
        self.assertTrue(report["ok"])
        self.assertEqual(report["reference_count"], 0)

    def test_an_empty_symbol_is_refused(self) -> None:
        self.assertFalse(dex.trace_references(self.dex_path, "")["ok"])


class ArchiveTest(unittest.TestCase):
    def test_both_verbs_read_inside_an_apk(self) -> None:
        import tempfile
        import zipfile
        directory = tempfile.mkdtemp(prefix="xtapk-")
        try:
            path = Path(directory) / "a.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", build_dex(
                    ["Lcom/example/FromApk;"], ["fromApkMethod"]))
                archive.writestr("classes2.dex", build_dex(
                    ["Lcom/example/Second;"], ["secondMethod"]))
            found = dex.search_classes(path, "FromApk")
            self.assertEqual(found["dex_entries"], 2,
                             "both .dex entries must be scanned")
            self.assertEqual(found["matches"][0]["entry"], "classes.dex")
            traced = dex.trace_references(path, "secondMethod")
            self.assertEqual(traced["references"][0]["entry"], "classes2.dex")
        finally:
            import shutil
            shutil.rmtree(directory, ignore_errors=True)


@unittest.skipUnless(REAL_APK, "no real APK on this host")
class RealApkTest(unittest.TestCase):
    def test_classes_are_found_in_a_real_package(self) -> None:
        report = dex.search_classes(REAL_APK, "Activity")
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["classes_scanned"], 0)
        self.assertGreater(report["match_count"], 0)

    def test_a_real_superclass_chain_is_resolved(self) -> None:
        """A framework superclass proves type resolution works, not just name matching."""
        report = dex.search_classes(REAL_APK, "Activity")
        supers = {item.get("superclass") for item in report["matches"]}
        self.assertTrue(any(superclass and "Landroid" in superclass
                            for superclass in supers if superclass),
                        f"no framework superclass resolved: {list(supers)[:4]}")

    def test_references_in_a_real_package_are_found(self) -> None:
        report = dex.trace_references(REAL_APK, "onCreate")
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["reference_count"], 0)


if __name__ == "__main__":
    unittest.main()
