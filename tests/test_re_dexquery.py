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
              super_name: str = "Ljava/lang/Object;",
              native_methods: list[tuple[str, str]] | None = None) -> bytes:
    """Assemble a DEX with the string, type and id tables, plus optional native methods.

    `native_methods` is a list of (class name, method name). Each gets an entry in a
    `class_data_item` marked ACC_NATIVE, which is the only place the compiler records that a
    method's body lives in a shared library rather than in DEX code.
    """
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
    for _cls, method in (native_methods or []):
        intern(method)

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

    # class_data_items come after the class-def table and before the string data, because the
    # class-def records must know the offset of each one before it is written.
    class_data_blobs: dict[int, bytes] = {}
    if native_methods:
        def uleb(value: int) -> bytes:
            out = b""
            while True:
                byte = value & 0x7F
                value >>= 7
                if value:
                    out += bytes([byte | 0x80])
                else:
                    out += bytes([byte])
                    return out

        class_data_base = class_defs_off + class_defs_size * 32
        cursor = class_data_base
        for class_name in class_names:
            own = [m for cls, m in (native_methods or []) if cls == class_name]
            if not own:
                continue
            blob = uleb(0) + uleb(0) + uleb(len(own)) + uleb(0)  # static, instance, direct, virtual
            previous = 0
            for method in own:
                index = method_names.index(method)
                blob += uleb(index - previous) + uleb(0x0100) + uleb(0)  # ACC_NATIVE, no code
                previous = index
            class_data_blobs[class_names.index(class_name)] = blob
            cursor += len(blob)

    # Lay out string data, aligned to 4 bytes as the format requires.
    data_start = class_defs_off + class_defs_size * 32 + sum(len(b) for b in class_data_blobs.values())
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
    # Second pass over class_defs, now that class_data offsets are known.
    out_class_defs = bytearray()
    running = class_defs_off + class_defs_size * 32
    for position, name in enumerate(class_names):
        blob = class_data_blobs.get(position)
        class_data_off = 0
        if blob is not None:
            class_data_off = running
            running += len(blob)
        # superclass_idx is a type_ids index, not an offset. intern() gives each class its
        # superclass string immediately after its own name.
        out_class_defs += struct.pack("<IIIIIIII", strings.index(name), 0x1,
                                      strings.index(super_name), 0, 0xFFFFFFFF, 0,
                                      class_data_off, 0)
    out += bytes(out_class_defs)
    out += b"".join(class_data_blobs[key] for key in sorted(class_data_blobs))
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


class NativeMethodTest(unittest.TestCase):
    """Recovering `native` methods and the JNI symbol each one binds to.

    A `native` method has no DEX code: the body is in a `.so`, and the only link between the two
    is a naming convention. `inspect()` computed this list and `inspect_entry()` — the function
    `re apk` actually calls — did not, so the verb an analyst uses reported nothing for a package
    that had native methods. (It happens that the real APK here has none; the earlier claim that
    `inspect_entry` "dropped" them was mine and wrong, which is why the synthetic fixture below
    exists rather than a claim about a real package.)
    """

    @classmethod
    def setUpClass(cls) -> None:
        import tempfile
        cls.directory = Path(tempfile.mkdtemp(prefix="xtnat-"))
        cls.dex = build_dex(["Lcom/example/Native;"], ["loadLibrary", "doIt"],
                            native_methods=[("Lcom/example/Native;", "doIt")])

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil
        shutil.rmtree(cls.directory, ignore_errors=True)

    def test_the_fixture_really_marks_a_method_native(self) -> None:
        """Guard the fixture: a builder that silently emits nothing proves nothing."""
        from xtforge.core.re import dex as _dex
        report = _dex.native_methods(self.dex)
        self.assertEqual(report["native_method_count"], 1, report)
        self.assertEqual(report["native_methods"][0]["name"], "doIt")

    def test_a_non_native_method_is_not_listed(self) -> None:
        from xtforge.core.re import dex as _dex
        report = _dex.native_methods(self.dex)
        names = [m["name"] for m in report["native_methods"]]
        self.assertNotIn("loadLibrary", names)

    def test_the_jni_symbol_uses_underscore_for_the_package_separator(self) -> None:
        """`com/example` becomes `com_example`, not `com_1example`.

        The escaping rules exist so a package separator cannot be confused with a literal
        underscore. Applying the underscore escape before the separator replacement produced
        `Java_com_1example_Native_doIt` — a plausible-looking symbol that matches nothing.
        """
        from xtforge.core.re import dex as _dex
        report = _dex.native_methods(self.dex)
        self.assertEqual(report["jni_symbols"], ["Java_com_example_Native_doIt"])

    def test_a_literal_underscore_in_a_class_name_is_escaped(self) -> None:
        from xtforge.core.re import dex as _dex
        self.assertEqual(_dex.jni_symbol("Lcom/example/My_Class;", "run"),
                         "Java_com_example_My_1Class_run")

    def test_semicolons_and_brackets_in_a_descriptor_are_escaped(self) -> None:
        from xtforge.core.re import dex as _dex
        self.assertEqual(
            _dex.jni_symbol("Landroid/app/Activity;", "onCreate",
                            "(Landroid/os/Bundle;)V"),
            "Java_android_app_Activity_onCreate__(Landroid/os/Bundle_2)V")
        self.assertEqual(_dex.jni_symbol("Lcom/a/b/C;", "f", "[I;"),
                         "Java_com_a_b_C_f___3I_2")

    def test_the_derived_symbol_matches_a_compiled_library(self) -> None:
        """The real oracle: build a `.so` exporting the symbol and find it with `nm`."""
        import shutil
        import subprocess
        if not shutil.which("gcc") or not shutil.which("nm"):
            self.skipTest("needs gcc and nm")
        from xtforge.core.re import dex as _dex
        symbol = _dex.jni_symbol("Lcom/example/Native;", "doIt")
        source = Path(self.directory) / "n.c"
        source.write_text("__attribute__((visibility(\"default\")))\n"
                          f"void {symbol}(void *env, void *self) {{ (void)env; (void)self; }}\n")
        library = Path(self.directory) / "libnative.so"
        built = subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(library), str(source)],
                               capture_output=True, text=True)
        if built.returncode != 0:
            self.skipTest(f"build failed: {built.stderr[:120]}")
        exported = subprocess.run(["nm", "-D", "--defined-only", str(library)],
                                  capture_output=True, text=True).stdout
        self.assertIn(symbol, exported,
                      f"{symbol} is not exported by a library compiled to export it")

    def test_inspect_entry_reports_native_methods(self) -> None:
        """The function `re apk` calls must carry the data, not only `inspect`."""
        import zipfile
        from xtforge.core.re import dex as _dex
        archive = Path(self.directory) / "native.apk"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("classes.dex", self.dex)
        report = _dex.inspect_entry(archive, "classes.dex")
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["native_method_count"], 1)
        self.assertEqual(report["jni_symbols"], ["Java_com_example_Native_doIt"])

    def test_a_dex_with_no_natives_reports_zero_not_an_error(self) -> None:
        from xtforge.core.re import dex as _dex
        plain = build_dex(["Lcom/plain/Thing;"], ["go"])
        report = _dex.native_methods(plain)
        self.assertEqual(report["native_method_count"], 0)
        self.assertEqual(report["jni_symbols"], [])

    def test_truncated_input_fails_cleanly(self) -> None:
        """A truncated DEX must raise `ValueError`, not something a caller cannot anticipate.

        A too-small file is refused by the header check with a clear message; that is correct and
        the assertion says so. What must never happen is an `IndexError` or `struct.error` from
        deep inside the walk, because a caller parsing an untrusted archive has no way to
        distinguish that from a bug in its own code.
        """
        from xtforge.core.re import dex as _dex
        for cut in (16, 64, 200, len(self.dex) // 2):
            try:
                _dex.native_methods(self.dex[:cut])
            except ValueError:
                continue  # refusing a truncated file is the expected behaviour
            except Exception as exc:  # noqa: BLE001 - anything else is a defect
                self.fail(f"truncation at {cut} raised {type(exc).__name__}: {exc}")
