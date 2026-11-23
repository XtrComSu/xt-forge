"""Tests for the Objective-C metadata reader.

The oracle is `llvm-objdump --macho --objc-meta-data`, and the fixtures are real
Mach-O images produced by clang for `x86_64-apple-macos11`, linked with ld64.lld.
Testing against a real compiler's output matters here because Objective-C metadata is
a pointer graph, not a record format: a reader can be self-consistently wrong about
every offset and still produce a plausible class list from its own fixture.

Four things this reader has to get right, each pinned by a test:

  * **The vmaddr-to-fileoff slide.** Object files are identity-mapped; linked images
    are not. Reading a linked image's pointers as file offsets lands in unrelated
    bytes. The linked fixture is the one that catches this.
  * **entsize_and_flags.** The "relative method list" marker is bit 31, not bit 0, and
    the entry size lives in the low 30 bits. Masking with 1 gets the mode wrong.
  * **The relative-name double hop.** A relative method entry may point straight at
    the selector string, or at a slot in __objc_selrefs holding the real pointer.
    There is no flag for which; the bytes decide.
  * **The metaclass.** Every class has a metaclass with the same name and its own
    method list. Emitting both doubles the class count and puts class methods in a
    phantom class.

Where clang is unavailable the test skips rather than passing vacuously.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import objc

OBJC_SOURCE = """
__attribute__((objc_root_class))
@interface RootBase { id isa; } @end
@implementation RootBase @end

@protocol Renderable
- (void)render;
@end

@interface Sprite : RootBase <Renderable> @end
@implementation Sprite
- (void)render {}
@end

@interface Widget : RootBase
- (int)computeValue:(int)x;
+ (id)sharedWidget;
@end
@implementation Widget
- (int)computeValue:(int)x { return x * 2; }
+ (id)sharedWidget { return 0; }
@end
"""

# Expected values, taken from `llvm-objdump --macho --objc-meta-data` on the image
# built from OBJC_SOURCE. These are the oracle's numbers, not the reader's.
EXPECTED_CLASSES = {"RootBase", "Sprite", "Widget"}
EXPECTED_SUPERCLASS = {"Sprite": "RootBase", "Widget": "RootBase"}
EXPECTED_METHODS = {"Widget": [("computeValue:", "i20@0:8i16")],
                    "Sprite": [("render", "v16@0:8")]}
# Class methods ("+foo") live in the metaclass, not in the class's own class_ro_t, so
# a reader that only follows the class reports this list as empty.
EXPECTED_CLASS_METHODS = {"Widget": ["sharedWidget"]}
EXPECTED_PROTOCOLS = {"Renderable": [("render", "v16@0:8")]}


def _find_tool(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _build(directory: Path, *, link: bool) -> Path | None:
    """Compile — and optionally link — the ObjC fixture. None if tooling is absent."""
    clang = _find_tool("clang")
    if clang is None:
        return None
    source = directory / "fixture.m"
    source.write_text(OBJC_SOURCE)
    if not link:
        target = directory / "fixture.o"
        command = [clang, "-target", "x86_64-apple-macos11", "-c",
                   "-o", str(target), str(source)]
    else:
        obj = directory / "fixture_link.o"
        build = subprocess.run(
            [clang, "-target", "x86_64-apple-macos11", "-c", "-o", str(obj),
             str(source)], capture_output=True, text=True)
        if build.returncode != 0:
            return None
        linker = _find_tool("ld64.lld", "ld64")
        if linker is None:
            return None
        target = directory / "fixture.dylib"
        # -undefined dynamic_lookup: the fixture references libobjc symbols
        # (__objc_empty_cache) that are not resolvable on a Linux host.
        command = [linker, "-arch", "x86_64", "-platform_version", "macos", "11.0",
                   "11.0", "-dylib", "-undefined", "dynamic_lookup",
                   "-o", str(target), str(obj)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0 or not target.is_file():
        return None
    return target


class _FixtureBase(unittest.TestCase):
    link = True

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = _build(Path(cls._tmp.name), link=cls.link)
        if cls.path is None:
            cls._tmp.cleanup()
            cls.path = None

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.path is not None:
            cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("clang/ld64.lld unavailable for a Mach-O ObjC fixture")
        self.report = objc.inspect_objc(self.path)

    @property
    def classes(self) -> dict:
        return {cls["name"]: cls
                for image in self.report["images"] for cls in image["classes"]}

    @property
    def protocols(self) -> dict:
        return {proto["name"]: proto
                for image in self.report["images"] for proto in image["protocols"]}


class LinkedImageTest(_FixtureBase):
    """The real-world case: a linked image, where pointers are vmaddrs."""

    link = True

    def test_reports_ok_and_has_objc(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertTrue(self.report["has_objc"])

    def test_class_names_match_the_oracle(self) -> None:
        self.assertEqual(set(self.classes), EXPECTED_CLASSES)

    def test_class_count_is_not_inflated(self) -> None:
        """Three @interfaces produce three classes.

        Each class also has a metaclass with the *same name*. __objc_classlist holds
        only the real classes, so the metaclasses are reached through class_t.isa
        rather than walked as entries of their own.
        """
        self.assertEqual(self.report["class_count"], 3)

    def test_class_methods_come_from_the_metaclass(self) -> None:
        """`+sharedWidget` is not in the class's class_ro_t.

        Class methods live in the metaclass, reached through class_t.isa. Reading only
        the class reports every class as having instance methods and none else, which
        silently hides factory and shared-instance methods — often the most
        interesting surface of a class.
        """
        for name, expected in EXPECTED_CLASS_METHODS.items():
            actual = [m["name"] for m in self.classes[name].get("class_methods") or []]
            self.assertEqual(actual, expected, f"class methods for {name}")
        # Widget declares one instance method and one class method; they must not be
        # merged into a single list.
        self.assertEqual([m["name"] for m in self.classes["Widget"]["methods"]],
                         [name for name, _ in EXPECTED_METHODS["Widget"]])

    def test_superclass_is_resolved(self) -> None:
        """RootBase is a root class, so it has no superclass; the others do."""
        self.assertNotIn("superclass", self.classes["RootBase"])
        for name, expected in EXPECTED_SUPERCLASS.items():
            self.assertEqual(self.classes[name].get("superclass"), expected)

    def test_methods_and_type_encodings(self) -> None:
        """Names *and* type encodings, matching llvm-objdump byte for byte.

        Type encodings are the strongest check available: they come from a different
        string table, so a reader that fumbles the relative-offset resolution usually
        gets one right and the other wrong.
        """
        for name, expected in EXPECTED_METHODS.items():
            actual = [(m["name"], m.get("types"))
                      for m in self.classes[name].get("methods") or []]
            self.assertEqual(actual, expected, f"methods for {name}")

    def test_protocol_conformance_link(self) -> None:
        """Sprite declares <Renderable>; Widget does not."""
        self.assertEqual(self.classes["Sprite"].get("protocols"), ["Renderable"])
        self.assertNotIn("protocols", self.classes["Widget"])

    def test_protocol_definition_and_its_methods(self) -> None:
        self.assertIn("Renderable", self.protocols)
        methods = [(m["name"], m.get("types"))
                   for m in self.protocols["Renderable"].get("instance_methods") or []]
        self.assertEqual(methods, EXPECTED_PROTOCOLS["Renderable"])

    def test_objc_sections_are_listed(self) -> None:
        sections = self.report["images"][0]["sections"]
        self.assertTrue(any("__objc_classlist" in name for name in sections))

    def test_root_class_flag(self) -> None:
        self.assertTrue(self.classes["RootBase"].get("root_class"))
        self.assertFalse(self.classes["Widget"].get("root_class"))


class ObjectFileTest(_FixtureBase):
    """An unlinked object file: pointers are zero and relocations are external.

    The reader must not invent classes from an unrelocated image. Reporting nothing
    with a clear reason beats reporting a graph built from zeroed pointers.
    """

    link = False

    def test_unlinked_object_does_not_invent_classes(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["class_count"], 0)


class MachOObjCBoundariesTest(unittest.TestCase):
    def test_non_macho_is_rejected(self) -> None:
        report = objc.inspect_objc("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)

    def test_missing_file_reports_error(self) -> None:
        report = objc.inspect_objc("/nonexistent/binary")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)

    def test_elf_is_rejected_as_not_macho(self) -> None:
        report = objc.inspect_objc("/bin/sh")
        self.assertFalse(report["ok"])

    def test_truncated_macho_does_not_raise(self) -> None:
        """A cut-down Mach-O must fail cleanly, not index past the end."""
        header = bytearray(32)
        header[0:4] = (0xFEEDFACF).to_bytes(4, "little")
        header[4:8] = (0x01000007).to_bytes(4, "little")  # x86_64
        header[16:20] = (10).to_bytes(4, "little")       # 10 load commands...
        # ...that are not actually present.
        with tempfile.TemporaryDirectory() as tmp:
            for length in (0, 4, 8, 16, 31, 32):
                target = Path(tmp) / f"cut{length}.bin"
                target.write_bytes(bytes(header[:length]))
                try:
                    objc.inspect_objc(target)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"length {length} raised {type(exc).__name__}: {exc}")

    def test_real_dylib_without_objc_says_so(self) -> None:
        """A C dylib must report no ObjC metadata, not an error.

        The distinction matters: "this binary has no Objective-C in it" is an answer,
        while an error suggests the read failed.
        """
        candidates = list((Path.home() / "projects").rglob("*.dylib"))[:8] \
            if (Path.home() / "projects").is_dir() else []
        for candidate in candidates:
            try:
                with candidate.open("rb") as handle:
                    magic = int.from_bytes(handle.read(4), "big")
            except OSError:
                continue
            if magic not in (0xCAFEBABE, 0xFEEDFACF):
                continue
            report = objc.inspect_objc(candidate)
            if not report.get("ok"):
                continue
            self.assertFalse(report["has_objc"],
                             f"{candidate} unexpectedly reported ObjC metadata")
            self.assertIn("hint", report)
            return
        self.skipTest("no Mach-O dylib on this host to check")


if __name__ == "__main__":
    unittest.main()
