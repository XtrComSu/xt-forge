"""Tests for the Swift metadata reader.

The oracle is the Swift compiler itself: `swiftc 6.0.3` builds a library with a known type
model, and `swift-demangle` — the compiler's own demangler — prints the ground truth for
every mangled symbol. The strongest test here feeds a sample of symbols to both
implementations and requires that we never attribute a symbol to a module or type the
compiler does not.

That comparison found two real bugs:

  * `$s8RawValueSYTl` is an **associated-type descriptor** for
    `Swift.RawRepresentable.RawValue`. Reading its leading component as a module invented a
    module called "RawValue" that does not exist. A standard-library kind letter (`S`/`s`)
    means the leading component is a stdlib name.
  * `$s7TestMod8DrivableMp` is the **metatype of a protocol**. The `M` refers to the
    metatype; the declaration's real kind is protocol, so reporting "metatype" for
    `Drivable` mislabels the one entity a reader most wants to identify.

Both were invisible in the fixture's *summary* — the type list looked right — and only
appeared when individual symbols were checked against the compiler.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import swiftmeta

SOURCE = """
public struct Vehicle {
    public var wheels: Int
    public var name: String
    public init(wheels: Int, name: String) { self.wheels = wheels; self.name = name }
    public func describe() -> String { return "\\(name) has \\(wheels) wheels" }
}

public enum Terrain: Int {
    case road = 0
    case offroad = 1
}

public protocol Drivable {
    func drive() -> String
}

public class Car: Drivable {
    let vehicle: Vehicle
    let terrain: Terrain
    public init(vehicle: Vehicle, terrain: Terrain) {
        self.vehicle = vehicle
        self.terrain = terrain
    }
    public func drive() -> String { return vehicle.describe() }
}

public struct Garage<T> {
    public var items: [T] = []
    public mutating func add(_ item: T) { items.append(item) }
}
"""


def find_swiftc() -> tuple[Path, Path] | None:
    """(swiftc, swift-demangle) from an unpacked toolchain on this host."""
    for root in (Path.home() / "swifttc", Path("/opt/swift"), Path("/tmp/art")):
        if not root.is_dir():
            continue
        try:
            hits = [hit for hit in root.rglob("swiftc")
                    if hit.is_file() and os.access(hit, os.X_OK)]
        except OSError:
            continue
        for compiler in hits:
            demangler = compiler.with_name("swift-demangle")
            if demangler.is_file():
                return compiler, demangler
    return None


def swift_env() -> dict[str, str]:
    env = dict(os.environ)
    # The Ubuntu toolchain wants libncurses.so.6; this host ships only the wide build.
    env["LD_LIBRARY_PATH"] = "/tmp/swiftlibs"
    return env


class DemanglerUnitTest(unittest.TestCase):
    """The demangler on its own, with expectations taken from `swift-demangle`."""

    def test_class_method(self) -> None:
        entry = swiftmeta.demangle_symbol("$s7TestMod3CarC5driveSSyF")
        self.assertEqual(entry["module"], "TestMod")
        self.assertEqual(entry["type_name"], "Car")
        self.assertEqual(entry["decl_kind"], "class")
        self.assertEqual(entry["member"], "drive")

    def test_protocol_is_a_protocol(self) -> None:
        entry = swiftmeta.demangle_symbol("$s7TestMod8DrivableP")
        self.assertEqual(entry["decl_kind"], "protocol")
        self.assertEqual(entry["type_name"], "Drivable")

    def test_metatype_of_protocol_is_still_a_protocol(self) -> None:
        """`Mp` is "metatype of a protocol"; the declaration kind is protocol."""
        entry = swiftmeta.demangle_symbol("$s7TestMod8DrivableMp")
        self.assertEqual(entry["decl_kind"], "protocol",
                         "M was read as the declaration kind instead of the metatype")

    def test_standard_library_symbol_has_no_invented_module(self) -> None:
        """`$s8RawValueSYTl` is Swift.RawRepresentable.RawValue, not module "RawValue"."""
        entry = swiftmeta.demangle_symbol("$s8RawValueSYTl")
        self.assertEqual(entry["module"], "Swift")
        self.assertTrue(entry.get("stdlib"))
        self.assertNotEqual(entry["module"], "RawValue")

    def test_nested_type_path_is_split_by_length_not_by_dots(self) -> None:
        """Nested types concatenate with no separator; only the lengths delimit them."""
        entry = swiftmeta.demangle_symbol("$s7TestMod3Car4DoorC5frameSivg")
        self.assertEqual(entry["module"], "TestMod")
        self.assertEqual(entry["type_path"], ["Car", "Door"])
        self.assertEqual(entry["type_name"], "Car.Door")

    def test_underscore_t_prefix_is_accepted(self) -> None:
        entry = swiftmeta.demangle_symbol("_T7TestMod3CarC5driveSSyF")
        self.assertEqual(entry["module"], "TestMod")
        self.assertEqual(entry["type_name"], "Car")

    def test_non_swift_symbol_is_rejected(self) -> None:
        for bogus in ("_main", "malloc", "", "$s", "$sZZZZ"):
            self.assertIsNone(swiftmeta.demangle_symbol(bogus), bogus)

    def test_property_accessor_role(self) -> None:
        entry = swiftmeta.demangle_symbol("$s7TestMod3CarC7terrainAA7TerrainOvg")
        self.assertEqual(entry["member"], "terrain")
        self.assertEqual(entry.get("symbol_role"), "getter")

    def test_field_offset_role(self) -> None:
        entry = swiftmeta.demangle_symbol("$s7TestMod3CarC7terrainAA7TerrainOvpWvd")
        self.assertEqual(entry.get("symbol_role"), "direct field offset")


class RealSwiftBinaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.tools = find_swiftc()
        cls.library = None
        cls.report = None
        if cls.tools is None:
            return
        source = cls.root / "fixture.swift"
        source.write_text(SOURCE)
        cls.library = cls.root / "libfixture.so"
        try:
            result = subprocess.run(
                [str(cls.tools[0]), "-O", "-module-name", "TestMod",
                 "-emit-library", "-o", str(cls.library), str(source)],
                capture_output=True, timeout=600, check=False, env=swift_env())
        except (OSError, subprocess.SubprocessError):
            return
        if result.returncode != 0 or not cls.library.is_file():
            cls.library = None
            return
        cls.report = swiftmeta.inspect_swift_metadata(cls.library)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.tools is None:
            self.skipTest("no Swift toolchain on this host")
        if self.report is None:
            self.skipTest("could not build the Swift fixture")

    def test_binary_is_recognised_as_swift(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["format"], "ELF")
        self.assertGreater(self.report["swift_section_count"], 5)

    def test_type_model_is_recovered(self) -> None:
        names = {entry["type"] for entry in self.report["types"]}
        for expected in ("Vehicle", "Terrain", "Drivable", "Car", "Garage"):
            self.assertIn(expected, names)

    def test_decl_kinds_are_correct(self) -> None:
        kinds = {entry["type"]: entry["decl_kind"] for entry in self.report["types"]}
        self.assertEqual(kinds.get("Vehicle"), "struct")
        self.assertEqual(kinds.get("Terrain"), "enum")
        self.assertEqual(kinds.get("Car"), "class")
        self.assertEqual(kinds.get("Drivable"), "protocol")

    def test_members_are_attached_to_their_types(self) -> None:
        by_type = {entry["type"]: entry for entry in self.report["types"]}
        self.assertIn("wheels", by_type["Vehicle"]["members"])
        self.assertIn("describe", by_type["Vehicle"]["members"])
        self.assertIn("drive", by_type["Car"]["members"])

    def test_reflection_strings_contain_field_names(self) -> None:
        """swift5_reflstr holds the compiler's field names verbatim."""
        strings = set(self.report["reflection_strings"])
        for expected in ("wheels", "name", "offroad", "terrain"):
            self.assertIn(expected, strings)

    def test_agrees_with_the_compiler_demangler(self) -> None:
        """Both implementations must place a symbol in the same module and type.

        This is the assertion that found the "RawValue" phantom module and the
        mislabelled protocol: it checks individual symbols, which a type-list summary
        cannot.
        """
        raw = self.library.read_bytes()
        symbols = swiftmeta._mangled_symbols(raw)[:40]
        if not symbols:
            self.skipTest("no mangled symbols found")
        try:
            proc = subprocess.run(
                [str(self.tools[1])] + symbols, capture_output=True,
                timeout=300, check=False, env=swift_env())
        except (OSError, subprocess.SubprocessError):
            self.skipTest("swift-demangle could not be run")
        oracle: dict[str, str] = {}
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if "--->" in line:
                mangled, meaning = line.split("--->", 1)
                oracle[mangled.strip()] = meaning.strip()
        if not oracle:
            self.skipTest("swift-demangle produced no output")
        checked = 0
        for symbol in symbols:
            entry = swiftmeta.demangle_symbol(symbol)
            expected = oracle.get(symbol)
            if entry is None or expected is None:
                continue
            module = entry.get("module") or ""
            self.assertIn(module, expected,
                          f"{symbol}: we say module {module!r}, compiler says {expected!r}")
            type_name = entry.get("type_name") or ""
            if type_name:
                head = type_name.split(".")[0]
                self.assertIn(head, expected,
                              f"{symbol}: we say type {head!r}, compiler says {expected!r}")
            checked += 1
        self.assertGreater(checked, 15, "too few symbols were cross-checked")

    def test_result_is_json_serialisable(self) -> None:
        import json
        json.dumps(self.report)

    def test_unresolved_symbols_are_reported_not_hidden(self) -> None:
        if self.report["undemangled_count"]:
            self.assertIn("note", self.report)


class NonSwiftBinaryTest(unittest.TestCase):
    def test_plain_binary_is_rejected(self) -> None:
        report = swiftmeta.inspect_swift_metadata("/bin/ls")
        self.assertFalse(report["ok"])
        self.assertIn("no Swift metadata", report["error"])

    def test_missing_file_reports_error(self) -> None:
        report = swiftmeta.inspect_swift_metadata("/nonexistent/lib.so")
        self.assertFalse(report["ok"])

    def test_random_data_is_not_claimed_as_swift(self) -> None:
        """A byte pair that starts like a symbol is not evidence of Swift.

        In 20 MB of random data a "$s<digit>" sequence occurs by chance. An earlier
        version of this reader accepted any such match and reported `ok: true` with zero
        demangled symbols — a false positive that would tell an analyst the wrong thing
        about a file. The gate now requires either a real swift5 section or a symbol that
        actually decomposes.
        """
        import random
        random.seed(7)
        blob = bytes(random.randrange(256) for _ in range(4 * 1024 * 1024))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "random.bin"
            path.write_bytes(blob)
            report = swiftmeta.inspect_swift_metadata(path)
        self.assertFalse(report["ok"], "random data was claimed to be a Swift binary")

    def test_candidate_count_is_reported_when_rejected(self) -> None:
        """Rejecting a file should still say how many candidates were seen."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "noise.bin"
            # "$s99ab" is a candidate the scanner accepts (prefix + digit) but the
            # demangler rejects: length 99 overruns the symbol. A *valid* symbol such as
            # "$s9noisehere" would legitimately parse as module "noisehere".
            path.write_bytes(b"$s99ab" + bytes(64))
            report = swiftmeta.inspect_swift_metadata(path)
        self.assertFalse(report["ok"])
        self.assertIn("candidate_symbol_count", report)

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(515)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(12):
                blob = root / f"r{index}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 900))))
                try:
                    swiftmeta.inspect_swift_metadata(blob)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"raised {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    unittest.main()
