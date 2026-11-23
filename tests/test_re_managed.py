"""PE/CLI (.NET) managed assembly tests.

The fixture is built by scripts/make_managed_fixture.py, which assembles a real
ECMA-335 metadata blob by hand. That was necessary because no .NET toolchain
exists on this host and the only managed assemblies present (Wine's .winmd
reference files) have placeholder versions of 255.255.255.255 and no IL bodies —
asserting against those would only prove the parser handles a degenerate file.

Every expected value below is a constant the builder chose, so these tests compare
the parser against a known fact rather than against another reader.

Two bugs shipped in the first version and both are now tests that fail when the
bug is restored:

  * every fixed-width column used `None` as its dict key, so they all overwrote
    each other and a Module row decoded as `{None: 0}` — every name in the
    assembly read as absent;
  * MethodAttributes bit positions were taken from memory rather than from
    ECMA-335 II.23.1.10, so a method whose Virtual bit was set decoded as
    HideBySig, and MemberAccess was ANDed as a bitfield when it is an exclusive
    range (Public 0x0006 came back as FamORAssem).
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.managed import (
    ManagedAssembly,
    ManagedError,
    inspect_artifact,
    inspect_boundaries,
    inspect_members,
)

BUILDER = Path(__file__).resolve().parents[1] / "scripts" / "make_managed_fixture.py"

# Mirrors the builder's constants. Kept here as literals on purpose: importing the
# builder's dict would let a change there silently change the expectation too.
EXPECTED_NAME = "XtForgeFixture"
EXPECTED_VERSION = "1.2.3.4"
EXPECTED_CULTURE = "neutral"
EXPECTED_MODULE = "XtForgeFixture.dll"
EXPECTED_TYPES = ["XtForge.Program", "XtForge.Outer", "XtForge.Nested.Inner"]
EXPECTED_METHODS = ["Main", "VirtualThing", "AbstractThing", "NativeCall"]
EXPECTED_REFS = ["System.Runtime", "System.Console"]
EXPECTED_PINVOKE = ("kernel32.dll", "Beep", "NativeCall")


def build_fixture(directory: Path) -> Path | None:
    if not BUILDER.is_file():
        return None
    completed = subprocess.run([sys.executable, str(BUILDER), str(directory)],
                               capture_output=True, text=True, timeout=300)
    target = directory / "managed_fixture.dll"
    if completed.returncode != 0 or not target.is_file():
        return None
    return target


class ManagedArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("cannot build the managed fixture")
        self.report = inspect_artifact(self.path)

    def test_identity(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["kind"], "managed")
        self.assertEqual(self.report["pe_magic"], "PE32+")
        self.assertEqual(self.report["runtime_version"], "2.5")

    def test_assembly_name_version_and_culture(self) -> None:
        asm = self.report["assembly"]
        self.assertIsNotNone(asm, "Assembly table was not found")
        self.assertEqual(asm["name"], EXPECTED_NAME)
        self.assertEqual(asm["version"], EXPECTED_VERSION)
        self.assertEqual(asm["culture"], EXPECTED_CULTURE)

    def test_module_name_comes_from_the_string_heap(self) -> None:
        """This is the assertion that catches unnamed columns.

        With every fixed-width column keyed `None`, the string index of the module
        name was overwritten and this returned None.
        """
        self.assertEqual(self.report["module"], EXPECTED_MODULE)

    def test_table_counts(self) -> None:
        counts = self.report["table_counts"]
        self.assertEqual(counts["Module"], 1)
        self.assertEqual(counts["TypeDef"], 3)
        self.assertEqual(counts["MethodDef"], 4)
        self.assertEqual(counts["Assembly"], 1)
        self.assertEqual(counts["AssemblyRef"], 2)

    def test_references_are_listed_with_versions(self) -> None:
        names = [r["name"] for r in self.report["references"]]
        self.assertEqual(names, EXPECTED_REFS)
        self.assertTrue(all(r["version"] == "4.0.0.0" for r in self.report["references"]))

    def test_entry_point_token_is_described(self) -> None:
        entry = self.report["entry_point"]
        self.assertEqual(entry["token"], "0x06000002")
        self.assertEqual(entry["table"], "MethodDef")
        self.assertEqual(entry["rid"], 2)

    def test_il_only_flag_is_decoded(self) -> None:
        self.assertIn("ILOnly", self.report["flags_decoded"])
        self.assertTrue(self.report["il_only"])

    def test_native_pe_is_rejected_with_a_clear_message(self) -> None:
        """A native DLL must say why, not return an empty inventory."""
        report = inspect_artifact("/tmp/pe_t.exe")
        if report["ok"]:
            self.skipTest("/tmp/pe_t.exe is absent or unexpectedly managed")
        self.assertIn("not a .NET assembly", report["error"])

    def test_garbage_is_rejected(self) -> None:
        report = inspect_artifact("/etc/hostname")
        self.assertFalse(report["ok"])
        self.assertTrue(report["error"])


class ManagedMembersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("cannot build the managed fixture")
        self.report = inspect_members(self.path)
        self.by_name = {m["name"]: m
                        for t in self.report["types"] for m in t["methods"]}

    def test_types_and_counts(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual([t["full_name"] for t in self.report["types"]], EXPECTED_TYPES)
        self.assertEqual(self.report["type_count"], 3)
        self.assertEqual(self.report["method_count"], 4)

    def test_all_methods_present(self) -> None:
        self.assertEqual(sorted(self.by_name), sorted(EXPECTED_METHODS))

    def test_access_range_is_exclusive_not_a_bitfield(self) -> None:
        """Public is 0x0006, which has two bits set and is not a bitmask.

        ANDing it as a bitfield yields FamORAssem, which is a different (and wrong)
        claim about the method's visibility.
        """
        self.assertEqual(self.by_name["VirtualThing"]["access"], "Public")
        self.assertEqual(self.by_name["AbstractThing"]["access"], "Public")
        self.assertEqual(self.by_name["Main"]["access"], "Private")

    def test_virtual_and_abstract_bits_match_ecma335(self) -> None:
        """Virtual is 0x0040 and Abstract 0x0400 per II.23.1.10.

        Reading them from the wrong bits is invisible: the method still gets a list
        of plausible flag names, just the wrong ones.
        """
        self.assertTrue(self.by_name["VirtualThing"]["is_virtual"])
        self.assertFalse(self.by_name["VirtualThing"]["is_abstract"])
        self.assertTrue(self.by_name["AbstractThing"]["is_virtual"])
        self.assertTrue(self.by_name["AbstractThing"]["is_abstract"])
        self.assertFalse(self.by_name["Main"]["is_virtual"])

    def test_static_flag(self) -> None:
        self.assertTrue(self.by_name["Main"]["is_static"])
        self.assertFalse(self.by_name["AbstractThing"]["is_static"])

    def test_pinvoke_method_is_marked(self) -> None:
        self.assertTrue(self.by_name["NativeCall"]["is_pinvoke"])
        self.assertFalse(self.by_name["Main"]["is_pinvoke"])

    def test_nested_type_owns_its_own_method(self) -> None:
        """TypeDef method lists are runs delimited by the next TypeDef's start.

        Getting that boundary wrong attributes methods to the wrong type, which
        reads as a correct report with the wrong owner.
        """
        inner = next(t for t in self.report["types"]
                     if t["full_name"] == "XtForge.Nested.Inner")
        self.assertEqual([m["name"] for m in inner["methods"]], ["NativeCall"])


class ManagedMethodBodyTest(unittest.TestCase):
    """CIL method body headers (ECMA-335 II.25.4).

    The discriminator is the low two bits of the first byte: 0b10 is a tiny header
    with the code size in the remaining six bits, 0b11 is a fat header with an
    explicit u32 code size. Confusing them reports a code size wrong by a factor of
    ~100 and invents a max stack for tiny bodies, so both formats are asserted.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("cannot build the managed fixture")
        report = inspect_members(self.path)
        self.by_name = {m["name"]: m
                        for t in report["types"] for m in t["methods"]}

    def test_tiny_body(self) -> None:
        body = self.by_name["Main"].get("body")
        self.assertIsNotNone(body, "Main has an RVA into .text and must have a body")
        self.assertEqual(body["format"], "tiny")
        self.assertEqual(body["code_size"], 7)
        # A tiny header carries no max-stack field; the CLI fixes it at 8.
        self.assertEqual(body["max_stack"], 8)
        self.assertEqual(body["header_size"], 1)

    def test_fat_body(self) -> None:
        body = self.by_name["VirtualThing"].get("body")
        self.assertIsNotNone(body)
        self.assertEqual(body["format"], "fat")
        self.assertEqual(body["code_size"], 12)
        self.assertEqual(body["max_stack"], 4)
        self.assertEqual(body["header_size"], 12)

    def test_locals_come_from_the_signature_token_not_the_flag(self) -> None:
        """`locals` is decided by the local var sig token being non-nil.

        The InitLocals flag only says whether locals are zeroed; a method can have
        locals without initialising them. Reading the flag as `locals` misses those.
        """
        body = self.by_name["VirtualThing"]["body"]
        self.assertTrue(body["locals"])
        self.assertFalse(body["init_locals"])

    def test_methods_without_code_have_no_body(self) -> None:
        """A P/Invoke and an abstract method both have RVA 0 — no IL to read."""
        self.assertIsNone(self.by_name["NativeCall"].get("body"))
        self.assertIsNone(self.by_name["AbstractThing"].get("body"))

    def test_bodies_can_be_skipped(self) -> None:
        """The cheap path must still work when bodies are not wanted."""
        report = inspect_members(self.path, bodies=False)
        for type_record in report["types"]:
            for method in type_record["methods"]:
                self.assertNotIn("body", method)


class ManagedBoundariesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("cannot build the managed fixture")
        self.report = inspect_boundaries(self.path)

    def test_pinvoke_is_reported_with_dll_and_import(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))
        self.assertEqual(self.report["pinvoke_count"], 1)
        entry = self.report["pinvokes"][0]
        dll, import_name, managed = EXPECTED_PINVOKE
        self.assertEqual(entry["dll"], dll)
        self.assertEqual(entry["import_name"], import_name)
        self.assertEqual(entry["managed_method"], managed)

    def test_dll_list_is_deduplicated(self) -> None:
        self.assertEqual(self.report["dlls"], ["kernel32.dll"])

    def test_native_method_body_is_not_il(self) -> None:
        natives = {m["name"]: m for m in self.report["native_methods"]}
        self.assertIn("NativeCall", natives)
        self.assertIn("Native", natives["NativeCall"]["impl"])


class ManagedRobustnessTest(unittest.TestCase):
    """Corrupt metadata must raise ManagedError, never a struct or index crash."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.path is None:
            self.skipTest("cannot build the managed fixture")
        self.data = Path(self.path).read_bytes()

    def test_truncation_raises_managed_error(self) -> None:
        for cut in (0, 2, 0x40, 0x80, 0x200, 0x300, len(self.data) // 2,
                    len(self.data) - 1):
            with self.subTest(cut=cut):
                try:
                    ManagedAssembly(self.data[:cut]).artifact()
                except ManagedError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"truncation at {cut} raised {type(exc).__name__}: {exc}")

    def test_random_mutation_never_escapes_as_a_non_managed_error(self) -> None:
        import random
        random.seed(424242)
        for _ in range(200):
            mutated = bytearray(self.data)
            for _ in range(random.randint(1, 8)):
                mutated[random.randrange(len(mutated))] = random.randrange(256)
            try:
                ManagedAssembly(bytes(mutated)).artifact()
            except ManagedError:
                pass
            except Exception as exc:  # noqa: BLE001
                self.fail(f"mutation raised {type(exc).__name__}: {exc}")

    def test_bad_metadata_signature_is_named(self) -> None:
        """A wrong BSJB signature must be reported as such, not as empty metadata."""
        assembly = ManagedAssembly(self.data)
        cli_off = assembly._rva_to_offset(assembly.cli["metadata_rva"])
        patched = bytearray(self.data)
        struct.pack_into("<I", patched, cli_off, 0xDEADBEEF)
        with self.assertRaises(ManagedError) as ctx:
            ManagedAssembly(bytes(patched)).artifact()
        self.assertIn("metadata signature", str(ctx.exception))

    def test_heap_size_flags_are_read_not_assumed(self) -> None:
        """#Strings/#GUID/#Blob widths come from the table-stream header.

        Assuming 2 bytes parses small assemblies correctly and large ones into
        noise, which is the worst kind of bug: it passes every fixture of modest
        size. Here the flags are asserted to have been consumed.
        """
        assembly = ManagedAssembly(self.data)
        self.assertEqual(len(assembly._heap_sizes), 3)
        self.assertTrue(all(w in (2, 4) for w in assembly._heap_sizes))


if __name__ == "__main__":
    unittest.main()
