"""PE load-config and Authenticode certificate tests.

The fixture is built by scripts/make_pe_fixtures.py, which compiles a real mingw PE
and then appends a hand-written load-config struct and WIN_CERTIFICATE. That was
necessary because mingw will not emit a load config for a trivial program and
nothing on this host produces a signed PE — without a fixture, every assertion
here would be about an absent directory, which is the shape of test that passes
while the parser is broken.

The oracle is `llvm-readobj --coff-load-config`, which parses the same bytes
independently and prints the fields this parser claims to read.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re.pe import PEFile

BUILDER = Path(__file__).resolve().parents[1] / "scripts" / "make_pe_fixtures.py"


def build_fixture(directory: Path) -> Path | None:
    if not BUILDER.is_file():
        return None
    completed = subprocess.run([sys.executable, str(BUILDER), str(directory)],
                               capture_output=True, text=True, timeout=300)
    candidate = directory / "loadconfig_signed.exe"
    if completed.returncode != 0 or not candidate.is_file():
        return None
    return candidate


class PeLoadConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pe_path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.pe_path is None:
            self.skipTest("cannot build the load-config fixture (no PE toolchain)")
        self.pe = PEFile(self.pe_path)
        self.report = self.pe.load_config()

    def test_directory_is_reported_present_with_declared_size(self) -> None:
        self.assertTrue(self.report["present"])
        self.assertEqual(self.report["size"], 0x98)

    def test_security_relevant_fields(self) -> None:
        fields = self.report["fields"]
        self.assertEqual(fields["security_cookie"], 0x7FF612345678)
        self.assertEqual(fields["se_handler_table"], 0x140001000)
        self.assertEqual(fields["se_handler_count"], 3)
        self.assertEqual(fields["guard_cf_check_function"], 0x140001100)
        self.assertEqual(fields["guard_cf_dispatch_function"], 0x140001200)
        self.assertEqual(fields["guard_cf_function_table"], 0x140001300)
        self.assertEqual(fields["guard_cf_function_count"], 7)
        self.assertEqual(fields["guard_flags"], 0xC0100)
        self.assertEqual(fields["global_flags_set"], 0x20)

    def test_mitigations_decoded_from_fields(self) -> None:
        mit = self.report["mitigations"]
        self.assertTrue(mit["gs_cookie"])
        self.assertTrue(mit["control_flow_guard"])   # 0x100
        self.assertTrue(mit["xfg_enabled"])          # 0x40000
        self.assertTrue(mit["cast_guard"])           # 0x80000
        self.assertFalse(mit["cfg_export_suppression"])
        self.assertTrue(mit["high_entropy_va"])

    def test_safe_seh_is_not_claimed_on_a_64_bit_image(self) -> None:
        """A zero SEH table on x64 is not a missing mitigation.

        SEH on x64 is table-based and the load-config field is unused, so reporting
        "safe_seh: no" would state a fact about the binary's defences that is not
        true. The fixture sets a non-zero table deliberately, so a parser that
        ignored the architecture would answer True here.
        """
        self.assertIsNone(self.report["mitigations"]["safe_seh"])
        self.assertTrue(any("safe_seh" in w for w in self.report["warnings"]))

    def test_matches_llvm_readobj(self) -> None:
        readobj = shutil.which("llvm-readobj")
        if not readobj:
            self.skipTest("llvm-readobj unavailable")
        out = subprocess.run([readobj, "--coff-load-config", str(self.pe_path)],
                             capture_output=True, text=True).stdout
        self.assertIn("Size: 0x98", out)
        self.assertIn("SecurityCookie: 0x7FF612345678", out)
        self.assertIn("SEHandlerTable: 0x140001000", out)
        self.assertIn("SEHandlerCount: 3", out)
        self.assertIn("GuardCFFunctionCount: 7", out)
        self.assertIn("0xC0100", out)

    def test_absent_load_config_is_not_an_error(self) -> None:
        plain = PEFile(self.pe_path)
        plain.data_directories[10] = {"name": "LoadConfig", "rva": 0, "size": 0}
        report = plain.load_config()
        self.assertTrue(report["ok"])
        self.assertFalse(report["present"])
        self.assertTrue(report["warnings"])

    def test_short_directory_does_not_report_absent_fields(self) -> None:
        """A pre-GuardFlags directory must not produce guard flags.

        The struct grew over Windows releases, so fields are gated on the declared
        size. Reading past it would invent CFG support for a binary compiled before
        CFG existed.
        """
        shortened = PEFile(self.pe_path)
        # Rewrite the declared size to 0x5C — the Windows XP era layout, which ends
        # at SecurityCookie and has no Guard* fields at all.
        shortened.data_directories[10] = dict(shortened.data_directories[10], size=0x5C)
        offset = shortened.rva_to_offset(shortened.data_directories[10]["rva"])
        import struct as _struct
        patched = bytearray(shortened.data)
        _struct.pack_into("<I", patched, offset, 0x5C)
        shortened.data = bytes(patched)
        report = shortened.load_config()
        self.assertTrue(report["present"])
        # 0x5C is 92 bytes: EditList at 0x50..0x58 fits, SecurityCookie at
        # 0x58..0x60 does not. Both facts are asserted, because the point of the
        # gate is that it excludes exactly the fields that do not fit.
        self.assertIn("edit_list", report["fields"])
        self.assertNotIn("security_cookie", report["fields"])
        self.assertNotIn("guard_flags", report["fields"])
        self.assertNotIn("guard_cf_check_function", report["fields"])
        self.assertNotIn("control_flow_guard", report["mitigations"])


class PeCertificatesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pe_path = build_fixture(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if self.pe_path is None:
            self.skipTest("cannot build the signed-PE fixture")
        self.report = PEFile(self.pe_path).certificates()

    def test_reports_the_signature(self) -> None:
        self.assertTrue(self.report["signed"])
        self.assertEqual(len(self.report["certificates"]), 1)
        entry = self.report["certificates"][0]
        self.assertEqual(entry["type_name"], "PKCS_SIGNED_DATA")
        self.assertEqual(entry["revision_name"], "2.0")
        self.assertEqual(entry["payload_size"], 0x100)
        self.assertIn("DER", entry["encoding"])

    def test_directory_is_read_as_a_file_offset(self) -> None:
        """Directory 4 is a file offset, not an RVA — the classic mistake.

        Reinterpreting it as an RVA lands somewhere else in the image entirely and
        reports a certificate that is not there. The fixture places the table past
        every section's RVA range, so the two readings cannot coincide.
        """
        pe = PEFile(self.pe_path)
        raw = pe.data_directories[4]["rva"]
        self.assertGreater(raw, 0x10000)
        entry = self.report["certificates"][0]
        self.assertEqual(entry["offset"], raw)
        data = Path(self.pe_path).read_bytes()
        self.assertLessEqual(entry["offset"] + entry["length"], len(data))

    def test_unsigned_image_says_so(self) -> None:
        pe = PEFile(self.pe_path)
        pe.data_directories[4] = {"name": "Certificate", "rva": 0, "size": 0}
        report = pe.certificates()
        self.assertFalse(report["signed"])
        self.assertTrue(report["warnings"])

    def test_zero_length_entry_does_not_loop_forever(self) -> None:
        """A declared length below the 8-byte header must stop the walk.

        Without the guard, stepping by an aligned length of 0 never advances and the
        parser spins — a hang, not an exception, which is worse.
        """
        import signal
        import struct as _struct
        pe = PEFile(self.pe_path)
        offset = pe.data_directories[4]["rva"]
        patched = bytearray(pe.data)
        _struct.pack_into("<I", patched, offset, 0)  # length 0
        pe.data = bytes(patched)

        def _timeout(signum, frame):
            raise TimeoutError("certificate walk did not terminate")

        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(10)
        try:
            report = pe.certificates()
            self.assertFalse(report["signed"])
            self.assertTrue(report["warnings"])
        except TimeoutError:
            self.fail("zero-length certificate entry caused an infinite loop")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    unittest.main()
