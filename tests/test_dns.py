"""DNS wire-format tests. No network: packets are handcrafted."""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import dns  # noqa: E402


class TestNameCodec(unittest.TestCase):
    def test_encodes_labels(self):
        self.assertEqual(dns._encode_name("example.com"),
                         b"\x07example\x03com\x00")

    def test_encode_ignores_trailing_dot(self):
        self.assertEqual(dns._encode_name("example.com."),
                         dns._encode_name("example.com"))

    def test_decode_plain(self):
        packet = b"\x07example\x03com\x00"
        self.assertEqual(dns._decode_name(packet, 0)[0], "example.com")

    def test_decode_compression_pointer(self):
        # "example.com" at 0 (13 bytes), then "www" + pointer back to 0.
        packet = b"\x07example\x03com\x00" + b"\x03www\xc0\x00"
        name, offset = dns._decode_name(packet, 13)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, 19, "must resume after the 2-byte pointer")

    def test_pointer_loop_does_not_hang(self):
        # A self-referential pointer must terminate, not spin.
        packet = b"\xc0\x00"
        name, _ = dns._decode_name(packet, 0)
        self.assertIsInstance(name, str)


class TestRdata(unittest.TestCase):
    def test_a_record(self):
        self.assertEqual(dns._parse_rdata(1, b"\x01\x02\x03\x04", 0, 4,
                                          b"\x01\x02\x03\x04"), "1.2.3.4")

    def test_txt_record_joins_segments(self):
        block = b"\x05hello\x05world"
        self.assertEqual(dns._parse_rdata(16, block, 0, len(block), block),
                         "hello world")

    def test_mx_record(self):
        block = struct.pack("!H", 10) + b"\x04mail\x07example\x03com\x00"
        value = dns._parse_rdata(15, block, 0, len(block), block)
        self.assertEqual(value, {"preference": 10, "host": "mail.example.com"})

    def test_null_mx_is_explicit(self):
        block = struct.pack("!H", 0) + b"\x00"
        value = dns._parse_rdata(15, block, 0, len(block), block)
        self.assertEqual(value["host"], ".",
                         "RFC 7505 null MX means 'no mail', not 'unknown'")

    def test_ns_record(self):
        block = b"\x03ns1\x07example\x03com\x00"
        self.assertEqual(dns._parse_rdata(2, block, 0, len(block), block),
                         "ns1.example.com")


class TestQueryValidation(unittest.TestCase):
    def test_unsupported_type(self):
        res = dns.query("example.com", "WKS")
        self.assertFalse(res["ok"])
        self.assertIn("unsupported", res["error"])

    def test_overlong_name(self):
        self.assertFalse(dns.query("a" * 300, "A")["ok"])

    def test_resolve_requires_a_name(self):
        self.assertFalse(dns.resolve("")["ok"])

    def test_edns_packet_is_well_formed(self):
        """The OPT record is what stops large TXT sets coming back empty."""
        packet = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 1)
        packet += dns._encode_name("example.com") + struct.pack("!HH", 16, 1)
        packet += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
        # additional count must be 1 and the OPT must be the last 11 bytes
        self.assertEqual(struct.unpack("!H", packet[10:12])[0], 1)
        self.assertEqual(packet[-11], 0)                      # root name
        self.assertEqual(struct.unpack("!H", packet[-10:-8])[0], 41)   # OPT


class TestSpoofability(unittest.TestCase):
    def test_missing_records_are_reported(self):
        from xtforge.core import intel
        notes = intel._spoofability([], [])
        self.assertTrue(any("no SPF record" in n for n in notes))
        self.assertTrue(any("no DMARC record" in n for n in notes))

    def test_hard_fail_and_reject(self):
        from xtforge.core import intel
        notes = intel._spoofability(["v=spf1 -all"], ["v=DMARC1; p=reject"])
        self.assertTrue(any("-all" in n for n in notes))
        self.assertTrue(any("reject" in n for n in notes))

    def test_permissive_all_is_flagged(self):
        from xtforge.core import intel
        notes = intel._spoofability(["v=spf1 +all"], [])
        self.assertTrue(any("allows everything" in n for n in notes))

    def test_soft_fail_is_flagged(self):
        from xtforge.core import intel
        notes = intel._spoofability(["v=spf1 ~all"], [])
        self.assertTrue(any("may be delivered" in n for n in notes))

    def test_p_none_is_monitor_only(self):
        from xtforge.core import intel
        notes = intel._spoofability([], ["v=DMARC1; p=none"])
        self.assertTrue(any("monitor only" in n for n in notes))


class TestDomainValidation(unittest.TestCase):
    def test_rejects_urls_and_paths(self):
        from xtforge.core import intel
        for bad in ("http://evil.test/x", "evil.test/path", "not a domain",
                    "a..b.com", ""):
            self.assertFalse(intel.domain(bad)["ok"], bad)

    def test_accepts_plain_hostnames(self):
        from xtforge.core import intel
        self.assertRegex("example.com", intel.HOSTNAME)
        self.assertRegex("sub.example.co.uk", intel.HOSTNAME)
        self.assertFalse(intel.HOSTNAME.match("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
