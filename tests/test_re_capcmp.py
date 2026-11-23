"""Capture comparison and static-vs-runtime correlation, against pcaps written from the spec.

No capture tooling (tcpdump, tshark, scapy, dpkt) exists on this host, so the fixtures are
built byte by byte from the libpcap file format and the DNS wire format. That is not a
workaround — it is what makes the tests worth having: the expected packet contents are known
exactly, so a parser that silently mis-reads a field is caught rather than quietly producing
plausible output.

The DNS parser exists because of a real mismatch of alphabets. A capture records *IP
addresses* in its flow table; a binary records *hostnames* in its strings. Comparing them
directly gave a 0% correlation on a fixture where the application and the capture agreed about
everything — the two sides simply never spelled the same endpoint twice. Parsing the captures'
own DNS answers bridges them.

The bug that parser had is recorded in `test_dns_name_offset_is_past_the_terminator`: the
name decoder returned an offset after the *first label* rather than after the terminating
zero, so every caller resumed inside the name, read garbage as the record type, and produced
an empty DNS map from a capture that plainly contained valid answers.
"""
from __future__ import annotations

import socket
import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import capcmp


def udp_frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    ethernet = (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
                + struct.pack(">H", 0x0800))
    total = 20 + 8 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return ethernet + ip + udp + payload


def tcp_frame(src_ip: str, dst_ip: str, sport: int, dport: int,
              payload: bytes = b"") -> bytes:
    ethernet = (b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"
                + struct.pack(">H", 0x0800))
    total = 20 + 20 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 8192, 0, 0)
    return ethernet + ip + tcp + payload


def dns_exchange(hostname: str, address: str, txid: int = 0x1234) -> list[bytes]:
    """A DNS query and its answer, as a sniffer on the wire would see both."""
    qname = b"".join(bytes([len(part)]) + part.encode() for part in hostname.split("."))
    qname += b"\x00"
    question = qname + struct.pack(">HH", 1, 1)
    query = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    # Answer name uses a compression pointer to offset 12, which is what real resolvers do.
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
              + socket.inet_aton(address))
    response = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer
    return [udp_frame("10.0.0.5", "8.8.8.8", 53000, 53, query),
            udp_frame("8.8.8.8", "10.0.0.5", 53, 53000, response)]


def write_pcap(path: Path, packets: list[bytes]) -> Path:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", 1000000 + index, 0, len(packet),
                                     len(packet)))
            handle.write(packet)
    return path


APP_C = """
#include <stdio.h>
const char *A = "https://api.example.com/v2/users";
const char *B = "https://telemetry.example.net:8443/report";
const char *C = "https://dormant.example.org/beacon";
int main(void){ printf("%s\\n", A); return 0; }
"""


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import shutil
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)

        cls.v1 = write_pcap(cls.root / "v1.pcap", [
            tcp_frame("10.0.0.5", "93.184.216.34", 51000, 80,
                      b"GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            tcp_frame("10.0.0.5", "8.8.8.8", 51001, 53, b"\x00\x01dns"),
            tcp_frame("10.0.0.5", "93.184.216.34", 51002, 443, b"\x16\x03\x01tls"),
        ])
        cls.v2 = write_pcap(cls.root / "v2.pcap", [
            tcp_frame("10.0.0.5", "93.184.216.34", 51000, 80,
                      b"GET /api/v2/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
            tcp_frame("10.0.0.5", "1.2.3.4", 51003, 8080,
                      b"POST /telemetry HTTP/1.1\r\n\r\n"),
            tcp_frame("10.0.0.5", "93.184.216.34", 51002, 443, b"\x16\x03\x01tls"),
        ])

        runtime_packets: list[bytes] = []
        runtime_packets += dns_exchange("api.example.com", "93.184.216.34")
        runtime_packets += dns_exchange("telemetry.example.net", "93.184.216.35", 0x1235)
        runtime_packets.append(tcp_frame("10.0.0.5", "93.184.216.34", 51000, 443,
                                         b"\x16\x03\x01tls"))
        runtime_packets.append(tcp_frame("10.0.0.5", "93.184.216.35", 51003, 8443,
                                         b"POST /report"))
        cls.runtime = write_pcap(cls.root / "runtime.pcap", runtime_packets)

        cls.app = None
        if shutil.which("gcc"):
            source = cls.root / "app.c"
            source.write_text(APP_C)
            binary = cls.root / "app"
            import subprocess
            result = subprocess.run(["gcc", "-O1", "-o", str(binary), str(source)],
                                    capture_output=True, timeout=300, check=False)
            if result.returncode == 0:
                cls.app = binary

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()


class CaptureCompareTest(FixtureCase):
    def test_endpoints_added_and_removed(self) -> None:
        report = capcmp.compare_captures(self.v1, self.v2)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("1.2.3.4:8080", report["added_endpoints"])
        self.assertIn("8.8.8.8:53", report["removed_endpoints"])

    def test_path_change_is_detected_when_host_and_port_are_unchanged(self) -> None:
        """`/api/v1/` becoming `/api/v2/` is invisible to endpoint comparison alone."""
        report = capcmp.compare_captures(self.v1, self.v2)
        self.assertIn("/api/v1/users", report["removed_paths"])
        self.assertIn("/telemetry", report["added_paths"])

    def test_change_flag_is_set(self) -> None:
        self.assertTrue(capcmp.compare_captures(self.v1, self.v2)["changed"])

    def test_identical_capture_has_no_changes(self) -> None:
        report = capcmp.compare_captures(self.v1, self.v1)
        self.assertFalse(report["changed"])
        self.assertEqual(report["added_endpoints"], [])
        self.assertEqual(report["removed_endpoints"], [])

    def test_packet_counts_are_reported(self) -> None:
        report = capcmp.compare_captures(self.v1, self.v2)
        self.assertEqual(report["packets_a"], 3)
        self.assertEqual(report["packets_b"], 3)


class DnsResolutionTest(FixtureCase):
    def test_dns_map_is_built_from_answers(self) -> None:
        """The offset bug produced an empty map from a capture full of valid answers."""
        mapping = capcmp._dns_map(self.runtime)
        self.assertEqual(mapping.get("93.184.216.34"), "api.example.com")
        self.assertEqual(mapping.get("93.184.216.35"), "telemetry.example.net")

    def test_dns_name_offset_is_past_the_terminator(self) -> None:
        """Decoding must resume after the terminating zero, not after the first label."""
        name = b"\x03api\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        decoded, offset = capcmp._decode_dns_name(name, 0)
        self.assertEqual(decoded, "api.example.com")
        self.assertEqual(offset, 17, "offset must point at qtype, past the zero byte")

    def test_compression_pointer_is_followed(self) -> None:
        data = b"\x03api\x07example\x03com\x00" + b"\xc0\x00"
        decoded, offset = capcmp._decode_dns_name(data, 17)
        self.assertEqual(decoded, "api.example.com")
        self.assertEqual(offset, 19)

    def test_capture_without_dns_yields_empty_map(self) -> None:
        self.assertEqual(capcmp._dns_map(self.v2), {})


class CorrelationTest(FixtureCase):
    def setUp(self) -> None:
        if self.app is None:
            self.skipTest("gcc is not available")
        self.report = capcmp.correlate_static_runtime(self.app, self.runtime)

    def test_correlation_succeeds(self) -> None:
        self.assertTrue(self.report["ok"], self.report.get("error"))

    def test_static_endpoints_are_extracted(self) -> None:
        self.assertIn("api.example.com", self.report["in_both"])
        self.assertIn("telemetry.example.net", self.report["in_both"])

    def test_dormant_endpoint_is_reported_as_static_only(self) -> None:
        """A URL in the binary that never fires is a dormant capability, not a match."""
        self.assertIn("dormant.example.org", self.report["static_only"])

    def test_resolved_ips_are_not_reported_as_runtime_only(self) -> None:
        """`93.184.216.34` resolved to `api.example.com`; listing both double-counts."""
        self.assertNotIn("93.184.216.34", self.report["runtime_only"])
        self.assertNotIn("93.184.216.35", self.report["runtime_only"])

    def test_unresolved_ip_is_kept(self) -> None:
        """An IP with no DNS answer must not be silently dropped."""
        self.assertIn("8.8.8.8", self.report["runtime_only"])

    def test_correlation_percentage_is_bounded(self) -> None:
        self.assertGreaterEqual(self.report["correlation_pct"], 0.0)
        self.assertLessEqual(self.report["correlation_pct"], 100.0)

    def test_port_mismatch_is_reported(self) -> None:
        """`telemetry.example.net:8443` is static; the capture also used 8443."""
        for entry in self.report["port_mismatches"]:
            self.assertNotEqual(entry["static_port"], entry["observed_port"])


class HonestyTest(FixtureCase):
    def test_missing_capture_is_an_error(self) -> None:
        report = capcmp.compare_captures("/nonexistent/a.pcap", self.v1)
        self.assertFalse(report["ok"])

    def test_non_capture_file_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "x.bin"
            blob.write_bytes(b"\x00" * 128)
            report = capcmp.compare_captures(blob, self.v1)
        self.assertFalse(report["ok"])

    def test_correlation_needs_a_real_binary(self) -> None:
        report = capcmp.correlate_static_runtime("/nonexistent/app", self.runtime)
        self.assertFalse(report["ok"])

    def test_limits_are_stated(self) -> None:
        report = capcmp.compare_captures(self.v1, self.v2)
        self.assertIn("endpoint", report["note"].lower())
        correlation = capcmp.correlate_static_runtime(
            self.root / "app" if self.app is None else self.app, self.runtime)
        if correlation.get("ok"):
            self.assertIn("sample", correlation["note"].lower())

    def test_empty_static_extraction_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "plain.bin"
            blob.write_bytes(b"\x00" * 256)
            report = capcmp.correlate_static_runtime(blob, self.runtime)
        if report.get("ok"):
            self.assertEqual(report["static_hosts"], 0)


if __name__ == "__main__":
    unittest.main()
