"""Tests for the pcap/pcapng capture reader (Python side).

The Go hub answers `re netcap` on the native path, so this module is the reference
implementation and the fallback for builds without the native runtime. Both must
agree, which is why the same fixtures and the same assertions appear in
native/xtforge-go/internal/rehub/pcap_test.go.

Fixtures are assembled here byte by byte so every expected value is chosen. The three
failure modes all produce output that looks valid, so the tests assert concrete
addresses, ports and timestamps rather than just ok:true:

  * reading a big-endian capture as little-endian gives nonsense timestamps;
  * treating a nanosecond capture as microsecond puts every packet in 1970;
  * the wrong link-layer offset yields addresses that still look like IPs.
"""
from __future__ import annotations

import random
import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import capture


def _ipv4(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def eth_ipv4_tcp(src: str, dst: str, src_port: int, dst_port: int,
                 payload: bytes = b"") -> bytes:
    tcp = struct.pack(">HHII", src_port, dst_port, 1, 0)
    tcp += bytes([0x50, 0x18])
    tcp += struct.pack(">HHH", 8192, 0, 0)
    tcp += payload
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0)
    ip += _ipv4(src) + _ipv4(dst)
    eth = bytes.fromhex("aabbccddeeff112233445566") + b"\x08\x00"
    return eth + ip + tcp


def write_pcap(directory: Path, magic: int, order: str, fraction: int,
               frames: list[bytes], linktype: int = 1) -> Path:
    out = struct.pack(f"{order}IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for index, frame in enumerate(frames):
        out += struct.pack(f"{order}IIII", 1700000000 + index, fraction,
                           len(frame), len(frame))
        out += frame
    path = directory / "capture.pcap"
    path.write_bytes(out)
    return path


def write_pcapng(directory: Path, frames: list[bytes], linktype: int = 1) -> Path:
    def block(kind: int, body: bytes) -> bytes:
        padding = (-len(body)) % 4
        total = 12 + len(body) + padding
        return (struct.pack("<II", kind, total) + body + bytes(padding)
                + struct.pack("<I", total))

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))
    for index, frame in enumerate(frames):
        total = (1700000000 + index) * 1_000_000
        body = struct.pack("<IIIII", 0, total >> 32, total & 0xFFFFFFFF,
                           len(frame), len(frame)) + frame
        out += block(0x00000006, body)
    path = directory / "capture.pcapng"
    path.write_bytes(out)
    return path


HTTP_GET = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"


class PcapTest(unittest.TestCase):
    def test_little_endian_microsecond(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pcap(Path(tmp), 0xA1B2C3D4, "<", 500000,
                              [eth_ipv4_tcp("10.0.0.5", "93.184.216.34", 51000, 80,
                                            HTTP_GET)])
            report = capture.inspect_capture(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["endianness"], "little")
        self.assertEqual(report["resolution"], "micro")
        self.assertEqual(report["packet_count"], 1)
        # The date, not just "non-empty": byte-order confusion still yields a
        # valid-looking timestamp, just in the wrong year.
        self.assertEqual(report["first_packet"], "2023-11-14T22:13:20.500000Z")
        self.assertEqual(report["flow_count"], 1)
        flow = report["flows"][0]
        self.assertEqual((flow["src"], flow["dst"]), ("10.0.0.5", "93.184.216.34"))
        self.assertEqual(flow["dst_port"], 80)
        self.assertEqual(flow["protocol"], "TCP")

    def test_http_request_is_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pcap(Path(tmp), 0xA1B2C3D4, "<", 500000,
                              [eth_ipv4_tcp("10.0.0.5", "93.184.216.34", 51000, 80,
                                            HTTP_GET)])
            report = capture.inspect_capture(path)
        self.assertEqual(report["http_request_count"], 1)
        request = report["http_requests"][0]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["url"], "http://example.com/index.html")

    def test_big_endian_matches_little_endian(self) -> None:
        """The same logical capture, both byte orders, must agree.

        If endianness were assumed the timestamp moves to a different year rather
        than failing, so this compares the rendered instant rather than presence.
        """
        frame = eth_ipv4_tcp("192.168.0.1", "8.8.8.8", 1234, 53)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            little = capture.inspect_capture(
                write_pcap(root, 0xA1B2C3D4, "<", 250000, [frame]))
            big_path = root / "big.pcap"
            big_path.write_bytes(
                struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                + struct.pack(">IIII", 1700000000, 250000, len(frame), len(frame))
                + frame)
            big = capture.inspect_capture(big_path)
        self.assertEqual(little["first_packet"], big["first_packet"])
        self.assertEqual(big["endianness"], "big")
        self.assertEqual(big["flows"][0]["src"], "192.168.0.1")

    def test_nanosecond_resolution(self) -> None:
        """500_000_000 ns is the same instant as 500_000 us.

        Read as microseconds it becomes ~500 seconds past the epoch minute, which is
        a valid timestamp — so only comparing the rendered value catches it.
        """
        frame = eth_ipv4_tcp("10.1.1.1", "10.2.2.2", 1000, 2000)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            micro = capture.inspect_capture(
                write_pcap(root, 0xA1B2C3D4, "<", 500000, [frame]))
            nano_path = root / "nano.pcap"
            nano_path.write_bytes(
                struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
                + struct.pack("<IIII", 1700000000, 500000000, len(frame), len(frame))
                + frame)
            nano = capture.inspect_capture(nano_path)
        self.assertEqual(nano["resolution"], "nano")
        self.assertEqual(micro["first_packet"], nano["first_packet"])

    def test_flow_accounting(self) -> None:
        """Repeated frames in one direction collapse into a single flow."""
        frames = [eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 40000, 443) for _ in range(3)]
        with tempfile.TemporaryDirectory() as tmp:
            report = capture.inspect_capture(
                write_pcap(Path(tmp), 0xA1B2C3D4, "<", 0, frames))
        self.assertEqual(report["flow_count"], 1)
        self.assertEqual(report["flows"][0]["packets"], 3)
        self.assertGreater(report["flows"][0]["bytes"], 0)
        self.assertEqual(report["parsed_packets"], 3)
        self.assertEqual(report["unparsed_packets"], 0)

    def test_raw_ip_linktype_has_no_link_header(self) -> None:
        """LINKTYPE_RAW frames start at the IP header.

        Using the Ethernet offset reads byte 0 of the IP header as a MAC and lands
        mid-header, producing an address that still looks like an address.
        """
        frame = eth_ipv4_tcp("10.9.9.9", "10.8.8.8", 5555, 6666)[14:]
        with tempfile.TemporaryDirectory() as tmp:
            report = capture.inspect_capture(
                write_pcap(Path(tmp), 0xA1B2C3D4, "<", 0, [frame], linktype=101))
        self.assertEqual(report["linktype_name"], "Raw IP")
        self.assertEqual(report["parsed_packets"], 1)
        self.assertEqual(report["flows"][0]["src"], "10.9.9.9")


class PcapngTest(unittest.TestCase):
    def test_enhanced_packet_blocks(self) -> None:
        frame = eth_ipv4_tcp("172.16.0.9", "1.1.1.1", 40000, 443,
                             b"GET /secret HTTP/1.1\r\nHost: api.example\r\n\r\n")
        with tempfile.TemporaryDirectory() as tmp:
            report = capture.inspect_capture(write_pcapng(Path(tmp), [frame]))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["format"], "pcapng")
        self.assertEqual(report["interfaces"], 1)
        self.assertEqual(report["linktype_name"], "Ethernet")
        self.assertEqual(report["packet_count"], 1)
        self.assertEqual(report["flows"][0]["src"], "172.16.0.9")
        self.assertEqual(report["http_requests"][0]["url"], "http://api.example/secret")

    def test_trailing_block_length_mismatch_is_reported(self) -> None:
        """pcapng repeats each block's length at the end.

        Using only the leading copy means a corrupt file walks off into garbage
        silently; the mismatch flag is how that becomes visible.
        """
        frame = eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 2)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pcapng(Path(tmp), [frame])
            data = bytearray(path.read_bytes())
            # Corrupt the trailing length of the last block.
            data[-4:] = struct.pack("<I", 999)
            path.write_bytes(bytes(data))
            report = capture.inspect_capture(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(report.get("trailing_length_mismatch"))


class CaptureRobustnessTest(unittest.TestCase):
    def test_non_capture_is_rejected_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notes.txt"
            path.write_text("this is definitely not a packet capture at all")
            report = capture.inspect_capture(path)
        self.assertFalse(report["ok"])
        self.assertIn("found_magic", report)

    def test_truncation_does_not_raise(self) -> None:
        frames = [eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 2)]
        with tempfile.TemporaryDirectory() as tmp:
            full = write_pcap(Path(tmp), 0xA1B2C3D4, "<", 100, frames).read_bytes()
            for cut in (0, 4, 20, 24, 30, len(full) // 2, len(full) - 3):
                path = Path(tmp) / f"cut{cut}.pcap"
                path.write_bytes(full[:cut])
                try:
                    capture.inspect_capture(path)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"cut at {cut} raised {type(exc).__name__}: {exc}")

    def test_mutation_fuzz_never_raises(self) -> None:
        """Every byte position, several values: reach length and offset edge cases."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = bytearray(
                write_pcap(root, 0xA1B2C3D4, "<", 100,
                           [eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 80, 443,
                                         HTTP_GET)]).read_bytes())
            scratch = root / "mutated.pcap"
            random.seed(5150)
            for index in range(len(original)):
                for value in (0x00, 0xFF, 0x7F):
                    if original[index] == value:
                        continue
                    mutated = bytearray(original)
                    mutated[index] = value
                    scratch.write_bytes(bytes(mutated))
                    try:
                        capture.inspect_capture(scratch, limit=10)
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"byte {index}=0x{value:02x} raised "
                                  f"{type(exc).__name__}: {exc}")

    def test_missing_file_reports_error(self) -> None:
        report = capture.inspect_capture("/nonexistent/capture.pcap")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)

    def test_netcap_routes_raw_captures(self) -> None:
        """`re netcap` must accept a real capture, not only HAR/SAZ."""
        from xtforge.core.re import runtimes
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pcap(Path(tmp), 0xA1B2C3D4, "<", 0,
                              [eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 80, 443,
                                            HTTP_GET)])
            report = runtimes.inspect_netcap(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["engine"], "pcap")
        self.assertEqual(report["packet_count"], 1)

    def test_netcap_redacts_query_values_but_keeps_the_url(self) -> None:
        """A token in a query string must not leak, but the endpoint must survive.

        Redacting the whole URL to "http...html" would hide which endpoint was called,
        which is the one thing worth keeping.
        """
        from xtforge.core.re import runtimes
        self.assertEqual(
            runtimes._redact_query("http://h/p?token=SECRET&a=1"),
            "http://h/p?token=<6 chars>&a=<1 chars>")
        self.assertEqual(runtimes._redact_query("http://h/p"), "http://h/p")


if __name__ == "__main__":
    unittest.main()
