"""Packet capture readers: classic pcap and pcapng.

WHY: `re netcap` already reads HAR and SAZ, which are browser-export formats. The
format a capture actually arrives in from a device, an IDS or a switch SPAN port is
pcap or pcapng, and neither was readable. REA exposes packet-capture inspection, so
this closes the same gap.

The reader answers the question netcap already answers for HAR — which endpoints did
this traffic touch — plus the flow summary an analyst wants first: who talked to whom,
on which ports, how much data moved, and whether anything is still unresolved.

Four things in capture files regularly produce wrong output and are handled here:

  * Endianness is per-file and declared by the magic number, not assumed. A pcap
    written on a big-endian host read as little-endian yields absurd timestamps and
    packet lengths, and nothing about it looks invalid.
  * The two timestamp resolutions (microsecond and nanosecond) differ only in the
    magic's low bits; treating nanos as micros puts every packet in 1970.
  * pcapng is a *block* format with a byte-order magic block, so the same rule applies
    one level down, and block lengths are repeated at both ends of each block — using
    the trailing copy is what detects a truncated capture.
  * Link-layer type decides where the IP header starts. Reading an Ethernet frame as
    raw IP (or vice versa) parses the destination MAC as an IP version and produces
    nonsense addresses that still look like addresses.

Returns {"ok": bool, ...} and never raises.
"""
from __future__ import annotations

import datetime as _dt
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_PACKETS = 200000

# pcap magic numbers. The low bit of the "nano" variants is the resolution marker.
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", "micro"),
    b"\xa1\xb2\xc3\xd4": (">", "micro"),
    b"\x4d\x3c\xb2\xa1": ("<", "nano"),
    b"\xa1\xb2\x3c\x4d": (">", "nano"),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

# Link-layer types (tcpdump LINKTYPE_*).
_LINKTYPES = {
    0: "NULL", 1: "Ethernet", 101: "Raw IP", 105: "IEEE 802.11", 113: "Linux SLL",
    127: "IEEE 802.11 radiotap", 228: "Raw IPv4", 229: "Raw IPv6", 276: "Linux SLL2",
}

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_ARP = 0x0806

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PROTO_ICMPV6 = 58
_PROTO_NAMES = {PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMP: "ICMP",
                PROTO_ICMPV6: "ICMPv6", 47: "GRE", 50: "ESP", 51: "AH"}


def _read(path: str | Path) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"file too large: {size} bytes (max {MAX_BYTES})")
    return canon.read_bytes()


def _ipv4(blob: bytes) -> dict[str, Any] | None:
    if len(blob) < 20:
        return None
    version = blob[0] >> 4
    if version != 4:
        return None
    header_len = (blob[0] & 0x0F) * 4
    if header_len < 20 or header_len > len(blob):
        return None
    total_len = struct.unpack_from(">H", blob, 2)[0]
    protocol = blob[9]
    source = ".".join(str(b) for b in blob[12:16])
    destination = ".".join(str(b) for b in blob[16:20])
    # Fragments after the first carry no transport header.
    fragment_offset = struct.unpack_from(">H", blob, 6)[0] & 0x1FFF
    payload = blob[header_len:total_len] if total_len <= len(blob) else blob[header_len:]
    return {"version": 4, "src": source, "dst": destination,
            "protocol": protocol, "payload": payload,
            "first_fragment": fragment_offset == 0,
            "ttl": blob[8]}


def _ipv6(blob: bytes) -> dict[str, Any] | None:
    if len(blob) < 40:
        return None
    if blob[0] >> 4 != 6:
        return None

    def address(chunk: bytes) -> str:
        # Compress the longest run of zero groups, as the canonical text form does.
        groups = [f"{chunk[i] << 8 | chunk[i + 1]:x}" for i in range(0, 16, 2)]
        best_start = best_len = 0
        run_start = run_len = 0
        for index, group in enumerate(groups):
            if group == "0":
                if run_len == 0:
                    run_start = index
                run_len += 1
                if run_len > best_len:
                    best_start, best_len = run_start, run_len
            else:
                run_len = 0
        if best_len > 1:
            head = ":".join(groups[:best_start])
            tail = ":".join(groups[best_start + best_len:])
            return f"{head}::{tail}" if (head or tail) else "::"
        return ":".join(groups)

    payload_length = struct.unpack_from(">H", blob, 4)[0]
    next_header = blob[6]
    return {"version": 6, "src": address(blob[8:24]), "dst": address(blob[24:40]),
            "protocol": next_header, "payload": blob[40:40 + payload_length],
            "first_fragment": True, "ttl": blob[7]}


def _transport(ip: dict[str, Any]) -> dict[str, Any]:
    """Decode the port numbers and, for TCP, the flag set."""
    payload = ip["payload"]
    protocol = ip["protocol"]
    out: dict[str, Any] = {}
    if protocol in (PROTO_TCP, PROTO_UDP) and len(payload) >= 4 and ip["first_fragment"]:
        out["src_port"], out["dst_port"] = struct.unpack_from(">HH", payload, 0)
        if protocol == PROTO_TCP and len(payload) >= 20:
            offset = (payload[12] >> 4) * 4
            if 20 <= offset <= len(payload):
                out["app_payload"] = payload[offset:]
            flags = payload[13]
            out["tcp_flags"] = "".join(
                name for bit, name in ((0x02, "S"), (0x10, "A"), (0x01, "F"),
                                       (0x04, "R"), (0x08, "P"))
                if flags & bit)
        elif protocol == PROTO_UDP and len(payload) >= 8:
            out["app_payload"] = payload[8:]
    return out


def _http_request(payload: bytes) -> dict[str, Any] | None:
    """Recognise a plaintext HTTP request line in a TCP stream payload."""
    if not payload or len(payload) < 16:
        return None
    head = payload[:400]
    for method in (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH"):
        if head.startswith(method + b" "):
            end = head.find(b"\r\n")
            line = head[:end if end > 0 else len(head)].decode("latin-1", "replace")
            parts = line.split(" ")
            if len(parts) < 2:
                return None
            host = ""
            lower = head.lower()
            marker = lower.find(b"\r\nhost:")
            if marker >= 0:
                stop = head.find(b"\r\n", marker + 2)
                host = head[marker + 7:stop].decode("latin-1", "replace").strip()
            return {"method": parts[0], "path": parts[1], "host": host,
                    "url": f"http://{host}{parts[1]}" if host else parts[1]}
    return None


def _frames_from_pcap(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    order, resolution = _PCAP_MAGICS[data[:4]]
    (major, minor, _zone, _sigfigs, snaplen, linktype) = struct.unpack_from(
        f"{order}HHiIII", data, 4)
    info = {"format": "pcap", "endianness": "big" if order == ">" else "little",
            "resolution": resolution, "version": f"{major}.{minor}",
            "snaplen": snaplen, "linktype": linktype,
            "linktype_name": _LINKTYPES.get(linktype, f"unknown({linktype})"),
            "byte_order_magic": data[:4].hex()}
    frames: list[dict[str, Any]] = []
    cursor = 24
    while cursor + 16 <= len(data) and len(frames) < MAX_PACKETS:
        seconds, fraction, captured, original = struct.unpack_from(
            f"{order}IIII", data, cursor)
        cursor += 16
        if captured > len(data) - cursor:
            info["truncated"] = True
            break
        # Nanosecond captures store nanoseconds in the same field; dividing by 1000
        # is the difference between a correct timestamp and one in 1970.
        micros = fraction // 1000 if resolution == "nano" else fraction
        frames.append({"index": len(frames), "seconds": seconds,
                       "timestamp": _stamp(seconds, micros),
                       "captured_length": captured, "original_length": original,
                       "data": data[cursor:cursor + captured]})
        cursor += captured
    return frames, info


def _frames_from_pcapng(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    info: dict[str, Any] = {"format": "pcapng", "linktype": None,
                            "linktype_name": None, "interfaces": 0}
    cursor = 0
    order = "<"
    while cursor + 12 <= len(data) and len(frames) < MAX_PACKETS:
        block_type = data[cursor:cursor + 4]
        if block_type == _PCAPNG_SHB:
            # Byte-order magic at offset 8 settles endianness for the whole file.
            if cursor + 12 > len(data):
                break
            magic = data[cursor + 8:cursor + 12]
            order = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            info["endianness"] = "little" if order == "<" else "big"
        raw_length = data[cursor + 4:cursor + 8]
        if len(raw_length) < 4:
            break
        block_length = struct.unpack(f"{order}I", raw_length)[0]
        if block_length < 12 or cursor + block_length > len(data):
            info["truncated"] = True
            break
        # Block length is repeated at the end; a mismatch means truncation or
        # corruption that would otherwise slide the whole walk out of alignment.
        trailing = struct.unpack_from(f"{order}I", data, cursor + block_length - 4)[0]
        if trailing != block_length:
            info["trailing_length_mismatch"] = True
        kind = struct.unpack(f"{order}I", block_type)[0]
        if kind == 0x00000001 and block_length >= 20:  # Interface Description Block
            (linktype,) = struct.unpack_from(f"{order}H", data, cursor + 8)
            info["interfaces"] = int(info.get("interfaces") or 0) + 1
            if info["linktype"] is None:
                info["linktype"] = linktype
                info["linktype_name"] = _LINKTYPES.get(linktype, f"unknown({linktype})")
        elif kind == 0x00000006 and block_length >= 32:  # Enhanced Packet Block
            interface_id, high, low, captured, original = struct.unpack_from(
                f"{order}IIIII", data, cursor + 8)
            body_offset = cursor + 28
            if body_offset + captured <= cursor + block_length:
                # Timestamp is a 64-bit count of interface units; the default
                # resolution is microseconds, but it is declared per interface and
                # this reader reports the raw value alongside a default-resolution
                # rendering rather than asserting a resolution it did not read.
                total = (high << 32) | low
                frames.append({
                    "index": len(frames),
                    "timestamp": _stamp(total // 1_000_000, total % 1_000_000),
                    "interface": interface_id,
                    "captured_length": captured,
                    "original_length": original,
                    "data": data[body_offset:body_offset + captured],
                })
        elif kind == 0x00000003 and block_length >= 16:  # Simple Packet Block
            (original,) = struct.unpack_from(f"{order}I", data, cursor + 8)
            body_offset = cursor + 12
            captured = block_length - 16
            frames.append({"index": len(frames), "timestamp": None,
                           "captured_length": captured, "original_length": original,
                           "data": data[body_offset:body_offset + captured]})
        cursor += block_length
    return frames, info


def _stamp(seconds: int, micros: int) -> str | None:
    try:
        return _dt.datetime.fromtimestamp(seconds, _dt.UTC).strftime(
            "%Y-%m-%dT%H:%M:%S") + f".{micros:06d}Z"
    except (OverflowError, OSError, ValueError):
        return None


def _network_offset(frame: bytes, linktype: int) -> tuple[int, int | None] | None:
    """Where does the network header start, and what EtherType is declared?"""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        offset = 14
        # 802.1Q VLAN tag shifts the payload by 4 bytes.
        while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
            ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4
        return offset, ethertype
    if linktype in (0, 101, 228, 229):  # NULL / Raw IP
        return 0, None
    if linktype == 113:  # Linux SLL: 16-byte header
        if len(frame) < 16:
            return None
        return 16, struct.unpack_from(">H", frame, 14)[0]
    if linktype == 276:  # Linux SLL2: 20-byte header
        if len(frame) < 20:
            return None
        return 20, struct.unpack_from(">H", frame, 0)[0]
    if linktype == 127:  # radiotap: 4-byte header then a length field
        if len(frame) < 4:
            return None
        (radiotap_len,) = struct.unpack_from("<H", frame, 2)
        return radiotap_len, None
    return None


def inspect_capture(path: str | Path, *, limit: int = 200,
                    extract_http: bool = True) -> dict[str, Any]:
    """Read a pcap or pcapng capture: flows, endpoints, and HTTP requests.

    `limit` bounds the number of flows and HTTP requests returned, not the number of
    packets read — a capture with 100k packets still produces a complete flow table.
    """
    try:
        data = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(data) < 24:
        return {"ok": False, "path": str(path),
                "error": f"file too small for a capture header ({len(data)} bytes)"}

    if data[:4] == _PCAPNG_SHB:
        frames, info = _frames_from_pcapng(data)
    elif data[:4] in _PCAP_MAGICS:
        frames, info = _frames_from_pcap(data)
    else:
        return {"ok": False, "path": str(path),
                "error": "not a pcap or pcapng capture",
                "found_magic": data[:4].hex(),
                "expected": [m.hex() for m in _PCAP_MAGICS] + [_PCAPNG_SHB.hex()]}

    linktype = info.get("linktype")
    flows: dict[tuple, dict[str, Any]] = {}
    http: list[dict[str, Any]] = []
    protocols: dict[str, int] = {}
    parsed = 0
    unparsed = 0
    earliest = latest = None

    for frame in frames:
        payload = frame["data"]
        located = _network_offset(payload, linktype) if linktype is not None else None
        if located is None:
            unparsed += 1
            continue
        offset, ethertype = located
        if offset < 0 or offset > len(payload):
            # A corrupt link-layer header (a radiotap length, say) can name an offset
            # past the end of the frame. A negative slice in Python silently wraps to
            # the wrong bytes instead of raising, which is worse than a crash: it
            # reports a plausible packet from the wrong part of the frame.
            unparsed += 1
            continue
        network = payload[offset:]
        ip = None
        if ethertype in (None, _ETHERTYPE_IPV4):
            ip = _ipv4(network)
            if ip is None and ethertype is None:
                ip = _ipv6(network)
        elif ethertype == _ETHERTYPE_IPV6:
            ip = _ipv6(network)
        if ip is None:
            if ethertype == _ETHERTYPE_ARP:
                protocols["ARP"] = protocols.get("ARP", 0) + 1
            else:
                unparsed += 1
            continue
        parsed += 1
        name = _PROTO_NAMES.get(ip["protocol"], f"IP({ip['protocol']})")
        protocols[name] = protocols.get(name, 0) + 1
        transport = _transport(ip)
        key = (ip["src"], transport.get("src_port"), ip["dst"],
               transport.get("dst_port"), name)
        flow = flows.setdefault(key, {
            "src": ip["src"], "src_port": transport.get("src_port"),
            "dst": ip["dst"], "dst_port": transport.get("dst_port"),
            "protocol": name, "packets": 0, "bytes": 0,
        })
        flow["packets"] += 1
        flow["bytes"] += frame["original_length"]
        if frame.get("timestamp"):
            if earliest is None or frame["timestamp"] < earliest:
                earliest = frame["timestamp"]
            if latest is None or frame["timestamp"] > latest:
                latest = frame["timestamp"]
        if extract_http and len(http) < limit and ip["protocol"] == PROTO_TCP:
            request = _http_request(transport.get("app_payload") or b"")
            if request:
                request.update({"src": ip["src"], "dst": ip["dst"],
                                "timestamp": frame.get("timestamp")})
                http.append(request)

    ordered = sorted(flows.values(), key=lambda f: -f["bytes"])
    return {
        "ok": True,
        "path": str(path),
        **info,
        "packet_count": len(frames),
        "parsed_packets": parsed,
        "unparsed_packets": unparsed,
        "flow_count": len(flows),
        "flows": ordered[:limit],
        "protocols": dict(sorted(protocols.items(), key=lambda kv: -kv[1])),
        "http_requests": http[:limit],
        "http_request_count": len(http),
        "first_packet": earliest,
        "last_packet": latest,
        "truncated": bool(info.get("truncated")),
    }
